"""Node-side scan loop. Claims groups of 100 extensions from the manager
table, scans them concurrently, and upserts trimmed results into `main`.

Loops until the table is drained or the process is interrupted. Writes a
human-grep-able status line per extension and per group to log.txt so we
can measure throughput / debug stragglers without parsing JSON.

Usage:
    python scripts/run_node.py [--node-id <name>] [--workers 4]
"""

import argparse
import dataclasses
import json
import logging
import os
import socket
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT))

import psycopg  # noqa: E402

from scan import fetch_extension  # noqa: E402 — reuse the existing pipeline
from vsc_scanner.cleanup import cleanup_bundle  # noqa: E402
from vsc_scanner.dep_visibility import classify as classify_dep_visibility  # noqa: E402
from vsc_scanner.preprocess import preprocess  # noqa: E402
from vsc_scanner.runner import run_scanners  # noqa: E402
from vsc_scanner.scanners.gitleaks_scanner import GitleaksScanner  # noqa: E402
from vsc_scanner.scanners.osv_scanner import OsvScanner  # noqa: E402
from vsc_scanner.scanners.retirejs_scanner import RetireJsScanner  # noqa: E402
from vsc_scanner.scanners.semgrep_scanner import SemgrepScanner  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]
# All three default to repo-relative paths for laptop use, but the container
# entrypoint will set VSC_PW_PATH / VSC_EXTENSIONS_JSON / VSC_LOG_PATH to
# locations under the shared $HOME so secrets and the 200 MB extension list
# don't have to live in the image.
_LOG_PATH = Path(os.environ.get("VSC_LOG_PATH", str(_REPO / "log.txt")))
_PW_PATH = Path(os.environ.get("VSC_PW_PATH", str(_REPO / "pw.txt")))
_JSON_PATH = Path(os.environ.get(
    "VSC_EXTENSIONS_JSON",
    "/home/alex/cse227/project/stuff/marketplace_extensions.json",
))

_CONN_STR = (
    "postgresql://postgres.lnoxdusiuktldwelqakn"
    "@aws-1-us-west-1.pooler.supabase.com:5432/postgres"
)

_GROUP_SIZE = 100
_FINDING_CAP = 500  # per scanner, with truncated flag if exceeded

_CLAIM_SQL = """
UPDATE manager
SET status = 'claimed',
    claimed_at = now(),
    claimed_by = %s,
    attempts = attempts + 1
WHERE group_idx = (
    SELECT group_idx FROM manager
    WHERE status = 'unclaimed'
       OR (status = 'claimed' AND claimed_at < now() - interval '1 hour')
    ORDER BY group_idx
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING
    group_idx,
    (SELECT COALESCE(MAX(idx), group_idx * 100 - 1)
       FROM main
      WHERE idx >= group_idx * 100
        AND idx <  group_idx * 100 + 100
        AND completed_at IS NOT NULL) AS last_completed_idx;
"""

_UPSERT_SQL = """
UPDATE main
SET preprocessing   = %s,
    dep_visibility  = %s,
    semgrep_output  = %s,
    retire_output   = %s,
    osv_output      = %s,
    gitleaks_output = %s,
    errors          = %s,
    scanner_version = %s,
    completed_at    = now()
WHERE idx = %s;
"""

_COMPLETE_SQL = """
UPDATE manager
SET status = 'completed', completed_at = now()
WHERE group_idx = %s
  AND status <> 'completed'
  AND (SELECT COUNT(*) FROM main
        WHERE idx >= %s * 100 AND idx < %s * 100 + 100
          AND completed_at IS NOT NULL)
    = (SELECT COUNT(*) FROM main
        WHERE idx >= %s * 100 AND idx < %s * 100 + 100);
"""


def _setup_logging() -> logging.Logger:
    log = logging.getLogger("vsc_node")
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(_LOG_PATH)
    fh.setFormatter(fmt)
    log.addHandler(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    return log


def _scanner_version() -> str:
    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=_REPO, text=True
        ).strip()
        return rev
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


# ---------- trimming ----------

def _cap(items: list, cap: int = _FINDING_CAP) -> tuple[list, bool]:
    if len(items) > cap:
        return items[:cap], True
    return items, False


def _trim_semgrep(block: dict | None) -> dict | None:
    if block is None or not block.get("ran"):
        return block
    findings = [
        {
            "check_id": f.get("check_id"),
            "message": f.get("message"),
            "severity": f.get("severity"),
            "intent": f.get("intent"),
        }
        for f in block.get("findings", [])
    ]
    findings, truncated = _cap(findings)
    return {
        "ran": True,
        "exit_code": block.get("exit_code", 0),
        "findings": findings,
        "truncated": truncated,
        "scanned_files": block.get("scanned_files"),
        "skipped_files": block.get("skipped_files"),
    }


def _trim_retire(block: dict | None) -> dict | None:
    if block is None or not block.get("ran"):
        return block
    out = []
    for f in block.get("findings", []):
        vulns = [
            {"severity": v.get("severity"), "identifiers": v.get("identifiers")}
            for v in f.get("vulnerabilities", [])
        ]
        out.append({
            "component": f.get("component"),
            "version": f.get("version"),
            "vulnerabilities": vulns,
        })
    out, truncated = _cap(out)
    return {
        "ran": True,
        "exit_code": block.get("exit_code", 0),
        "findings": out,
        "truncated": truncated,
    }


def _trim_osv(block: dict | None) -> dict | None:
    if block is None or not block.get("ran"):
        return block
    out = []
    for f in block.get("findings", []):
        vulns = [
            {"id": v.get("id"), "severity": v.get("severity")}
            for v in f.get("vulnerabilities", [])
        ]
        out.append({"package": f.get("package"), "vulnerabilities": vulns})
    out, truncated = _cap(out)
    return {
        "ran": True,
        "exit_code": block.get("exit_code", 0),
        "findings": out,
        "truncated": truncated,
    }


def _trim_gitleaks(block: dict | None) -> dict | None:
    if block is None or not block.get("ran"):
        return block
    findings = [{"rule_id": f.get("rule_id")} for f in block.get("findings", [])]
    findings, truncated = _cap(findings)
    return {
        "ran": True,
        "exit_code": block.get("exit_code", 0),
        "findings": findings,
        "truncated": truncated,
    }


def _finding_counts(report: dict) -> dict[str, int | str]:
    """Compact per-scanner counts for the log line."""
    counts: dict[str, int | str] = {}
    for name in ("semgrep", "retirejs", "osv", "gitleaks"):
        block = report["scanners"].get(name) or {}
        if not block.get("ran"):
            counts[name] = "skip"
        else:
            counts[name] = len(block.get("findings", []))
    return counts


# ---------- scanning ----------

def _build_scanners(semgrep_jobs: int) -> list:
    return [
        SemgrepScanner(deep=False, jobs=semgrep_jobs),
        RetireJsScanner(),
        OsvScanner(),
        GitleaksScanner(),
    ]


def scan_one(idx: int, extension_id: str, semgrep_jobs: int) -> dict:
    """Run the full pipeline against one extension and return a trimmed report.

    Always returns a report dict — failures are encoded as `errors`. The
    bundle's temp dir is always cleaned up.
    """
    url = f"https://marketplace.visualstudio.com/items?itemName={extension_id}"
    bundle = None
    try:
        bundle = fetch_extension(url)
        pre = preprocess(bundle.extension_dir, bundle.root_dir / "preprocessed")
        dep_vis = classify_dep_visibility(bundle.extension_dir, pre.bundle_artifact_detected)
        bundle = dataclasses.replace(
            bundle,
            preprocessed_dir=pre.preprocessed_dir,
            preprocess=pre,
            dep_visibility=dep_vis,
        )
        report = run_scanners(bundle, _build_scanners(semgrep_jobs))
        report["scanners"]["semgrep"] = _trim_semgrep(report["scanners"].get("semgrep"))
        report["scanners"]["retirejs"] = _trim_retire(report["scanners"].get("retirejs"))
        report["scanners"]["osv"] = _trim_osv(report["scanners"].get("osv"))
        report["scanners"]["gitleaks"] = _trim_gitleaks(report["scanners"].get("gitleaks"))
        return report
    except Exception as exc:
        return {
            "schema_version": 1,
            "extension": {"id": extension_id},
            "preprocessing": None,
            "dep_visibility": None,
            "scanners": {},
            "errors": [{"stage": "scan_one", "error": str(exc),
                        "trace": traceback.format_exc(limit=3)}],
        }
    finally:
        if bundle is not None:
            try:
                cleanup_bundle(bundle)
            except Exception:
                pass


# ---------- DB helpers ----------

def claim_group(conn: psycopg.Connection, node_id: str) -> tuple[int, int] | None:
    with conn.cursor() as cur:
        cur.execute(_CLAIM_SQL, (node_id,))
        row = cur.fetchone()
    conn.commit()
    if row is None:
        return None
    return row[0], row[1]


def upsert_result(conn_lock: Lock, conn: psycopg.Connection, idx: int,
                  report: dict, scanner_version: str) -> None:
    pre = report.get("preprocessing")
    dv = report.get("dep_visibility")
    sc = report.get("scanners", {})
    with conn_lock:
        with conn.cursor() as cur:
            cur.execute(
                _UPSERT_SQL,
                (
                    json.dumps(pre) if pre else None,
                    json.dumps(dv) if dv else None,
                    json.dumps(sc.get("semgrep")) if sc.get("semgrep") else None,
                    json.dumps(sc.get("retirejs")) if sc.get("retirejs") else None,
                    json.dumps(sc.get("osv")) if sc.get("osv") else None,
                    json.dumps(sc.get("gitleaks")) if sc.get("gitleaks") else None,
                    json.dumps(report.get("errors") or []),
                    scanner_version,
                    idx,
                ),
            )
        conn.commit()


def mark_group_if_complete(conn_lock: Lock, conn: psycopg.Connection,
                            group_idx: int) -> bool:
    with conn_lock:
        with conn.cursor() as cur:
            cur.execute(_COMPLETE_SQL, (group_idx, group_idx, group_idx, group_idx, group_idx))
            rowcount = cur.rowcount
        conn.commit()
    return rowcount > 0


# ---------- main loop ----------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-id", default=f"{socket.gethostname()}-{os.getpid()}")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-groups", type=int, default=0,
                        help="Stop after this many groups (0 = unlimited).")
    args = parser.parse_args()

    log = _setup_logging()
    log.info("NODE_START id=%s workers=%d", args.node_id, args.workers)

    extensions = json.loads(_JSON_PATH.read_text())
    total = len(extensions)
    log.info("LOADED extensions=%d", total)

    # Cap semgrep --jobs so workers × jobs ≤ cores. Min 1.
    cores = os.cpu_count() or 8
    semgrep_jobs = max(1, cores // args.workers)
    log.info("CONFIG cores=%d workers=%d semgrep_jobs=%d", cores, args.workers, semgrep_jobs)

    scanner_version = _scanner_version()
    password = _PW_PATH.read_text().strip()

    conn = psycopg.connect(_CONN_STR, password=password, autocommit=False)
    conn_lock = Lock()

    groups_done = 0
    try:
        while True:
            if args.max_groups and groups_done >= args.max_groups:
                log.info("MAX_GROUPS_REACHED groups_done=%d — exiting", groups_done)
                break
            t_claim = time.perf_counter()
            claim = claim_group(conn, args.node_id)
            if claim is None:
                log.info("NO_GROUPS_AVAILABLE — exiting")
                break
            group_idx, last_completed = claim
            start_idx = max(group_idx * _GROUP_SIZE, last_completed + 1)
            end_idx = min(group_idx * _GROUP_SIZE + _GROUP_SIZE, total)
            todo_idxs = list(range(start_idx, end_idx))
            log.info(
                "GROUP_CLAIM group=%d range=[%d,%d) todo=%d claim_ms=%.0f",
                group_idx, start_idx, end_idx, len(todo_idxs),
                (time.perf_counter() - t_claim) * 1000,
            )

            t_group = time.perf_counter()
            success = 0
            failed = 0

            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                fut_to_meta = {}
                for idx in todo_idxs:
                    ext_id = f"{extensions[idx]['publisher']['publisherName']}.{extensions[idx]['extensionName']}"
                    log.info("EXT_START idx=%d ext=%s", idx, ext_id)
                    fut = pool.submit(_scan_and_log, idx, ext_id, semgrep_jobs,
                                      conn_lock, conn, scanner_version, log)
                    fut_to_meta[fut] = (idx, ext_id)
                for fut in as_completed(fut_to_meta):
                    ok = fut.result()
                    if ok:
                        success += 1
                    else:
                        failed += 1

            elapsed = time.perf_counter() - t_group
            avg = elapsed / max(1, len(todo_idxs))
            became_complete = mark_group_if_complete(conn_lock, conn, group_idx)
            log.info(
                "GROUP_DONE group=%d elapsed=%.1fs success=%d failed=%d avg=%.2fs/ext marked_complete=%s",
                group_idx, elapsed, success, failed, avg, became_complete,
            )
            groups_done += 1
    finally:
        conn.close()

    log.info("NODE_EXIT id=%s", args.node_id)
    return 0


def _scan_and_log(idx: int, ext_id: str, semgrep_jobs: int,
                  conn_lock: Lock, conn: psycopg.Connection,
                  scanner_version: str, log: logging.Logger) -> bool:
    t0 = time.perf_counter()
    report = scan_one(idx, ext_id, semgrep_jobs)
    elapsed = time.perf_counter() - t0
    try:
        upsert_result(conn_lock, conn, idx, report, scanner_version)
    except Exception as exc:
        log.error("EXT_UPSERT_FAIL idx=%d ext=%s err=%s", idx, ext_id, exc)
        return False
    errors = report.get("errors") or []
    if errors and not report.get("scanners"):
        log.info(
            "EXT_FAIL idx=%d ext=%s elapsed=%.2fs err=%s",
            idx, ext_id, elapsed, (errors[0].get("error") or "?")[:200],
        )
        return False
    counts = _finding_counts(report)
    log.info(
        "EXT_DONE idx=%d ext=%s elapsed=%.2fs scanners=%s",
        idx, ext_id, elapsed, counts,
    )
    return True


if __name__ == "__main__":
    raise SystemExit(main())
