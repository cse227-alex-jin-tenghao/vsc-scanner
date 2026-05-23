"""Parallel scanner runner — Stage 3 + Stage 4 report assembly."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor

from vsc_scanner.scanners.base import ScanResult, Scanner
from vsc_scanner.structs import ExtensionBundle

log = logging.getLogger("vsc_scanner")

_MAX_WORKERS = 8
_SCHEMA_VERSION = 1


def run_scanners(bundle: ExtensionBundle, scanners: list[Scanner]) -> dict:
    """Fan out scanners in parallel; return the Stage-4 aggregated report."""
    workers = max(1, min(len(scanners), _MAX_WORKERS))
    flat: list[ScanResult] = []
    errors: list[dict] = []

    timings: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_name = {}
        for s in scanners:
            future_to_name[pool.submit(_run_timed, s, bundle, timings)] = s.name
        for future, name in future_to_name.items():
            try:
                flat.extend(future.result())
            except Exception as exc:
                log.warning("scanner %s raised: %s", name, exc)
                errors.append({"scanner": name, "error": str(exc)})
    for name, secs in sorted(timings.items(), key=lambda kv: -kv[1]):
        log.info("scanner %s took %.2fs", name, secs)

    return {
        "schema_version": _SCHEMA_VERSION,
        "extension": _extension_block(bundle),
        "preprocessing": _preprocessing_block(bundle),
        "dep_visibility": _dep_visibility_block(bundle),
        "scanners": _scanners_block(flat),
        "errors": errors,
    }


def _run_timed(scanner: Scanner, bundle: ExtensionBundle, sink: dict) -> list[ScanResult]:
    t0 = time.perf_counter()
    try:
        return scanner.run(bundle)
    finally:
        sink[scanner.name] = time.perf_counter() - t0


def _extension_block(bundle: ExtensionBundle) -> dict:
    return {
        "publisher": bundle.publisher,
        "name": bundle.name,
        "version": bundle.version,
        "last_updated": bundle.last_updated,
    }


def _preprocessing_block(bundle: ExtensionBundle) -> dict | None:
    pre = bundle.preprocess
    if pre is None:
        return None
    return {
        "scanned_as": pre.scanned_as,
        "minified": pre.minified,
        "had_source_map": pre.had_source_map,
        "notes": list(pre.notes),
    }


def _dep_visibility_block(bundle: ExtensionBundle) -> dict | None:
    dv = bundle.dep_visibility
    if dv is None:
        return None
    return {
        "has_lockfile": dv.has_lockfile,
        "has_node_modules": dv.has_node_modules,
        "deps_declared_nonempty": dv.deps_declared_nonempty,
        "bundle_artifact_detected": dv.bundle_artifact_detected,
        "tier": dv.tier,
    }


def _scanners_block(results: list[ScanResult]) -> dict:
    """Collapse per-target ScanResults into one entry per scanner name."""
    by_name: dict[str, list[ScanResult]] = {}
    for r in results:
        by_name.setdefault(r.name, []).append(r)

    block: dict[str, dict] = {}
    for name, rs in by_name.items():
        # A gated scanner returns one ScanResult with `findings={"skipped": ...}`.
        if len(rs) == 1 and "skipped" in rs[0].findings:
            block[name] = {
                "ran": False,
                "skipped": rs[0].findings.get("skipped"),
                "tier": rs[0].findings.get("tier"),
            }
            continue

        findings: list[dict] = []
        extras: dict = {}
        worst_exit = 0
        for r in rs:
            findings.extend(r.findings.get("findings") or [])
            for k, v in r.findings.items():
                if k != "findings":
                    # Merge non-findings metadata (e.g. scanned_files, error).
                    extras.setdefault(k, v)
            if r.exit_code != 0:
                worst_exit = r.exit_code
        block[name] = {
            "ran": True,
            "exit_code": worst_exit,
            "findings": findings,
            **extras,
        }
    return block
