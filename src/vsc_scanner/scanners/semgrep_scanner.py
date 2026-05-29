"""Semgrep source-pattern scanner."""

import json
import logging
import os
from pathlib import Path

from vsc_scanner.scanners._tools import resolve
from vsc_scanner.scanners.base import ScanResult, Scanner
from vsc_scanner.structs import ExtensionBundle

log = logging.getLogger("vsc_scanner")

# Custom rules live at <project-root>/rules. Resolved relative to this file
# so the path works whether the CLI is invoked from the repo root or elsewhere.
_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"


class SemgrepScanner(Scanner):
    def __init__(self, deep: bool = False, jobs: int | None = None) -> None:
        self.name = "semgrep"
        self.deep = deep
        # `jobs` overrides --jobs in fast mode. Batch runners that fan out N
        # extensions in parallel set this to (cores / N) to avoid oversubscription.
        self.jobs = jobs

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        target = bundle.preprocessed_dir or bundle.extension_dir
        return [("extension", target)]

    def argv(self, target: Path) -> list[str]:
        binary = resolve("semgrep") or "semgrep"
        # Default mode trades coverage for runtime: cap file size, tight
        # per-rule timeout, drop after a few timeouts, parallelize, two rule
        # packs. --deep restores the no-caps "scan everything" behavior.
        if self.deep:
            argv = [
                binary,
                "--config", "p/javascript",
                "--config", "p/nodejs",
                "--config", "p/security-audit",
                "--max-target-bytes", "0",
                "--timeout", "30",
                "--timeout-threshold", "0",
            ]
        else:
            argv = [
                binary,
                "--config", "p/javascript",
                "--config", "p/nodejs",
                "--max-target-bytes", "2000000",
                "--timeout", "5",
                "--timeout-threshold", "3",
                "--jobs", str(self.jobs if self.jobs else (os.cpu_count() or 4)),
            ]
        if _RULES_DIR.is_dir():
            argv += ["--config", str(_RULES_DIR)]
        argv += ["--json", "--quiet", str(target)]
        return argv

    def run(self, bundle: ExtensionBundle) -> list[ScanResult]:
        # The default .semgrepignore excludes *.min.js and node_modules/, which
        # is exactly what we need to scan. Overwrite with an empty file.
        for _, target in self.targets(bundle):
            try:
                (target / ".semgrepignore").write_text("", encoding="utf-8")
            except OSError as exc:
                log.warning("semgrep: could not write .semgrepignore in %s: %s", target, exc)
        return super().run(bundle)

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        if not stdout.strip():
            return {"findings": [], "error": "empty stdout", "stderr_tail": stderr[-500:]}
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return {"findings": [], "error": f"json decode: {exc}", "stderr_tail": stderr[-500:]}

        findings = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            metadata = extra.get("metadata") or {}
            findings.append(
                {
                    "check_id": r.get("check_id"),
                    "path": r.get("path"),
                    "start_line": (r.get("start") or {}).get("line"),
                    "end_line": (r.get("end") or {}).get("line"),
                    "message": extra.get("message"),
                    "severity": extra.get("severity"),
                    "intent": metadata.get("intent"),
                    "requires_clean_source": bool(metadata.get("requires_clean_source", False)),
                }
            )
        paths = data.get("paths") or {}
        scanned = paths.get("scanned") or []
        skipped = paths.get("skipped") or []
        result = {"findings": findings, "scanned_files": len(scanned)}
        if skipped:
            # Surface coverage gaps (size/timeout drops) so a clean report
            # isn't mistaken for "the whole extension was inspected".
            result["skipped_files"] = len(skipped)
        return result
