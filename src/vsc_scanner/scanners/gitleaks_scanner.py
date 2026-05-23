"""GitLeaks secret scanner.

GitLeaks writes its JSON report to a file, not stdout, so this scanner
overrides `run()` to manage a temp report path. Secret values are never
echoed into the report — only a redacted preview and offset are kept.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from vsc_scanner.scanners._tools import resolve
from vsc_scanner.scanners.base import ScanResult, Scanner, scanner_env
from vsc_scanner.structs import ExtensionBundle

log = logging.getLogger("vsc_scanner")

_STDERR_TAIL_BYTES = 2048


class GitleaksScanner(Scanner):
    def __init__(self) -> None:
        self.name = "gitleaks"

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        target = bundle.preprocessed_dir or bundle.extension_dir
        return [("extension", target)]

    def argv(self, target: Path) -> list[str]:
        # Unused — gitleaks needs --report-path; see run().
        return []

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        return {}

    def run(self, bundle: ExtensionBundle) -> list[ScanResult]:
        binary = resolve("gitleaks") or "gitleaks"
        results: list[ScanResult] = []
        for label, target in self.targets(bundle):
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                report_path = Path(tf.name)
            try:
                argv = [
                    binary, "detect", "--no-git",
                    "--source", str(target),
                    "--report-format", "json",
                    "--report-path", str(report_path),
                ]
                proc = subprocess.run(
                    argv, capture_output=True, text=True, check=False, env=scanner_env()
                )
                raw = self._load_report(report_path)
                findings = [_redact_finding(item) for item in raw]
                results.append(
                    ScanResult(
                        name=self.name,
                        target=label,
                        target_path=str(target),
                        # gitleaks exits 1 when leaks are found; treat that as
                        # "ran successfully with findings", not a tool error.
                        exit_code=proc.returncode if proc.returncode not in (0, 1) else 0,
                        findings={"findings": findings},
                        stderr_tail=proc.stderr[-_STDERR_TAIL_BYTES:],
                    )
                )
            finally:
                if report_path.exists():
                    report_path.unlink()
        return results

    @staticmethod
    def _load_report(path: Path) -> list[dict]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return []
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            log.warning("gitleaks: cannot parse report: %s", exc)
            return []
        return data if isinstance(data, list) else []


def _redact_finding(item: dict) -> dict:
    secret = item.get("Secret") or ""
    if len(secret) > 8:
        redacted = f"{secret[:4]}…{secret[-4:]}"
    else:
        redacted = "[REDACTED]"
    return {
        "rule_id": item.get("RuleID"),
        "file": item.get("File"),
        "start_line": item.get("StartLine"),
        "end_line": item.get("EndLine"),
        "secret_redacted": redacted,
        "secret_type": item.get("Description"),
        "entropy": item.get("Entropy"),
    }
