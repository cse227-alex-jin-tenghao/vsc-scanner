"""Retire.js dependency scanner. Gated on `has_node_modules` (tier 2)."""

import json
from pathlib import Path

from vsc_scanner.scanners._tools import resolve
from vsc_scanner.scanners.base import ScanResult, Scanner
from vsc_scanner.structs import ExtensionBundle


class RetireJsScanner(Scanner):
    def __init__(self) -> None:
        self.name = "retirejs"

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        # Retire scans installed node_modules — use the raw extension dir so
        # any text normalization from preprocessing doesn't perturb hash matches.
        return [("extension", bundle.extension_dir)]

    def argv(self, target: Path) -> list[str]:
        binary = resolve("retire") or "retire"
        return [
            binary,
            "--path", str(target),
            "--outputformat", "json",
            # Default exit code on findings is 13; collapse to 0 so the runner
            # sees "findings present" as a normal result, not a tool error.
            "--exitwith", "0",
        ]

    def run(self, bundle: ExtensionBundle) -> list[ScanResult]:
        dv = bundle.dep_visibility
        if dv is None or not dv.has_node_modules:
            return [
                ScanResult(
                    name=self.name,
                    target="extension",
                    target_path=str(bundle.extension_dir),
                    exit_code=0,
                    findings={
                        "skipped": "no node_modules",
                        "tier": dv.tier if dv else None,
                    },
                )
            ]
        return super().run(bundle)

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        # retire writes findings to stdout; messages/errors to stderr.
        if not stdout.strip():
            return {"findings": [], "error": "empty stdout", "stderr_tail": stderr[-500:]}
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return {"findings": [], "error": f"json decode: {exc}", "stderr_tail": stderr[-500:]}

        findings: list[dict] = []
        for entry in data.get("data", []):
            file_path = entry.get("file")
            for r in entry.get("results", []) or []:
                vulns = []
                for v in r.get("vulnerabilities", []) or []:
                    vulns.append(
                        {
                            "severity": v.get("severity"),
                            "identifiers": v.get("identifiers"),
                            "info": v.get("info"),
                            "below": v.get("below"),
                            "summary": (v.get("identifiers") or {}).get("summary"),
                        }
                    )
                if vulns:
                    findings.append(
                        {
                            "component": r.get("component"),
                            "version": r.get("version"),
                            "file": file_path,
                            "detection": r.get("detection"),
                            "vulnerabilities": vulns,
                        }
                    )
        return {"findings": findings}
