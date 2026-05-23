"""OSV-Scanner dependency scanner. Gated on `has_lockfile` (tier 1).

Tier 1 is authoritative because a lockfile pins exact resolved versions for
the entire transitive tree. OSV-Scanner has the same bundling blind spot as
Retire.js — it is not a rescue for the stripped-deps case.
"""

import json
from pathlib import Path

from vsc_scanner.scanners._tools import resolve
from vsc_scanner.scanners.base import ScanResult, Scanner
from vsc_scanner.structs import ExtensionBundle


class OsvScanner(Scanner):
    def __init__(self) -> None:
        self.name = "osv"

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        lockfile = _find_lockfile(bundle.extension_dir)
        if lockfile is None:
            return []
        return [("extension", lockfile)]

    def argv(self, target: Path) -> list[str]:
        binary = resolve("osv-scanner") or "osv-scanner"
        return [binary, "--format", "json", "--lockfile", str(target)]

    def run(self, bundle: ExtensionBundle) -> list[ScanResult]:
        dv = bundle.dep_visibility
        if dv is None or not dv.has_lockfile:
            return [
                ScanResult(
                    name=self.name,
                    target="extension",
                    target_path=str(bundle.extension_dir),
                    exit_code=0,
                    findings={
                        "skipped": "no lockfile",
                        "tier": dv.tier if dv else None,
                    },
                )
            ]
        return super().run(bundle)

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        if not stdout.strip():
            return {"findings": [], "error": "empty stdout", "stderr_tail": stderr[-500:]}
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return {"findings": [], "error": f"json decode: {exc}", "stderr_tail": stderr[-500:]}

        findings: list[dict] = []
        for source in data.get("results") or []:
            src_path = (source.get("source") or {}).get("path")
            for pkg in source.get("packages") or []:
                package = pkg.get("package") or {}
                for v in pkg.get("vulnerabilities") or []:
                    findings.append(
                        {
                            "package": package.get("name"),
                            "version": package.get("version"),
                            "ecosystem": package.get("ecosystem"),
                            "osv_id": v.get("id"),
                            "summary": v.get("summary"),
                            "aliases": v.get("aliases"),
                            "severity": v.get("severity") or v.get("database_specific", {}).get("severity"),
                            "source": src_path,
                        }
                    )
        return {"findings": findings}


def _find_lockfile(extension_dir: Path) -> Path | None:
    for name in ("package-lock.json", "yarn.lock"):
        p = extension_dir / name
        if p.is_file():
            return p
    return None
