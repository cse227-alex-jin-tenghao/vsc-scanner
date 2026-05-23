"""njsscan — Node-specific Semgrep-based scanner.

Output is normalized to match the Semgrep finding shape so cross-scanner
dedupe in the aggregator can key on `(path, start_line, rule_class)`.
"""

import json
from pathlib import Path

from vsc_scanner.scanners._tools import resolve
from vsc_scanner.scanners.base import Scanner
from vsc_scanner.structs import ExtensionBundle


class NjsscanScanner(Scanner):
    def __init__(self) -> None:
        self.name = "njsscan"

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        target = bundle.preprocessed_dir or bundle.extension_dir
        return [("extension", target)]

    def argv(self, target: Path) -> list[str]:
        binary = resolve("njsscan") or "njsscan"
        return [binary, "--json", str(target)]

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        if not stdout.strip():
            return {"findings": [], "error": "empty stdout", "stderr_tail": stderr[-500:]}
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return {"findings": [], "error": f"json decode: {exc}", "stderr_tail": stderr[-500:]}

        findings = []
        # njsscan groups under `nodejs` and `templates`; each value is keyed by
        # rule id and contains a metadata block + a `files` list.
        for section_name in ("nodejs", "templates"):
            section = (data.get(section_name) or {})
            for rule_id, rule in section.items():
                metadata = rule.get("metadata") or {}
                severity = metadata.get("severity")
                for hit in rule.get("files") or []:
                    findings.append(
                        {
                            "check_id": rule_id,
                            "path": hit.get("file_path"),
                            "start_line": hit.get("match_lines", [None])[0],
                            "end_line": (hit.get("match_lines") or [None, None])[-1],
                            "message": metadata.get("description") or metadata.get("owasp"),
                            "severity": severity,
                        }
                    )
        return {"findings": findings}
