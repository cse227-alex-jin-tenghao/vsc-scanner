"""Smoke-test scanner that just lists directory contents."""

from pathlib import Path

from vsc_scanner.scanners.base import Scanner
from vsc_scanner.structs import ExtensionBundle


class LsScanner(Scanner):
    """Run `ls -1 -a` against root, extension, and (if present) repo dirs."""

    def __init__(self) -> None:
        self.name = "ls"

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        return [
            ("root", bundle.root_dir),
            ("extension", bundle.extension_dir),
        ]

    def argv(self, target: Path) -> list[str]:
        return ["ls", "-1", "-a", str(target)]

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        entries = [line for line in stdout.splitlines() if line]
        return {"entries": entries}
