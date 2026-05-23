"""Base Scanner interface and ScanResult struct."""

import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

from vsc_scanner.structs import ExtensionBundle

_STDERR_TAIL_BYTES = 2048

# Prepended to PATH for every scanner subprocess. njsscan shells out to semgrep,
# semgrep finds rule plugins via PATH, etc. — they all need to see the venv
# and the project-local tools/ dir without requiring a system-wide install.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_EXTRA_PATH = os.pathsep.join(
    str(p)
    for p in (
        _PROJECT_ROOT / ".venv" / "bin",
        _PROJECT_ROOT / "tools",
        _PROJECT_ROOT / "tools" / "node" / "node_modules" / ".bin",
    )
)


def scanner_env() -> dict[str, str]:
    """Subprocess env with venv/tools dirs prepended to PATH."""
    env = os.environ.copy()
    env["PATH"] = _EXTRA_PATH + os.pathsep + env.get("PATH", "")
    return env


@dataclass(frozen=True)
class ScanResult:
    """One scanner's findings against one target directory."""

    name: str
    target: str
    target_path: str
    exit_code: int
    findings: dict
    stderr_tail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Scanner:
    """Base class. Subclasses set `name` and override argv/parse/targets."""

    name: str = field(default="", init=False)

    def targets(self, bundle: ExtensionBundle) -> list[tuple[str, Path]]:
        raise NotImplementedError

    def argv(self, target: Path) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str, exit_code: int) -> dict:
        raise NotImplementedError

    def run(self, bundle: ExtensionBundle) -> list[ScanResult]:
        """Default driver: exec argv per target, parse stdout, package results."""
        results: list[ScanResult] = []
        for label, path in self.targets(bundle):
            proc = subprocess.run(
                self.argv(path),
                capture_output=True,
                text=True,
                check=False,
                env=scanner_env(),
            )
            findings = self.parse(proc.stdout, proc.stderr, proc.returncode)
            results.append(
                ScanResult(
                    name=self.name,
                    target=label,
                    target_path=str(path),
                    exit_code=proc.returncode,
                    findings=findings,
                    stderr_tail=proc.stderr[-_STDERR_TAIL_BYTES:],
                )
            )
        return results
