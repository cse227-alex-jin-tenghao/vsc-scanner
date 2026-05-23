"""Resolve external tool binaries.

Looks in project-local locations first (`tools/`, `tools/node/node_modules/.bin/`,
`.venv/bin/`) before falling back to PATH so the pipeline is portable without
requiring system-wide installs.
"""

import shutil
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SEARCH_DIRS = (
    _PROJECT_ROOT / "tools",
    _PROJECT_ROOT / "tools" / "node" / "node_modules" / ".bin",
    _PROJECT_ROOT / ".venv" / "bin",
)


def resolve(name: str) -> str | None:
    """Return an absolute path to `name`, or None if it cannot be found."""
    for d in _SEARCH_DIRS:
        candidate = d / name
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)
