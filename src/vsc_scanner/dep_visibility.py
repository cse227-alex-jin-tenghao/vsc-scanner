"""Stage 1 — classify how much dependency signal an extension exposes.

The four booleans are recorded independently because they describe distinct
facts about the shipped tree; the tier is just a convenience ranking. Tier 4
(no signal, typical of a well-bundled extension) is the NORMAL outcome and
must not be reported as a risk indicator — it is an absence of measurement.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("vsc_scanner")


@dataclass(frozen=True)
class DepVisibility:
    has_lockfile: bool
    has_node_modules: bool
    deps_declared_nonempty: bool
    bundle_artifact_detected: bool
    tier: int  # 1 best (lockfile), 4 worst (no signal)


def classify(extension_dir: Path, bundle_artifact_detected: bool) -> DepVisibility:
    """Inspect the unpacked extension tree and return its dep-visibility tier."""
    has_lockfile = _has_lockfile(extension_dir)
    has_node_modules = _node_modules_nonempty(extension_dir)
    deps_declared_nonempty = _deps_declared_nonempty(extension_dir)
    tier = _derive_tier(has_lockfile, has_node_modules, deps_declared_nonempty)
    return DepVisibility(
        has_lockfile=has_lockfile,
        has_node_modules=has_node_modules,
        deps_declared_nonempty=deps_declared_nonempty,
        bundle_artifact_detected=bundle_artifact_detected,
        tier=tier,
    )


def _has_lockfile(extension_dir: Path) -> bool:
    return (
        (extension_dir / "package-lock.json").is_file()
        or (extension_dir / "yarn.lock").is_file()
    )


def _node_modules_nonempty(extension_dir: Path) -> bool:
    nm = extension_dir / "node_modules"
    if not nm.is_dir():
        return False
    try:
        return any(nm.iterdir())
    except OSError as exc:
        log.warning("dep_visibility: cannot list %s: %s", nm, exc)
        return False


def _deps_declared_nonempty(extension_dir: Path) -> bool:
    package_json = extension_dir / "package.json"
    if not package_json.is_file():
        return False
    try:
        data = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("dep_visibility: cannot parse %s: %s", package_json, exc)
        return False
    deps = data.get("dependencies")
    return isinstance(deps, dict) and len(deps) > 0


def _derive_tier(
    has_lockfile: bool, has_node_modules: bool, deps_declared_nonempty: bool
) -> int:
    if has_lockfile:
        return 1
    if has_node_modules:
        return 2
    if deps_declared_nonempty:
        return 3
    return 4
