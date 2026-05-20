"""Shallow git cloning with version-tag guessing."""

import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def candidate_tags(version: str) -> list[str]:
    """Plausible git tag names derived from a package.json version string."""
    return [f"v{version}", version, f"release-{version}"]


def clone_repo(
    repo_url: str, version: str | None, dest_dir: Path
) -> tuple[Path, str]:
    """Shallow-clone `repo_url` into `dest_dir`.

    Tries `candidate_tags(version)` in order; on success returns (dest, tag).
    Falls back to the default branch (returning ref "HEAD") if no tag matches
    or `version` is None. Raises on total clone failure.
    """
    tags_to_try = candidate_tags(version) if version else []
    for tag in tags_to_try:
        if _try_clone(repo_url, dest_dir, ref=tag):
            log.info("cloned %s at tag %s", repo_url, tag)
            return dest_dir, tag
        log.info("tag %s not found on %s", tag, repo_url)

    # Fallback: default branch tip. Worth noting in logs since the resulting
    # source may not match the published VSIX exactly.
    log.info("falling back to default branch for %s", repo_url)
    if _try_clone(repo_url, dest_dir, ref=None):
        return dest_dir, "HEAD"

    raise RuntimeError(f"failed to clone {repo_url}")


def _try_clone(repo_url: str, dest_dir: Path, ref: str | None) -> bool:
    """Attempt one clone. Cleans up `dest_dir` on failure. Returns success."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir)

    cmd = ["git", "clone", "--depth=1"]
    if ref is not None:
        cmd += ["--branch", ref]
    cmd += [repo_url, str(dest_dir)]

    log.info("running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True

    log.info("git clone failed (rc=%d): %s", result.returncode, result.stderr.strip())
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    return False
