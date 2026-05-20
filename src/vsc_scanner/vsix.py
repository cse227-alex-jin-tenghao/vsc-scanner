"""VSIX archive helpers: unzip and inspect package.json."""

import json
import logging
import re
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)


def extract_vsix(vsix_path: Path, dest_dir: Path) -> Path:
    """Unzip `vsix_path` into `dest_dir` and return the `extension/` subdir."""
    log.info("extracting %s to %s", vsix_path, dest_dir)
    with zipfile.ZipFile(vsix_path) as zf:
        zf.extractall(dest_dir)

    extension_dir = dest_dir / "extension"
    if not extension_dir.is_dir():
        raise RuntimeError(f"VSIX did not contain an extension/ folder: {vsix_path}")
    return extension_dir


def read_package_json(extension_dir: Path) -> dict:
    """Load and return the parsed `extension/package.json`."""
    package_json_path = extension_dir / "package.json"
    with package_json_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def extract_repo_info(package_json: dict) -> tuple[str | None, str | None]:
    """Return (normalized_repo_url, version) from a parsed package.json.

    Repo URL may be `None` when no repository field is present or it is not a
    git URL we know how to clone.
    """
    version = package_json.get("version")
    repo_field = package_json.get("repository")

    raw_url: str | None = None
    if isinstance(repo_field, str):
        raw_url = repo_field
    elif isinstance(repo_field, dict):
        raw_url = repo_field.get("url")

    normalized = _normalize_git_url(raw_url) if raw_url else None
    if raw_url and not normalized:
        log.info("repository field present but not a recognized git URL: %r", raw_url)
    return normalized, version


def _normalize_git_url(url: str) -> str | None:
    """Normalize various git URL spellings to https form, or return None."""
    cleaned = url.strip()
    if cleaned.startswith("git+"):
        cleaned = cleaned[len("git+"):]
    if cleaned.endswith(".git"):
        # keep the .git suffix - git clone accepts both forms but it's canonical
        pass

    # git@github.com:owner/repo(.git) -> https://github.com/owner/repo(.git)
    ssh_match = re.match(r"^git@([^:]+):(.+)$", cleaned)
    if ssh_match:
        host, path = ssh_match.groups()
        cleaned = f"https://{host}/{path}"

    if cleaned.startswith(("http://", "https://", "ssh://")):
        return cleaned
    return None
