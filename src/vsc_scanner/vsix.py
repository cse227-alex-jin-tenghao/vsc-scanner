"""VSIX archive helpers: unzip and inspect package.json."""

import json
import logging
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
