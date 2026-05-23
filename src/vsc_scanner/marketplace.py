"""VSCode Marketplace API client: extension queries and VSIX downloads."""

import logging
from pathlib import Path

import requests

_QUERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
_VSPACKAGE_URL = (
    "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/"
    "{publisher}/vsextensions/{name}/{version}/vspackage"
)
_QUERY_HEADERS = {
    "Accept": "application/json;api-version=3.0-preview.1",
    "Content-Type": "application/json",
}
_FILTER_TYPE_EXTENSION_NAME = 7
_FLAG_INCLUDE_VERSIONS = 0x1

log = logging.getLogger(__name__)


class ExtensionNotFoundError(RuntimeError):
    """Raised when the marketplace query returns no matching extension."""


def query_latest_version(publisher: str, name: str) -> tuple[str, str | None]:
    """Return (version, last_updated_iso) for the latest published version."""
    item_name = f"{publisher}.{name}"
    body = {
        "filters": [
            {
                "criteria": [
                    {"filterType": _FILTER_TYPE_EXTENSION_NAME, "value": item_name}
                ],
                "pageNumber": 1,
                "pageSize": 1,
                "sortBy": 0,
                "sortOrder": 0,
            }
        ],
        "flags": _FLAG_INCLUDE_VERSIONS,
    }

    log.info("querying marketplace for %s", item_name)
    response = requests.post(_QUERY_URL, json=body, headers=_QUERY_HEADERS, timeout=30)
    response.raise_for_status()

    results = response.json().get("results", [])
    extensions = results[0].get("extensions", []) if results else []
    if not extensions:
        raise ExtensionNotFoundError(f"no extension matching {item_name!r}")

    versions = extensions[0].get("versions", [])
    if not versions:
        raise ExtensionNotFoundError(f"no versions listed for {item_name!r}")

    latest = versions[0]
    version = latest["version"]
    # Marketplace API may surface either `lastUpdated` on the version entry or
    # on the extension itself; prefer the per-version timestamp.
    last_updated = latest.get("lastUpdated") or extensions[0].get("lastUpdated")
    log.info("latest version of %s is %s (lastUpdated=%s)", item_name, version, last_updated)
    return version, last_updated


def download_vsix(publisher: str, name: str, version: str, dest_path: Path) -> Path:
    """Download a VSIX file and write it to `dest_path`."""
    url = _VSPACKAGE_URL.format(publisher=publisher, name=name, version=version)
    log.info("downloading VSIX from %s", url)

    # Accept-Encoding: identity forces the server to return the raw VSIX bytes
    # instead of a gzip-wrapped response that requests would auto-decompress.
    headers = {"Accept-Encoding": "identity"}
    with requests.get(url, headers=headers, stream=True, timeout=60) as response:
        response.raise_for_status()
        with dest_path.open("wb") as fh:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if chunk:
                    fh.write(chunk)

    log.info("VSIX saved to %s (%d bytes)", dest_path, dest_path.stat().st_size)
    return dest_path
