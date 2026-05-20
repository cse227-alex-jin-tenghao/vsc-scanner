"""CLI entrypoint that materializes a VSCode extension's source on disk."""

import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vsc_scanner import marketplace, repo, vsix  # noqa: E402
from vsc_scanner.identifier import parse_marketplace_url  # noqa: E402
from vsc_scanner.structs import ExtensionBundle  # noqa: E402

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def fetch_extension(
    marketplace_url: str, *, work_dir: Path | None = None
) -> ExtensionBundle:
    """Download and unpack a VSCode extension and (best-effort) its repo.

    Returns an ExtensionBundle with paths into a fresh temp directory. The
    caller owns cleanup of `bundle.root_dir`.
    """
    root_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="vsc-scanner-"))
    root_dir.mkdir(parents=True, exist_ok=True)
    log_path = root_dir / "fetch.log"
    log = _configure_logging(log_path)

    log.info("fetch_extension start: url=%s root=%s", marketplace_url, root_dir)

    publisher, name = parse_marketplace_url(marketplace_url)
    log.info("parsed publisher=%s name=%s", publisher, name)

    version = marketplace.query_latest_version(publisher, name)
    vsix_path = root_dir / f"{publisher}.{name}-{version}.vsix"
    marketplace.download_vsix(publisher, name, version, vsix_path)

    extracted_root = root_dir / "vsix"
    extension_dir = vsix.extract_vsix(vsix_path, extracted_root)
    package_json = vsix.read_package_json(extension_dir)
    repo_url, repo_version = vsix.extract_repo_info(package_json)

    repo_dir: Path | None = None
    repo_ref: str | None = None
    if repo_url:
        try:
            repo_dir, repo_ref = repo.clone_repo(
                repo_url, repo_version, root_dir / "repo"
            )
        except RuntimeError as err:
            # Repo clone is best-effort; the VSIX scan can still proceed.
            log.warning("repo clone failed: %s", err)
    else:
        log.info("no repository URL found in package.json")

    log.info("fetch_extension done")
    return ExtensionBundle(
        publisher=publisher,
        name=name,
        version=version,
        root_dir=root_dir,
        extension_dir=extension_dir,
        repo_dir=repo_dir,
        repo_ref=repo_ref,
        log_path=log_path,
    )


def _configure_logging(log_path: Path) -> logging.Logger:
    """Attach a file handler for the `vsc_scanner` logger pointed at `log_path`."""
    log = logging.getLogger("vsc_scanner")
    log.setLevel(logging.INFO)

    # Avoid stacking duplicate file handlers when fetch_extension is called
    # multiple times in the same process.
    for existing in list(log.handlers):
        if isinstance(existing, logging.FileHandler) and Path(
            existing.baseFilename
        ) == log_path:
            return log

    handler = logging.FileHandler(log_path)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    log.addHandler(handler)
    return log


def _main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python scan.py <marketplace-url>", file=sys.stderr)
        return 2

    bundle = fetch_extension(argv[1])
    print(f"publisher:     {bundle.publisher}")
    print(f"name:          {bundle.name}")
    print(f"version:       {bundle.version}")
    print(f"root_dir:      {bundle.root_dir}")
    print(f"extension_dir: {bundle.extension_dir}")
    print(f"repo_dir:      {bundle.repo_dir}")
    print(f"repo_ref:      {bundle.repo_ref}")
    print(f"log:           {bundle.log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
