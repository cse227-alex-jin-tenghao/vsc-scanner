"""CLI entrypoint that materializes a VSCode extension's source on disk."""

import dataclasses
import json
import logging
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vsc_scanner import marketplace, vsix  # noqa: E402
from vsc_scanner.cleanup import cleanup_bundle  # noqa: E402
from vsc_scanner.dep_visibility import classify as classify_dep_visibility  # noqa: E402
from vsc_scanner.identifier import parse_marketplace_url  # noqa: E402
from vsc_scanner.preprocess import preprocess  # noqa: E402
from vsc_scanner.runner import run_scanners  # noqa: E402
from vsc_scanner.scanners.gitleaks_scanner import GitleaksScanner  # noqa: E402
from vsc_scanner.scanners.ls_scanner import LsScanner  # noqa: E402
from vsc_scanner.scanners.osv_scanner import OsvScanner  # noqa: E402
from vsc_scanner.scanners.retirejs_scanner import RetireJsScanner  # noqa: E402
from vsc_scanner.scanners.semgrep_scanner import SemgrepScanner  # noqa: E402
from vsc_scanner.structs import ExtensionBundle  # noqa: E402

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def fetch_extension(
    marketplace_url: str, *, work_dir: Path | None = None
) -> ExtensionBundle:
    """Download and unpack a VSCode extension's VSIX into a temp directory.

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

    version, last_updated = marketplace.query_latest_version(publisher, name)
    vsix_path = root_dir / f"{publisher}.{name}-{version}.vsix"
    marketplace.download_vsix(publisher, name, version, vsix_path)

    extracted_root = root_dir / "vsix"
    extension_dir = vsix.extract_vsix(vsix_path, extracted_root)

    log.info("fetch_extension done")
    return ExtensionBundle(
        publisher=publisher,
        name=name,
        version=version,
        root_dir=root_dir,
        extension_dir=extension_dir,
        log_path=log_path,
        last_updated=last_updated,
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

    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in log.handlers):
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        stderr_handler.setLevel(logging.INFO)
        log.addHandler(stderr_handler)

    return log


def _build_scanners(smoke: bool, deep: bool) -> list:
    if smoke:
        return [LsScanner()]
    return [
        SemgrepScanner(deep=deep),
        RetireJsScanner(),
        OsvScanner(),
        GitleaksScanner(),
    ]


def _main(argv: list[str]) -> int:
    smoke = "--smoke" in argv
    deep = "--deep" in argv
    positional = [a for a in argv[1:] if not a.startswith("--")]
    if len(positional) != 1:
        print("usage: python scan.py [--smoke] [--deep] <marketplace-url>", file=sys.stderr)
        return 2

    t_total = time.perf_counter()
    t0 = time.perf_counter()
    bundle = fetch_extension(positional[0])
    t_fetch = time.perf_counter() - t0
    try:
        t0 = time.perf_counter()
        pre = preprocess(bundle.extension_dir, bundle.root_dir / "preprocessed")
        t_pre = time.perf_counter() - t0
        t0 = time.perf_counter()
        dep_vis = classify_dep_visibility(
            bundle.extension_dir, pre.bundle_artifact_detected
        )
        t_dep = time.perf_counter() - t0
        bundle = dataclasses.replace(
            bundle,
            preprocessed_dir=pre.preprocessed_dir,
            preprocess=pre,
            dep_visibility=dep_vis,
        )
        t0 = time.perf_counter()
        report = run_scanners(bundle, _build_scanners(smoke, deep))
        t_scan = time.perf_counter() - t0
        print(json.dumps(report, indent=2))
        print(
            f"[timing] fetch={t_fetch:.2f}s preprocess={t_pre:.2f}s "
            f"dep_visibility={t_dep:.2f}s scanners={t_scan:.2f}s "
            f"total={time.perf_counter() - t_total:.2f}s",
            file=sys.stderr,
        )
    finally:
        cleanup_bundle(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
