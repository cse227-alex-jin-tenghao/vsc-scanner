"""Step 4 — teardown for a fetched extension bundle."""

import logging
import shutil

from vsc_scanner.structs import ExtensionBundle

log = logging.getLogger("vsc_scanner")


def cleanup_bundle(bundle: ExtensionBundle) -> None:
    """Best-effort removal of the bundle's temp root_dir and all contents."""
    root = bundle.root_dir
    if not root.exists():
        log.info("cleanup_bundle: root already gone: %s", root)
        return

    shutil.rmtree(root, onerror=_on_rmtree_error)
    log.info("cleanup_bundle: complete root=%s", root)


def _on_rmtree_error(func, path, exc_info) -> None:
    # Swallow per-file failures so cleanup can't mask earlier scan results;
    # the warning still lands in fetch.log (if still present) and stderr.
    log.warning("cleanup_bundle: failed to remove %s: %s", path, exc_info[1])
