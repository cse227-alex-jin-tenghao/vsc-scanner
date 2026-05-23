"""Data structs threaded through the pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vsc_scanner.dep_visibility import DepVisibility
    from vsc_scanner.preprocess import PreprocessResult


@dataclass(frozen=True)
class ExtensionBundle:
    """The materialized source for one VSCode extension."""

    publisher: str
    name: str
    version: str
    root_dir: Path
    extension_dir: Path
    log_path: Path
    last_updated: str | None = None
    preprocessed_dir: Path | None = None
    preprocess: PreprocessResult | None = None
    dep_visibility: DepVisibility | None = None
