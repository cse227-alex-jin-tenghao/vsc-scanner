"""Data structs returned by step 1 of the pipeline."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExtensionBundle:
    """The materialized source for one VSCode extension."""

    publisher: str
    name: str
    version: str
    root_dir: Path
    extension_dir: Path
    repo_dir: Path | None
    repo_ref: str | None
    log_path: Path
