"""Stage 0 — preprocess an unpacked extension before any scanner runs.

Normalizes text files (NFKC + strip invisibles) so hidden-payload tricks can't
slip past pattern matchers, detects minification, and tries to recover real
source from source maps / webcrack / js-beautify when bundles are present.
"""

import base64
import json
import logging
import shutil
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from vsc_scanner._tools import resolve as _resolve_tool

log = logging.getLogger("vsc_scanner")

# Zero-width / invisible codepoints stripped after NFKC.
# Real marketplace malware has hidden payloads in these specifically to evade
# regex/grep-based scanners — normalize before any scanner sees the source.
_ZERO_WIDTH = frozenset(
    {
        "​",  # ZERO WIDTH SPACE
        "‌",  # ZERO WIDTH NON-JOINER
        "‍",  # ZERO WIDTH JOINER
        "⁠",  # WORD JOINER
        "﻿",  # BOM / ZERO WIDTH NO-BREAK SPACE
    }
)

# bytes-per-newline above this = minified. Real source averages ~30-80.
_MINIFIED_RATIO = 500

# Files larger than this are copied verbatim; normalizing huge bundles in one
# string allocation is wasteful and rarely yields useful regex hits anyway.
_MAX_NORMALIZE_BYTES = 16 * 1024 * 1024

_BINARY_SNIFF_BYTES = 4096


@dataclass
class PreprocessResult:
    """Per-extension provenance attached to the bundle for the runner/report."""

    preprocessed_dir: Path
    scanned_as: str  # "plain" | "reconstructed_from_map" | "unpacked" | "beautified_only"
    minified: bool
    had_source_map: bool
    bundle_artifact_detected: bool
    notes: list[str] = field(default_factory=list)


def preprocess(extension_dir: Path, dest_dir: Path) -> PreprocessResult:
    """Build a normalized copy of `extension_dir` at `dest_dir` and report provenance."""
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True)

    _copy_normalized(extension_dir, dest_dir)

    minified = _any_minified_js(dest_dir)
    notes: list[str] = []
    had_source_map = False
    scanned_as = "plain"

    if minified:
        if _try_source_map_recovery(dest_dir):
            had_source_map = True
            scanned_as = "reconstructed_from_map"
        elif _try_beautify(dest_dir, notes):
            scanned_as = "beautified_only"
        elif _try_webcrack(dest_dir, notes):
            # webcrack is slow (multi-minute on large bundles); only used as a
            # fallback if js-beautify isn't available. Most pattern-based rules
            # in semgrep/njsscan key on string literals (e.g. require("fs"))
            # which survive minification, so beautify is usually sufficient.
            scanned_as = "unpacked"
        else:
            scanned_as = "beautified_only"
            notes.append("minified but no recovery tool succeeded")

    return PreprocessResult(
        preprocessed_dir=dest_dir,
        scanned_as=scanned_as,
        minified=minified,
        had_source_map=had_source_map,
        bundle_artifact_detected=minified,
        notes=notes,
    )


def _copy_normalized(src: Path, dst: Path) -> None:
    """Mirror src→dst. Text files are NFKC-normalized + stripped of invisibles."""
    for path in src.rglob("*"):
        rel = path.relative_to(src)
        out = dst / rel
        if path.is_dir():
            out.mkdir(parents=True, exist_ok=True)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)

        try:
            raw = path.read_bytes()
        except OSError as exc:
            log.warning("preprocess: cannot read %s: %s", path, exc)
            continue

        if _is_binary(raw) or len(raw) > _MAX_NORMALIZE_BYTES:
            out.write_bytes(raw)
            continue

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Files that don't cleanly decode as UTF-8 are copied verbatim;
            # we'd rather miss normalization than corrupt them.
            out.write_bytes(raw)
            continue

        out.write_text(_normalize_text(text), encoding="utf-8")


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]


def _normalize_text(text: str) -> str:
    nfkc = unicodedata.normalize("NFKC", text)
    return "".join(c for c in nfkc if c not in _ZERO_WIDTH and not _is_variation_selector(c))


def _is_variation_selector(c: str) -> bool:
    cp = ord(c)
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _bytes_per_newline(data: bytes) -> float:
    return len(data) / (data.count(b"\n") + 1)


def _any_minified_js(root: Path) -> bool:
    for path in root.rglob("*.js"):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if data and _bytes_per_newline(data) > _MINIFIED_RATIO:
            return True
    return False


def _is_minified_file(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return bool(data) and _bytes_per_newline(data) > _MINIFIED_RATIO


def _try_source_map_recovery(root: Path) -> bool:
    """Look for .js.map or inline data-URI maps; reconstruct any originals found."""
    recovered = False
    for js_path in root.rglob("*.js"):
        if not js_path.is_file() or not _is_minified_file(js_path):
            continue
        source_map = _load_source_map(js_path)
        if source_map is None:
            continue
        try:
            if _reconstruct_from_map(js_path, source_map):
                recovered = True
        except (OSError, ValueError) as exc:
            log.warning("preprocess: source map reconstruction failed for %s: %s", js_path, exc)
    return recovered


def _load_source_map(js_path: Path) -> dict | None:
    external = js_path.with_suffix(js_path.suffix + ".map")
    if external.is_file():
        try:
            return json.loads(external.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            pass

    try:
        text = js_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # The sourceMappingURL comment is conventionally on the last non-empty line.
    for line in reversed(text.splitlines()[-5:]):
        marker = "sourceMappingURL=data:"
        idx = line.find(marker)
        if idx < 0:
            continue
        payload = line[idx + len(marker):]
        if ";base64," not in payload:
            return None
        b64 = payload.split(";base64,", 1)[1].strip().rstrip("*/").strip()
        try:
            return json.loads(base64.b64decode(b64))
        except (ValueError, json.JSONDecodeError):
            return None
    return None


def _reconstruct_from_map(js_path: Path, source_map: dict) -> bool:
    sources = source_map.get("sources") or []
    contents = source_map.get("sourcesContent") or []
    if not sources or not contents:
        return False

    out_root = js_path.with_suffix(js_path.suffix + ".sources")
    out_root.mkdir(parents=True, exist_ok=True)
    wrote_any = False
    for src_name, content in zip(sources, contents):
        if content is None:
            continue
        rel = _safe_relative_path(src_name)
        out_path = out_root / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        wrote_any = True
    return wrote_any


def _safe_relative_path(name: str) -> Path:
    cleaned = name.replace("\\", "/")
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    parts = [p for p in cleaned.split("/") if p and p != ".." and p != "."]
    return Path(*parts) if parts else Path("unknown")


def _try_webcrack(root: Path, notes: list[str]) -> bool:
    binary = _resolve_tool("webcrack")
    if binary is None:
        notes.append("webcrack not installed; skipped")
        return False
    unpacked = False
    for js_path in root.rglob("*.js"):
        if not _is_minified_file(js_path):
            continue
        out_dir = js_path.with_suffix(js_path.suffix + ".webcrack")
        result = subprocess.run(
            [binary, "-o", str(out_dir), str(js_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and out_dir.exists():
            unpacked = True
        else:
            log.info("preprocess: webcrack failed for %s rc=%d", js_path, result.returncode)
    return unpacked


def _try_beautify(root: Path, notes: list[str]) -> bool:
    binary = _resolve_tool("js-beautify")
    if binary is None:
        notes.append("js-beautify not installed; minified files left as-is")
        return False
    beautified = False
    for js_path in root.rglob("*.js"):
        if not _is_minified_file(js_path):
            continue
        result = subprocess.run(
            [binary, "-r", str(js_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            beautified = True
    return beautified
