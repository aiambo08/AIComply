"""Bounded, read-only input handling for individual scanner entry points."""

from pathlib import Path

from aicomply.config import checked_path, read_regular_file

MAX_INPUT_BYTES = 4 * 1024 * 1024


def read_scan_text(file_path: Path, base_path: Path | None = None) -> str:
    path = checked_path(file_path)
    if base_path is not None:
        root = checked_path(base_path)
        path.relative_to(root)
    content = read_regular_file(path, MAX_INPUT_BYTES)
    return content.decode("utf-8-sig")
