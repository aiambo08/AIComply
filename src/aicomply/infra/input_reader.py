"""Bounded, read-only input handling for individual scanner entry points."""

import os
import stat
from pathlib import Path


MAX_INPUT_BYTES = 4 * 1024 * 1024


def read_scan_text(file_path: Path, base_path: Path | None = None) -> str:
    path = file_path.absolute()
    if base_path is not None:
        root = base_path.absolute()
        path.relative_to(root)
        path.resolve().relative_to(root.resolve())
        for component in (path, *path.parents):
            if component == root:
                break
            if component.is_symlink():
                raise ValueError(f"Symlink scan input is not supported: {file_path}")
    elif path.is_symlink():
        raise ValueError(f"Symlink scan input is not supported: {file_path}")

    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Scan input must be a regular file: {file_path}")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise ValueError(f"Scan input exceeds {MAX_INPUT_BYTES} bytes: {file_path}")
    flags = os.O_RDONLY
    if os.name == "posix":
        flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"Scan input must be a regular file: {file_path}")
        content = stream.read(MAX_INPUT_BYTES + 1)
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError(f"Scan input exceeds {MAX_INPUT_BYTES} bytes: {file_path}")
    return content.decode("utf-8-sig")
