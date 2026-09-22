"""Time-bounded local analysis on a private, size-bounded source snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import stat
import sys
from pathlib import Path

import yaml

from aicomply.config import error_summary
from aicomply.generator.annex_iv import AnnexIVGenerator
from aicomply.reporter.sarif_reporter import generate_sarif_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import IGNORED_DIRS, ScanEngine, is_scannable_file

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_DEPTH = 64
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


class SnapshotError(Exception):
    pass


class SourceSnapshot:
    """Copy regular inputs through directory-relative, non-following descriptors."""

    def __init__(self) -> None:
        self.entries = 0
        self.total_bytes = 0
        self.exclusions: dict[str, str] = {}
        self.destination = Path()

    def copy(self, root_fd: int, parts: list[str], filename: str, destination: Path) -> Path:
        self.destination = destination
        descriptor = os.dup(root_fd)
        try:
            for index, part in enumerate(parts):
                if part in {".", ".."} or "/" in part:
                    raise SnapshotError("Invalid snapshot path")
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if index < len(parts) - 1:
                    flags |= os.O_DIRECTORY
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            mode = os.fstat(descriptor).st_mode
            if stat.S_ISREG(mode):
                os.lseek(descriptor, 0, os.SEEK_SET)
                output = destination / filename
                self._file(descriptor, output)
                return output
            if not stat.S_ISDIR(mode):
                raise SnapshotError("Special files are not supported by the console")
            self._directory(descriptor, destination, 0)
            return destination
        finally:
            os.close(descriptor)

    def _file(self, descriptor: int, destination: Path) -> None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError("Special files are not supported by the console")
        if metadata.st_nlink > 1:
            raise SnapshotError("Hard-linked source files are not supported by the console")
        if metadata.st_size > MAX_FILE_BYTES:
            raise SnapshotError("Source file exceeds the 2 MiB console limit")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            self.total_bytes += len(chunk)
            if size > MAX_FILE_BYTES or self.total_bytes > MAX_TOTAL_BYTES:
                raise SnapshotError("Source bytes exceed console limits (2 MiB/file, 32 MiB total)")
        after = os.fstat(descriptor)
        if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) or size != after.st_size:
            raise SnapshotError("Source changed while copying; retry with a stable checkout")
        destination.write_bytes(b"".join(chunks))

    def _directory(self, descriptor: int, destination: Path, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise SnapshotError("Source directory nesting exceeds console limits")
        with os.scandir(descriptor) as entries:
            for entry in entries:
                self.entries += 1
                if self.entries > MAX_ENTRIES:
                    raise SnapshotError("Source tree exceeds the 10000-entry console limit")
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise SnapshotError("Symbolic links and special files are not supported by the console")
                if stat.S_ISDIR(mode) and entry.name in IGNORED_DIRS:
                    self.exclusions[(destination / entry.name).relative_to(self.destination).as_posix()] = "console: ignored directory"
                    continue
                if stat.S_ISREG(mode) and not is_scannable_file(Path(entry.name)):
                    self.exclusions[(destination / entry.name).relative_to(self.destination).as_posix()] = "console: unsupported extension or generated report"
                    continue
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if stat.S_ISDIR(mode):
                    flags |= os.O_DIRECTORY
                child = os.open(entry.name, flags, dir_fd=descriptor)
                try:
                    output = destination / entry.name
                    if stat.S_ISDIR(mode):
                        output.mkdir()
                        self._directory(child, output, depth + 1)
                    else:
                        self._file(child, output)
                finally:
                    os.close(child)


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    request = json.loads(sys.stdin.buffer.read(16384))
    target = Path(request["target"])
    try:
        copier = SourceSnapshot()
        snapshot = copier.copy(
            request["root_fd"], request["relative_parts"], target.name, Path(request["snapshot_dir"]),
        )
        try:
            report = ScanEngine(catalog=load_builtin_rules()).scan_path(snapshot)
        except (ValueError, SyntaxError, yaml.YAMLError, RecursionError) as error:
            cause = error_summary(error, 400).replace(str(snapshot), str(target))
            raise SnapshotError(f"Analysis incomplete: {cause}") from error
        config = {
            **report.effective_config,
            "console_limits": {
                "max_source_bytes": MAX_FILE_BYTES, "max_scan_bytes": MAX_TOTAL_BYTES,
                "max_entries": MAX_ENTRIES, "max_depth": MAX_DEPTH,
                "cpu_seconds": 20, "memory_bytes": 512 * 1024 * 1024,
            },
        }
        report = report.model_copy(update={
            "target_path": str(target),
            "effective_config": config,
            "config_fingerprint": hashlib.sha256(json.dumps(
                config, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ).encode("utf-8")).hexdigest(),
            "exclusions": {**copier.exclusions, **report.exclusions},
        })
        if request["operation"] == "docgen":
            markdown = AnnexIVGenerator(
                report, system_name=request["name"], version=request["version"],
            ).generate_markdown_dossier()
            result = json.dumps({
                "markdown": "DRAFT FOR QUALIFIED REVIEW — not a compliance determination.\n\n"
                            + markdown,
            })
        else:
            result = generate_sarif_report(report) if request["operation"] == "sarif" else report.model_dump_json()
        if len(result.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise SnapshotError("Result exceeds the 8 MiB console limit")
        sys.stdout.write(result)
    except SnapshotError as error:
        sys.stdout.write(json.dumps({"error": str(error), "status": 422}))
    except OSError:
        sys.stdout.write(json.dumps({"error": "Source cannot be read safely; no complete result is available", "status": 422}))


if __name__ == "__main__":
    main()
