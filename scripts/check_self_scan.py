"""Scan this repository while retaining explicitly reviewed findings in SARIF."""

import argparse
from collections import Counter
import os
from pathlib import Path
import sys
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from aicomply.cli import write_report
from aicomply.config import read_regular_file
from aicomply.reporter.sarif_reporter import generate_sarif_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine
from aicomply.schemas import ScanReport


SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ReviewedFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sha256: SHA256
    reason: str = Field(min_length=1)


class ReviewedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: SHA256
    rule_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int = Field(ge=1)


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    config_fingerprint: SHA256
    rules_fingerprint: SHA256
    files: dict[str, ReviewedFile]
    findings: list[ReviewedFinding]


class PolicyMismatch(ValueError):
    pass


def verify_baseline(report: ScanReport, baseline: Baseline) -> None:
    if report.analysis_status != "completed" or not report.source_manifest:
        raise ValueError("A completed scan with a source manifest is required")
    if (
        report.config_fingerprint != baseline.config_fingerprint
        or report.rules_fingerprint != baseline.rules_fingerprint
    ):
        raise PolicyMismatch("Scan configuration or rule catalog changed; review required")
    expected = Counter(
        (finding.id, finding.rule_id, finding.path, finding.line)
        for finding in baseline.findings
    )
    if any(count != 1 for count in expected.values()):
        raise ValueError("Duplicate reviewed findings")
    if set(baseline.files) != {finding.path for finding in baseline.findings}:
        raise ValueError("Reviewed files must exactly match reviewed finding paths")
    manifest = {entry.path: entry.sha256 for entry in report.source_manifest}
    for path, reviewed in baseline.files.items():
        if manifest.get(path) != reviewed.sha256:
            raise PolicyMismatch(f"Reviewed file changed or was not scanned: {path}")
    actual = Counter(
        (finding.id, finding.rule_id, finding.location.file_path, finding.location.start_line)
        for finding in report.findings
    )
    unexpected = actual - expected
    missing = expected - actual
    if unexpected or missing:
        details = [
            f"{kind}: {rule_id} at {path}:{line} ({count})"
            for kind, findings in (("Unexpected finding", unexpected), ("Missing reviewed finding", missing))
            for (_, rule_id, path, line), count in sorted(findings.items())
        ]
        raise PolicyMismatch("\n".join(details))


def sarif_ready(ready: bool) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if destination:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write(f"sarif_ready={str(ready).lower()}\n")


def run(root: Path, baseline_path: Path, output: Path) -> None:
    sarif_ready(False)
    report = ScanEngine(load_builtin_rules()).scan_path(root)
    write_report(output, generate_sarif_report(report))
    sarif_ready(True)
    print(f"Completed self-scan: {len(report.findings)} finding(s) retained in SARIF.")
    baseline = Baseline.model_validate_json(read_regular_file(baseline_path, 1024 * 1024))
    verify_baseline(report, baseline)
    print("Reviewed fingerprints, file contents, configuration and rules match.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--baseline", type=Path, default=Path(".github/self-scan-baseline.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.root, args.baseline, args.output)
    except PolicyMismatch as exc:
        print(f"Self-scan policy failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Self-scan execution failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
