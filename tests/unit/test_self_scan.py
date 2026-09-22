import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner
import yaml

from aicomply.cli import app
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine
from aicomply.schemas import ScanReport
from scripts.check_self_scan import (
    Baseline, PolicyMismatch, ReviewedFile, ReviewedFinding, main, run, verify_baseline,
)


ROOT = Path(__file__).resolve().parents[2]


def scan(root: Path) -> ScanReport:
    return ScanEngine(load_builtin_rules()).scan_path(root)


@pytest.fixture
def reviewed(tmp_path: Path) -> tuple[Path, ScanReport, Baseline]:
    root = tmp_path / "project"
    root.mkdir()
    (root / "fixture.py").write_text("ai_disclaimer = False\n", encoding="utf-8")
    (root / "app.py").write_text("answer = 42\n", encoding="utf-8")
    report = scan(root)
    assert report.findings
    assert report.config_fingerprint is not None
    assert report.rules_fingerprint is not None
    baseline = Baseline(
        version=1,
        config_fingerprint=report.config_fingerprint,
        rules_fingerprint=report.rules_fingerprint,
        files={
            entry.path: ReviewedFile(sha256=entry.sha256, reason="Synthetic regression fixture")
            for entry in report.source_manifest if entry.path == "fixture.py"
        },
        findings=[
            ReviewedFinding(
                id=finding.id, rule_id=finding.rule_id,
                path=finding.location.file_path, line=finding.location.start_line,
            )
            for finding in report.findings
        ],
    )
    return root, report, baseline


def test_exact_baseline_passes_without_changing_client_cli(reviewed):
    root, report, baseline = reviewed
    verify_baseline(report, baseline)
    assert CliRunner().invoke(app, ["scan", str(root)]).exit_code == 1


def test_new_finding_in_operational_code_blocks(reviewed):
    root, _, baseline = reviewed
    (root / "app.py").write_text("ai_disclaimer = False\n", encoding="utf-8")
    with pytest.raises(PolicyMismatch, match="Unexpected finding"):
        verify_baseline(scan(root), baseline)


def test_content_change_without_new_finding_blocks(reviewed):
    root, report, baseline = reviewed
    source = root / "fixture.py"
    source.write_text(source.read_text() + "answer = 42\n", encoding="utf-8")
    changed = scan(root)
    assert [item.id for item in changed.findings] == [item.id for item in report.findings]
    with pytest.raises(PolicyMismatch, match="Reviewed file changed"):
        verify_baseline(changed, baseline)


def test_deleted_reviewed_file_blocks(reviewed):
    root, _, baseline = reviewed
    (root / "fixture.py").unlink()
    with pytest.raises(PolicyMismatch, match="not scanned"):
        verify_baseline(scan(root), baseline)


@pytest.mark.parametrize("field", ["config_fingerprint", "rules_fingerprint"])
def test_policy_or_catalog_drift_blocks(reviewed, field):
    _, report, baseline = reviewed
    with pytest.raises(PolicyMismatch, match="configuration or rule catalog changed"):
        verify_baseline(report.model_copy(update={field: "f" * 64}), baseline)


def test_excluding_reviewed_files_blocks(reviewed):
    root, _, baseline = reviewed
    (root / ".aicomply.yaml").write_text("exclude_paths: ['fixture.py']\n", encoding="utf-8")
    with pytest.raises(PolicyMismatch, match="configuration or rule catalog changed"):
        verify_baseline(scan(root), baseline)


@pytest.mark.parametrize("change", ["missing", "duplicate", "id", "rule", "path", "line"])
def test_exact_finding_identity_and_multiplicity_required(reviewed, change):
    _, report, baseline = reviewed
    finding = report.findings[0]
    findings = list(report.findings)
    if change == "missing":
        findings.pop(0)
    elif change == "duplicate":
        findings.append(finding)
    elif change == "id":
        findings[0] = finding.model_copy(update={"id": "f" * 64})
    elif change == "rule":
        findings[0] = finding.model_copy(update={"rule_id": "NEW-ART01-001"})
    else:
        location = finding.location.model_copy(update={
            "file_path": "app.py",
        } if change == "path" else {"start_line": 2})
        findings[0] = finding.model_copy(update={"location": location})
    with pytest.raises(PolicyMismatch, match="finding"):
        verify_baseline(report.model_copy(update={"findings": findings}), baseline)


@pytest.mark.parametrize("change", ["duplicate", "unused_file"])
def test_inconsistent_baseline_blocks(reviewed, change):
    _, report, baseline = reviewed
    if change == "duplicate":
        invalid = baseline.model_copy(update={"findings": baseline.findings * 2})
    else:
        invalid = baseline.model_copy(update={
            "files": {**baseline.files, "app.py": baseline.files["fixture.py"]},
        })
    with pytest.raises(ValueError):
        verify_baseline(report, invalid)


@pytest.mark.parametrize("data", ["{}", '{"version": 2}', '{"version": "1"}', "null"])
def test_incomplete_or_invalid_baseline_rejected(data):
    with pytest.raises(ValidationError):
        Baseline.model_validate_json(data)


def test_sarif_preserves_findings_when_policy_fails(reviewed, tmp_path, monkeypatch):
    root, _, baseline = reviewed
    policy = tmp_path / "baseline.json"
    policy.write_text(baseline.model_dump_json(), encoding="utf-8")
    (root / "app.py").write_text("ai_disclaimer = False\n", encoding="utf-8")
    output = tmp_path / "report.sarif"
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    with pytest.raises(PolicyMismatch):
        run(root, policy, output)
    results = json.loads(output.read_text())["runs"][0]["results"]
    assert len(results) == len(baseline.findings) + 1
    assert not any("suppressions" in finding for finding in results)
    assert github_output.read_text().splitlines() == ["sarif_ready=false", "sarif_ready=true"]


@pytest.mark.parametrize("failure", ["syntax", "baseline", "finding"])
def test_command_exit_status_and_upload_readiness(reviewed, tmp_path, monkeypatch, failure):
    root, _, baseline = reviewed
    policy = tmp_path / "baseline.json"
    policy.write_text(baseline.model_dump_json(), encoding="utf-8")
    output = tmp_path / "report.sarif"
    output.write_text("stale report", encoding="utf-8")
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    if failure == "syntax":
        (root / "app.py").write_text("def broken(\n", encoding="utf-8")
    elif failure == "baseline":
        policy.write_text("{", encoding="utf-8")
    else:
        (root / "app.py").write_text("ai_disclaimer = False\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "check_self_scan.py", "--root", str(root),
        "--baseline", str(policy), "--output", str(output),
    ])
    assert main() == (1 if failure == "finding" else 2)
    assert github_output.read_text().splitlines()[-1] == (
        "sarif_ready=false" if failure == "syntax" else "sarif_ready=true"
    )
    if failure == "syntax":
        assert output.read_text() == "stale report"
    else:
        assert json.loads(output.read_text())["runs"][0]["invocations"][0]["executionSuccessful"]


def test_repository_matches_approved_self_scan_baseline():
    baseline = Baseline.model_validate_json((ROOT / ".github/self-scan-baseline.json").read_bytes())
    report = scan(ROOT)
    verify_baseline(report, baseline)
    assert len(report.findings) == len(baseline.findings) > 0


def test_workflow_enforces_policy_and_uploads_only_fresh_completed_scans():
    workflow = yaml.safe_load((ROOT / ".github/workflows/compliance.yml").read_text())
    job = workflow["jobs"]["aicomply-audit"]
    assert not job.get("continue-on-error")
    steps = job["steps"]
    assert all(not step.get("continue-on-error") for step in steps)
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "|| true" not in commands
    assert "uv sync --locked --no-dev --no-editable" in commands
    assert "scripts/check_self_scan.py" in commands
    upload = steps[-1]
    assert "sarif_ready == 'true'" in upload["if"]
    assert "!cancelled()" in upload["if"]
    assert "dependabot[bot]" in upload["if"]
    assert "head.repo.full_name == github.repository" in upload["if"]
