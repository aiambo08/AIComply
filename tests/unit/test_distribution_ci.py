import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from unittest.mock import patch
import zipfile

import pytest
import yaml

from scripts.check_quality import verify_archives

ROOT = Path(__file__).resolve().parents[2]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
STEPS = {step["id"]: step for step in ACTION["runs"]["steps"] if "id" in step}


def action_python(step_id: str) -> str:
    script = STEPS[step_id]["run"]
    assert script.startswith("python -I - <<'PY'\n")
    return script.split("\n", 1)[1].removesuffix("PY\n")


def sarif(findings: int = 0, successful: bool = True) -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "invocations": [{"executionSuccessful": successful}],
            "results": [{"message": {"text": "synthetic finding"}}] * findings,
        }],
    })


def execute_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int = 0,
    report: str | None = None,
    **overrides: str,
) -> tuple[int, dict[str, str], list[str]]:
    environment = {
        "AICOMPLY_PYTHON": sys.executable,
        "SCAN_PATH": ".",
        "REPORT_FORMAT": "sarif",
        "REPORT_OUTPUT": str(tmp_path / "result.sarif"),
        "SIGN_REPORT": "false",
        "SIGNING_KEY": "",
        "SIGNER_ID": "",
        "RISK_TIER": "",
        "UPLOAD_SARIF": "true",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        **overrides,
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    arguments = []

    def scan(command: list[str], *, check: bool) -> subprocess.CompletedProcess[str]:
        arguments.extend(command)
        if report is not None:
            Path(command[command.index("--output") + 1]).write_text(report, encoding="utf-8")
        return subprocess.CompletedProcess(command, exit_code)

    with patch("subprocess.run", side_effect=scan), pytest.raises(SystemExit) as result:
        exec(compile(action_python("run-scan"), "action.yml", "exec"), {})
    outputs = dict(
        line.split("=", 1)
        for line in Path(environment["GITHUB_OUTPUT"]).read_text(encoding="utf-8").splitlines()
    )
    return result.value.code, outputs, arguments


@pytest.mark.parametrize("code,count,status", [(0, 0, "no_findings"), (1, 2, "violations_found"), (0, 2, "violations_found")])
def test_scan_preserves_completed_exit_codes(tmp_path, monkeypatch, code, count, status):
    actual, outputs, _ = execute_scan(tmp_path, monkeypatch, code, sarif(count))
    assert actual == code
    assert outputs == {
        "scan_status": status, "findings_count": str(count), "sarif_ready": "true",
    }
    assert (tmp_path / "result.sarif").read_text() == sarif(count)


@pytest.mark.parametrize("code,count", [(0, 0), (0, 2), (1, 2)])
def test_scan_logs_finding_count_and_policy_failure(tmp_path, monkeypatch, capsys, code, count):
    actual, _, _ = execute_scan(tmp_path, monkeypatch, code, sarif(count))
    message = capsys.readouterr().out
    assert actual == code
    assert f"{count} finding(s) in the saved report" in message
    assert ("::error::AIComply findings exceed the configured policy" in message) == (code == 1)


@pytest.mark.parametrize("code", [2, 7, 127])
def test_scan_errors_do_not_upload_stale_reports(tmp_path, monkeypatch, code):
    destination = tmp_path / "result.sarif"
    destination.write_text(sarif())
    actual, outputs, _ = execute_scan(tmp_path, monkeypatch, code, sarif())
    assert actual == code
    assert outputs == {"scan_status": "error", "findings_count": "", "sarif_ready": "false"}


@pytest.mark.parametrize("report", [None, "", "not json", "{}", "[]", sarif(successful=False)])
def test_absent_malformed_or_incomplete_report_fails(tmp_path, monkeypatch, report):
    actual, outputs, _ = execute_scan(tmp_path, monkeypatch, report=report)
    assert actual == 2
    assert outputs["sarif_ready"] == "false"
    assert outputs["scan_status"] == "error"
    assert not (tmp_path / "result.sarif").exists()


def test_inputs_remain_literal_arguments(tmp_path, monkeypatch):
    suspicious = "-file with 'quotes' $(touch INJECTED); echo injected\nline"
    destination = tmp_path / "report 'quote' $(touch INJECTED).sarif"
    actual, outputs, command = execute_scan(
        tmp_path, monkeypatch, report=sarif(), SCAN_PATH=suspicious, REPORT_FORMAT="json",
        REPORT_OUTPUT=str(destination), SIGN_REPORT="true", SIGNING_KEY=suspicious,
        SIGNER_ID=suspicious, RISK_TIER="high_risk",
    )
    assert actual == 0
    assert command[:5] == [sys.executable, "-I", "-m", "aicomply.cli", "scan"]
    assert command[-2:] == ["--", suspicious]
    assert command[command.index("--key") + 1] == str(Path(suspicious).absolute())
    assert "--signer-id=" + suspicious in command
    assert command[command.index("--enforce-risk-tier") + 1] == "high_risk"
    assert destination.read_text() == sarif()
    assert outputs["sarif_ready"] == "false"
    assert outputs["scan_status"] == "completed"
    assert not (tmp_path / "INJECTED").exists()


@pytest.mark.parametrize("overrides", [
    {"REPORT_FORMAT": "sarif; echo unsafe"},
    {"RISK_TIER": "not-a-tier"},
    {"SIGN_REPORT": "true"},
    {"SIGN_REPORT": "true", "SIGNING_KEY": "key.pem", "REPORT_FORMAT": "sarif"},
    {"SIGN_REPORT": "yes"},
    {"UPLOAD_SARIF": "yes"},
    {"SCAN_PATH": ""},
    {"REPORT_OUTPUT": ""},
])
def test_invalid_inputs_fail_before_scan(tmp_path, monkeypatch, overrides):
    code, outputs, command = execute_scan(tmp_path, monkeypatch, report=sarif(), **overrides)
    assert code == 2
    assert not command
    assert outputs["scan_status"] == "error"


def test_non_sarif_is_not_reported_as_zero_findings(tmp_path, monkeypatch):
    code, outputs, _ = execute_scan(
        tmp_path, monkeypatch, 1, "markdown report", REPORT_FORMAT="markdown"
    )
    assert code == 1
    assert outputs["findings_count"] == ""
    assert outputs["sarif_ready"] == "false"


def test_report_symlinks_are_not_overwritten(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_text("untouched")
    destination = tmp_path / "result.sarif"
    destination.symlink_to(target)
    code, outputs, _ = execute_scan(tmp_path, monkeypatch, report=sarif())
    assert code == 2
    assert outputs["sarif_ready"] == "false"
    assert target.read_text() == "untouched"


def test_report_parent_symlinks_are_not_followed(tmp_path, monkeypatch):
    target = tmp_path / "outside"
    target.mkdir()
    protected = target / "result.sarif"
    protected.write_text("untouched")
    link = tmp_path / "reports"
    link.symlink_to(target, target_is_directory=True)
    code, outputs, _ = execute_scan(
        tmp_path, monkeypatch, report=sarif(), REPORT_OUTPUT=str(link / "result.sarif")
    )
    assert code == 2
    assert outputs["sarif_ready"] == "false"
    assert protected.read_text() == "untouched"


@pytest.mark.parametrize("version", ["", "aicomply-cli"])
def test_default_install_uses_action_source_and_lock(tmp_path, monkeypatch, version):
    source = "/action source/with 'quotes' $(not-executed)"
    for key, value in {
        "AICOMPLY_VERSION": version, "ACTION_PATH": source,
        "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "outputs"),
    }.items():
        monkeypatch.setenv(key, value)
    with patch("subprocess.run") as run:
        exec(compile(action_python("install"), "action.yml", "exec"), {})
    sync = run.call_args_list[-1]
    command = sync.args[0]
    assert command[-2:] == ["--project", source]
    assert {"--locked", "--no-editable", "--no-dev", "--no-config"} <= set(command)
    assert sync.kwargs["env"]["UV_PROJECT_ENVIRONMENT"].startswith(str(tmp_path))
    assert "python=" in (tmp_path / "outputs").read_text()


def test_pinned_override_ignores_client_uv_configuration(tmp_path, monkeypatch):
    for key, value in {
        "AICOMPLY_VERSION": "aicomply-cli==2.0.0a0",
        "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "outputs"),
    }.items():
        monkeypatch.setenv(key, value)
    with patch("subprocess.run") as run:
        exec(compile(action_python("install"), "action.yml", "exec"), {})
    uv_commands = [call.args[0] for call in run.call_args_list if "uv" in call.args[0]]
    assert len(uv_commands) == 2
    assert all(command[1:5] == ["-I", "-m", "uv", "--no-config"] for command in uv_commands)
    assert uv_commands[-1][-1] == "aicomply-cli==2.0.0a0"


@pytest.mark.parametrize("version", ["aicomply-cli>=1", ".", "git+https://example.org/client", '$(touch INJECTED)', "aicomply-cli; echo unsafe"])
def test_install_rejects_unpinned_or_executable_sources(monkeypatch, version):
    monkeypatch.setenv("AICOMPLY_VERSION", version)
    with patch("subprocess.run") as run, pytest.raises(SystemExit):
        exec(compile(action_python("install"), "action.yml", "exec"), {})
    run.assert_not_called()


def test_action_has_no_expression_interpolation_in_scripts():
    for step in ACTION["runs"]["steps"]:
        assert "${{" not in step.get("run", "")
    upload = ACTION["runs"]["steps"][-1]
    assert "!cancelled()" in upload["if"]
    assert "sarif_ready == 'true'" in upload["if"]
    assert "head.repo.full_name == github.repository" in upload["if"]
    assert "pull_request_target" in upload["if"]
    assert "dependabot[bot]" in upload["if"]


def test_real_action_shell_with_quoted_paths(tmp_path):
    target = tmp_path / "source 'quote' $(touch INJECTED)"
    target.mkdir()
    (target / "app.py").write_text("answer = 42\n", encoding="utf-8")
    destination = tmp_path / "report 'quote' $(touch INJECTED).sarif"
    output = tmp_path / "github-output"
    environment = {
        **os.environ,
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        "AICOMPLY_PYTHON": sys.executable,
        "SCAN_PATH": str(target),
        "REPORT_FORMAT": "sarif",
        "REPORT_OUTPUT": str(destination),
        "SIGN_REPORT": "false",
        "SIGNING_KEY": "",
        "SIGNER_ID": "",
        "RISK_TIER": "",
        "UPLOAD_SARIF": "true",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(output),
    }
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", STEPS["run-scan"]["run"]],
        env=environment, cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(destination.read_text())["runs"][0]["results"] == []
    assert "sarif_ready=true" in output.read_text()
    assert not (tmp_path / "INJECTED").exists()


@pytest.mark.parametrize("missing", [None, "rule", "ui"])
def test_archive_check_detects_missing_resources(tmp_path, missing):
    package = tmp_path / "src" / "aicomply"
    resources = {"rules/rule.yaml": b"rule", "ui/static/app.html": b"<html>ui</html>"}
    for name, content in resources.items():
        path = package / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    wheel = tmp_path / "aicomply.whl"
    sdist = tmp_path / "aicomply.tar.gz"
    with zipfile.ZipFile(wheel, "w") as archive, tarfile.open(sdist, "w:gz") as source:
        for name, content in resources.items():
            if not (missing == "ui" and name.startswith("ui/")):
                archive.writestr("aicomply/" + name, content)
            if not (missing == "rule" and name.startswith("rules/")):
                member = tarfile.TarInfo("aicomply/src/aicomply/" + name)
                member.size = len(content)
                source.addfile(member, io.BytesIO(content))
    if missing:
        with pytest.raises(KeyError):
            verify_archives(tmp_path, wheel, sdist)
    else:
        verify_archives(tmp_path, wheel, sdist)


def test_release_publishes_only_verified_artifacts():
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == "quality"
    assert publish["permissions"] == {"id-token": "write"}
    assert "refs/tags/v" in publish["if"]
    assert all("checkout" not in step.get("uses", "") for step in publish["steps"])
    assert publish["steps"][0]["with"]["name"] == "python-distributions"
    quality = yaml.safe_load((ROOT / ".github/workflows/quality.yml").read_text())
    assert quality["permissions"] == {"contents": "read"}
    commands = "\n".join(step.get("run", "") for step in quality["jobs"]["quality"]["steps"])
    assert "uv sync --locked --extra dev" in commands
    assert "scripts/check_quality.py" in commands
