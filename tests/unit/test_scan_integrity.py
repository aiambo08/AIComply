import hashlib
import json
import os
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aicomply.cli import app
from aicomply.config import AIComplyConfig, load_project_config, read_regular_file
from aicomply.evidence.hasher import compute_scan_hash
from aicomply.evidence.signer import generate_keypair, sign_scan_report, verify_evidence_bundle
from aicomply.rules.loader import RuleCatalog, RuleLoadError, load_builtin_rules, load_rules_from_dir
from aicomply.scanner import engine as engine_module
from aicomply.scanner.ast_parser import PythonASTScanner
from aicomply.scanner.engine import ScanEngine
from aicomply.schemas import ScanReport


@pytest.fixture(scope="module")
def catalog() -> RuleCatalog:
    return load_builtin_rules()


@pytest.mark.parametrize("content", [
    "exclude_paths: [", "exclude_paths: false", "ignore_rules: [123]", "unknown: true",
    "enforce_risk_tier: banana", "exclude_paths: []\nexclude_paths: [app.py]",
    "null", "false", "[]", "", "exclude_paths: &x [*x]",
    "custom_rules_dir: ../outside", "custom_rules_dir: /outside",
    "custom_rules_dir: 'C:\\outside'", "custom_rules_dir: ''",
    "exclude_paths: [../outside]", "ignore_rules: [typo]",
])
def test_invalid_configuration_fails_closed(tmp_path: Path, content: str):
    (tmp_path / ".aicomply.yaml").write_text(content)
    with pytest.raises(ValueError, match="Invalid project configuration"):
        load_project_config(tmp_path)


def test_ambiguous_configuration_fails(tmp_path: Path):
    (tmp_path / ".aicomply.yaml").write_text("{}")
    (tmp_path / "aicomply.yaml").write_text("{}")
    with pytest.raises(ValueError, match="Multiple"):
        load_project_config(tmp_path)


def test_explicit_default_configuration_is_not_overridden(tmp_path: Path, catalog: RuleCatalog):
    (tmp_path / ".aicomply.yaml").write_text("ignore_rules: [EUAIA-ART13-001]")
    source = tmp_path / "app.py"
    source.write_text("ai_disclaimer = False\n")
    report = ScanEngine(catalog, config=AIComplyConfig()).scan_path(source)
    assert any(f.rule_id == "EUAIA-ART13-001" for f in report.findings)


def test_reused_engine_reloads_configuration(tmp_path: Path, catalog: RuleCatalog):
    source = tmp_path / "app.py"
    source.write_text("ai_disclaimer = False\n")
    config = tmp_path / ".aicomply.yaml"
    config.write_text("ignore_rules: [EUAIA-ART13-001]")
    engine = ScanEngine(catalog)
    assert not engine.scan_path(source).findings
    config.unlink()
    assert engine.scan_path(source).findings


def write_custom_rule(directory: Path, catalog: RuleCatalog, **updates: object) -> str:
    directory.mkdir(exist_ok=True)
    rule = catalog.rules[0].model_dump(mode="json")
    rule.update(id="CUSTOM-GEN-001", patterns=[{"type": "regex", "target": "marker"}])
    rule.update(updates)
    (directory / "custom.yaml").write_text(yaml.safe_dump(rule))
    return str(rule["id"])


def test_custom_rules_extend_catalog_and_can_be_ignored(tmp_path: Path, catalog: RuleCatalog):
    custom_id = write_custom_rule(tmp_path / "rules", catalog)
    source = tmp_path / "app.py"
    source.write_text("marker = 1\n")
    config = AIComplyConfig(custom_rules_dir="rules")
    report = ScanEngine(catalog, config=config).scan_path(source)
    assert custom_id in report.active_rule_ids
    assert any(f.rule_id == custom_id for f in report.findings)
    ignored_config = config.model_copy(update={"ignore_rules": [custom_id]})
    ignored_report = ScanEngine(catalog, config=ignored_config).scan_path(source)
    assert custom_id not in ignored_report.active_rule_ids
    assert not ignored_report.findings
    assert report.rules_fingerprint != ignored_report.rules_fingerprint


def test_unknown_ignored_rule_fails(tmp_path: Path, catalog: RuleCatalog):
    config = AIComplyConfig(ignore_rules=["CUSTOM-GEN-999"])
    with pytest.raises(ValueError, match="unknown rule"):
        ScanEngine(catalog, config=config).scan_path(tmp_path)


@pytest.mark.parametrize("updates", [
    {"patterns": [{"type": "regex", "target": "["}]},
    {"patterns": [{"type": "regex"}]},
    {"patterns": [{"type": "data_flow"}]},
])
def test_invalid_custom_patterns_fail(tmp_path: Path, catalog: RuleCatalog, updates: dict):
    write_custom_rule(tmp_path, catalog, **updates)
    with pytest.raises(RuleLoadError):
        load_rules_from_dir(tmp_path)


def test_custom_rule_collision_fails(tmp_path: Path, catalog: RuleCatalog):
    write_custom_rule(tmp_path / "rules", catalog, id=catalog.rules[0].id)
    with pytest.raises(RuleLoadError):
        ScanEngine(catalog, config=AIComplyConfig(custom_rules_dir="rules")).scan_path(tmp_path)


@pytest.mark.parametrize("content", ["", "[]", "false", "patterns: [", "id: x\nid: y"])
def test_invalid_rule_files_fail(tmp_path: Path, content: str):
    (tmp_path / "rule.yaml").write_text(content)
    with pytest.raises(RuleLoadError):
        load_rules_from_dir(tmp_path)


def test_missing_or_empty_custom_rules_fail(tmp_path: Path, catalog: RuleCatalog):
    engine = ScanEngine(catalog, config=AIComplyConfig(custom_rules_dir="rules"))
    with pytest.raises((ValueError, OSError)):
        engine.scan_path(tmp_path)
    (tmp_path / "rules").mkdir()
    with pytest.raises(RuleLoadError):
        engine.scan_path(tmp_path)


@pytest.mark.parametrize("filename,content", [
    ("app.py", b"def unfinished("),
    ("app.pyw", b"def unfinished("),
    ("app.py", b"value = '\xff'"),
    ("data.txt", b"\xff"),
    ("data.txt", b"hello\x00world"),
    ("pyproject.toml", b"[project\n"),
    ("pyproject.toml", b'[project]\ndependencies = "fer"'),
    ("pyproject.toml", b"[project]\ndependencies = [123]"),
    ("pyproject.toml", b'[project]\ndependencies = ["@@"]'),
    ("pyproject.toml", b"[project.optional-dependencies]\ndev = 1"),
    ("pyproject.toml", b"tool = 1"),
    ("uv.lock", b"package = {}"),
    ("uv.lock", b"package = [1]"),
    ("uv.lock", b"[[package]]\nversion = '1'"),
    ("Pipfile", b"[packages"),
    ("Pipfile", b"packages = []"),
    ("Pipfile.lock", b"{invalid"),
    ("Pipfile.lock", b"[]"),
    ("Pipfile.lock", b'{"default": []}'),
    ("Pipfile.lock", b'{"default": {}, "default": {}}'),
    ("compose.yml", b"services: ["),
    ("compose.yml", b"services: []"),
    ("compose.yml", b"services:\n  app: null"),
    ("compose.yml", b"services:\n  app:\n    privileged: 'yes'"),
    ("compose.yml", b"services:\n  app:\n    ports: '8000:8000'"),
    ("compose.yml", b"services: {}\nservices: {}"),
    ("requirements.txt", b"!!!!invalid"),
    ("requirements.txt", b"fer=="),
    ("requirements.txt", b"fer==1,"),
    ("requirements.txt", b"fer==1; garbage"),
    ("requirements.txt", b"fer; python_version"),
    ("requirements.txt", b"fer; python_version < 3"),
    ("requirements-dev.txt", b"-r external.txt"),
])
def test_invalid_inputs_do_not_produce_clean_reports(
    tmp_path: Path, catalog: RuleCatalog, filename: str, content: bytes,
):
    (tmp_path / filename).write_bytes(content)
    with pytest.raises(ValueError, match="Unable to fully parse"):
        ScanEngine(catalog).scan_path(tmp_path)


@pytest.mark.parametrize("content", [
    b"services:\n  app:\n    image: test\n    user: nonroot\n",
    b"services:\n  app: &app\n    image: test\n    user: nonroot\n  other: *app\n",
    b"services:\n  app: &app\n    image: test\n  other:\n    <<: *app\n    image: override\n",
])
def test_valid_compose_aliases_remain_supported(tmp_path: Path, catalog: RuleCatalog, content: bytes):
    (tmp_path / "compose.yml").write_bytes(content)
    assert ScanEngine(catalog).scan_path(tmp_path).summary.total_files_scanned == 1


@pytest.mark.parametrize("requirement", [
    "example", "example>=1,<2", "example[foo,bar]~=1.0", "example (>=1.0)",
    "example; python_version < '3.13'", "example; os_name == 'posix' or sys_platform == 'linux'",
    "example @ https://example.com/example.whl",
])
def test_supported_requirements_remain_scannable(tmp_path: Path, catalog: RuleCatalog, requirement: str):
    (tmp_path / "requirements.txt").write_text(requirement)
    assert ScanEngine(catalog).scan_path(tmp_path).summary.total_files_scanned == 1


@pytest.mark.parametrize("kind", ["file", "directory", "dangling", "target", "ancestor"])
def test_symlinks_are_rejected(tmp_path: Path, catalog: RuleCatalog, kind: str):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text("secret = 1")
    if kind == "file":
        (root / "app.py").symlink_to(outside / "secret.py")
    elif kind == "dangling":
        (root / "app.py").symlink_to(outside / "missing.py")
    elif kind == "directory":
        (root / "linked").symlink_to(outside, target_is_directory=True)
    else:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
        root = tmp_path / "linked"
        if kind == "ancestor":
            root = root / "secret.py"
    with pytest.raises((ValueError, OSError)):
        ScanEngine(catalog).scan_path(root)


@pytest.mark.parametrize("name", [".aicomply.yaml", "rules"])
def test_policy_symlinks_are_rejected(tmp_path: Path, catalog: RuleCatalog, name: str):
    (tmp_path / name).symlink_to(tmp_path / "missing")
    engine = ScanEngine(catalog, config=AIComplyConfig(custom_rules_dir="rules")) if name == "rules" else ScanEngine(catalog)
    with pytest.raises((ValueError, OSError)):
        engine.scan_path(tmp_path)


def test_symbolic_rule_files_are_rejected(tmp_path: Path, catalog: RuleCatalog):
    rules = tmp_path / "rules"
    write_custom_rule(rules, catalog)
    (rules / "link.yaml").symlink_to(rules / "custom.yaml")
    with pytest.raises(RuleLoadError):
        load_rules_from_dir(rules)


@pytest.mark.parametrize("kind", ["config", "rules"])
def test_oversized_policy_files_fail(tmp_path: Path, catalog: RuleCatalog, kind: str):
    if kind == "config":
        (tmp_path / ".aicomply.yaml").write_bytes(b"#" * (1024 * 1024 + 1))
        with pytest.raises(ValueError):
            load_project_config(tmp_path)
    else:
        (tmp_path / "rule.yaml").write_bytes(b"#" * (1024 * 1024 + 1))
        with pytest.raises(RuleLoadError):
            load_rules_from_dir(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="FIFO requires POSIX")
def test_special_files_are_rejected_without_blocking(tmp_path: Path, catalog: RuleCatalog):
    fifo = tmp_path / "queue.txt"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        ScanEngine(catalog).scan_path(tmp_path)
    with pytest.raises(ValueError):
        ScanEngine(catalog).scan_path(fifo)
    with pytest.raises(ValueError):
        read_regular_file(fifo, 100)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_unreadable_input_fails(tmp_path: Path, catalog: RuleCatalog):
    source = tmp_path / "app.py"
    source.write_text("x = 1")
    source.chmod(0)
    try:
        with pytest.raises(PermissionError):
            ScanEngine(catalog).scan_path(tmp_path)
    finally:
        source.chmod(0o600)


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory permissions")
def test_unreadable_directory_fails(tmp_path: Path, catalog: RuleCatalog):
    directory = tmp_path / "source"
    directory.mkdir()
    directory.chmod(0)
    try:
        with pytest.raises(PermissionError):
            ScanEngine(catalog).scan_path(tmp_path)
    finally:
        directory.chmod(0o700)


def test_size_boundaries(tmp_path: Path, catalog: RuleCatalog, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(engine_module, "MAX_SOURCE_BYTES", 6)
    source = tmp_path / "app.py"
    source.write_bytes(b"x = 1\n")
    assert ScanEngine(catalog).scan_path(tmp_path).summary.total_files_scanned == 1
    source.write_bytes(b"x = 11\n")
    with pytest.raises(ValueError, match="exceeds"):
        ScanEngine(catalog).scan_path(tmp_path)


def test_total_size_and_entry_limits(tmp_path: Path, catalog: RuleCatalog, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("x = 1\n")
    monkeypatch.setattr(engine_module, "MAX_SCAN_BYTES", 10)
    with pytest.raises(ValueError, match="exceeds"):
        ScanEngine(catalog).scan_path(tmp_path)
    monkeypatch.setattr(engine_module, "MAX_SCAN_BYTES", 100)
    monkeypatch.setattr(engine_module, "MAX_SCAN_ENTRIES", 2)
    with pytest.raises(ValueError, match="entries"):
        ScanEngine(catalog).scan_path(tmp_path)


def test_root_named_build_is_scanned_and_exclusions_disclosed(tmp_path: Path, catalog: RuleCatalog):
    root = tmp_path / "build"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "readme.md").write_text("text")
    (root / ".venv").symlink_to(tmp_path / "missing")
    (root / "tests").mkdir()
    (root / "tests" / "bad.py").write_text("invalid syntax")
    report = ScanEngine(catalog).scan_path(root)
    assert [entry.path for entry in report.source_manifest] == ["app.py"]
    assert report.exclusions == {
        ".venv": "ignored_directory",
        "readme.md": "unsupported_or_generated_file",
        "tests": "exclude_paths",
    }


def test_env_and_pyw_files_are_included(tmp_path: Path, catalog: RuleCatalog):
    for name in [".env", ".env.local", "app.pyw"]:
        (tmp_path / name).write_text("x = 1")
    report = ScanEngine(catalog).scan_path(tmp_path)
    assert report.summary.total_files_scanned == 3


def test_scan_id_remains_finding_hash_but_source_provenance_changes(tmp_path: Path, catalog: RuleCatalog):
    source = tmp_path / "app.py"
    source.write_bytes(b"x = 1\r\n")
    engine = ScanEngine(catalog)
    first = engine.scan_path(tmp_path)
    second = engine.scan_path(tmp_path)
    assert first.source_manifest == second.source_manifest
    assert first.source_manifest_hash == second.source_manifest_hash
    assert first.source_manifest[0].sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert first.source_manifest[0].size_bytes == 7
    payload = json.dumps([entry.model_dump() for entry in first.source_manifest], sort_keys=True, separators=(",", ":"))
    assert first.source_manifest_hash == hashlib.sha256(payload.encode()).hexdigest()
    source.write_bytes(b"x = 1\n")
    third = engine.scan_path(tmp_path)
    assert first.scan_id == third.scan_id == compute_scan_hash([])
    assert first.source_manifest_hash != third.source_manifest_hash
    assert first.rules_fingerprint == third.rules_fingerprint


def test_policy_fingerprints_change_independently_of_findings(tmp_path: Path, catalog: RuleCatalog):
    (tmp_path / "app.py").write_text("x = 1")
    first = ScanEngine(catalog).scan_path(tmp_path)
    config = AIComplyConfig(exclude_paths=[])
    second = ScanEngine(catalog, config=config).scan_path(tmp_path)
    third = ScanEngine(catalog, target_articles={"5"}).scan_path(tmp_path)
    assert first.scan_id == second.scan_id == third.scan_id
    assert first.config_fingerprint != second.config_fingerprint
    assert first.rules_fingerprint == second.rules_fingerprint
    assert first.rules_fingerprint != third.rules_fingerprint
    assert third.effective_config["target_articles"] == ["5"]


def test_same_relative_sources_have_same_provenance(tmp_path: Path, catalog: RuleCatalog):
    reports = []
    for name in ["first", "second"]:
        root = tmp_path / name
        root.mkdir()
        (root / "z.py").write_text("z = 0")
        (root / "a.py").write_text("a = 0")
        reports.append(ScanEngine(catalog).scan_path(root))
    assert [entry.path for entry in reports[0].source_manifest] == ["a.py", "z.py"]
    assert reports[0].source_manifest_hash == reports[1].source_manifest_hash
    assert reports[0].config_fingerprint == reports[1].config_fingerprint


def test_downstream_scanners_share_captured_bytes(
    tmp_path: Path, catalog: RuleCatalog, monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "app.py"
    original = b"ai_disclaimer = False\n"
    source.write_bytes(original)
    original_scan = PythonASTScanner.scan_file

    def mutate_original(self: PythonASTScanner, file_path: Path, base_path: Path | None = None):
        assert file_path != source
        source.write_text("ai_disclaimer = True\n")
        return original_scan(self, file_path, base_path)

    monkeypatch.setattr(PythonASTScanner, "scan_file", mutate_original)
    report = ScanEngine(catalog).scan_path(tmp_path)
    assert report.source_manifest[0].sha256 == hashlib.sha256(original).hexdigest()
    assert any(f.rule_id == "EUAIA-ART13-001" for f in report.findings)
    assert all(f.location.file_path == "app.py" for f in report.findings)


def test_client_source_is_not_executed(tmp_path: Path, catalog: RuleCatalog):
    marker = tmp_path / "executed"
    source = tmp_path / "app.py"
    source.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    ScanEngine(catalog).scan_path(source)
    assert not marker.exists()


def test_rule_fingerprint_covers_content_not_only_ids(tmp_path: Path, catalog: RuleCatalog):
    source = tmp_path / "app.py"
    source.write_text("x = 1")
    first = ScanEngine(catalog).scan_path(source)
    rules = catalog.rules
    rules[0] = rules[0].model_copy(update={"description": "A different validated rule description"})
    second = ScanEngine(RuleCatalog(rules)).scan_path(source)
    assert first.active_rule_ids == second.active_rule_ids
    assert first.scan_id == second.scan_id
    assert first.rules_fingerprint != second.rules_fingerprint


def test_report_defaults_and_signed_provenance(tmp_path: Path, catalog: RuleCatalog):
    source = tmp_path / "app.py"
    source.write_text("x = 1")
    report = ScanEngine(catalog).scan_path(source)
    legacy = ScanReport.model_validate({
        key: value for key, value in report.model_dump().items()
        if key in {"scan_id", "timestamp", "target_path", "summary", "findings"}
    })
    assert legacy.source_manifest == []
    assert legacy.rules_fingerprint is None
    private_key, public_key, _ = generate_keypair(tmp_path / "keys")
    bundle = sign_scan_report(report, private_key)
    assert verify_evidence_bundle(bundle, public_key)[0]
    tampered = bundle.model_dump(mode="json")
    tampered["report"]["source_manifest"][0]["sha256"] = "0" * 64
    assert not verify_evidence_bundle(tampered, public_key)[0]


@pytest.mark.parametrize("filename,content", [
    ("app.py", "def broken("),
    (".aicomply.yaml", "unknown: true"),
    ("pyproject.toml", "[project"),
])
def test_cli_returns_two_for_incomplete_scan(tmp_path: Path, filename: str, content: str):
    (tmp_path / filename).write_text(content)
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2
