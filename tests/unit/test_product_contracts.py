"""Cross-layer regression coverage for evidence and contextual review contracts."""

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from aicomply.classifier.assess import SystemContext, assess_context
from aicomply.cli import app, write_report
from aicomply.evidence.signer import generate_keypair, sign_scan_report, verify_evidence_bundle
from aicomply.generator.annex_iv import AnnexIVGenerator
from aicomply.reporter.markdown_report import display_text, generate_markdown_report, safe_text
from aicomply.reporter.sarif_reporter import generate_sarif_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine
from aicomply.schemas import RiskTier
from tests.unit.test_ui_security import Console, console


@pytest.fixture
def engine() -> ScanEngine:
    return ScanEngine(load_builtin_rules())


def test_unknown_context_never_defaults_to_minimal() -> None:
    result = assess_context(SystemContext())
    assert result.risk_tier is None
    assert result.status == "requires_review"
    assert {"role", "intended_purpose", "eu_scope", "is_ai"} <= set(result.missing_context)
    assert result.sources and result.reviewed_on


@pytest.mark.parametrize("value", ["false", "true", 0, 1, {}, []])
def test_context_does_not_coerce_boolean_answers(value: object) -> None:
    with pytest.raises(ValidationError):
        SystemContext.model_validate({"is_ai": value})


@pytest.mark.parametrize("profile", [True, None])
def test_annex_iii_exception_requires_explicit_no_profiling(profile: bool | None) -> None:
    result = assess_context(SystemContext(
        is_ai=True, eu_scope=True, annex_iii_use=True,
        profiling=profile, narrow_exception=True,
    ))
    assert result.risk_tier == RiskTier.HIGH_RISK
    if profile is None:
        assert "profiling" in result.missing_context


def test_product_risk_requires_both_annex_i_conditions() -> None:
    result = assess_context(SystemContext(
        is_ai=True, eu_scope=True, annex_i_product=True, third_party_conformity=False,
    ))
    assert result.risk_tier != RiskTier.HIGH_RISK
    incomplete = assess_context(SystemContext(annex_i_product=True))
    assert "third_party_conformity" in incomplete.missing_context


def test_overlapping_regimes_preserve_role_specific_duties() -> None:
    result = assess_context(SystemContext(
        is_ai=True, eu_scope=True, role="deployer", annex_iii_use=True,
        profiling=True, transparency=True, gpai_provider=True,
        personal_data=True, solely_automated_significant_decision=True,
    ))
    assert {"Art. 26", "Art. 50", "Arts. 51–55 (GPAI)", "RGPD Art. 22"} <= set(result.applicable_articles)
    assert "Arts. 16–21" not in result.applicable_articles


def test_gpai_model_and_gdpr_review_survive_system_scope_exclusion() -> None:
    result = assess_context(SystemContext(is_ai=False, gpai_provider=True, personal_data=True))
    assert "Arts. 51–55 (GPAI)" in result.applicable_articles
    assert "solely_automated_significant_decision" in result.missing_context
    assert result.risk_tier is None


def test_annex_uses_captured_imports_after_source_deletion(tmp_path: Path, engine: ScanEngine) -> None:
    source = tmp_path / "app.py"
    source.write_text("import openai\nimport torch\n", encoding="utf-8")
    report = engine.scan_path(source)
    source.unlink()
    dossier = AnnexIVGenerator(report, system_name="<script>alert(1)</script>").generate_markdown_dossier()
    assert dossier.count("## SECCIÓN ") == 9
    assert "OpenAI SDK" in dossier and "PyTorch" in dossier
    assert "PENDIENTE" in dossier and "Conformidad Plena" not in dossier
    assert "<script>" not in dossier


def test_empty_scan_has_no_legal_conclusion_in_all_outputs(tmp_path: Path, engine: ScanEngine) -> None:
    (tmp_path / "app.py").write_text("answer = 42\n", encoding="utf-8")
    report = engine.scan_path(tmp_path)
    assert report.legal_assessment == "not_assessed"
    assert "No acredita conformidad legal" in generate_markdown_report(report)
    sarif = json.loads(generate_sarif_report(report))["runs"][0]
    assert sarif["properties"]["legalAssessment"] == "not_assessed"
    assert sarif["properties"]["sourceManifestHash"] == report.source_manifest_hash
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "SIN HALLAZGOS EN EL ALCANCE ANALIZADO" in result.stdout
    assert "CONFORMIDAD TÉCNICA VALIDADA" not in result.stdout


@pytest.mark.parametrize("module", ["transfer", "features", "prefer", "transformers"])
def test_import_matching_does_not_confuse_fer_substrings(
    tmp_path: Path, engine: ScanEngine, module: str,
) -> None:
    source = tmp_path / "app.py"
    source.write_text(f"import {module}\n", encoding="utf-8")
    assert not [finding for finding in engine.scan_path(source).findings
                if finding.rule_id == "EUAIA-ART05-001"]


def test_logging_rule_requires_complete_api_target(tmp_path: Path, engine: ScanEngine) -> None:
    source = tmp_path / "app.py"
    source.write_text("builder.create_node()\nchat_app.start()\n", encoding="utf-8")
    assert not [finding for finding in engine.scan_path(source).findings
                if finding.rule_id == "EUAIA-ART12-001"]
    source.write_text("client.chat.completions.create()\n", encoding="utf-8")
    assert any(finding.rule_id == "EUAIA-ART12-001" for finding in engine.scan_path(source).findings)


def test_risk_threshold_and_cli_override_are_recorded(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("execute_autonomous_action()\n", encoding="utf-8")
    runner = CliRunner()
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 1
    result = runner.invoke(app, ["scan", str(tmp_path), "--enforce-risk-tier", "high_risk", "--format", "json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["effective_config"]["enforce_risk_tier"] == "high_risk"
    (tmp_path / ".aicomply.yaml").write_text("enforce_risk_tier: minimal_risk\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 1
    assert runner.invoke(app, ["scan", str(tmp_path), "--enforce-risk-tier", "high_risk"]).exit_code == 0


@pytest.mark.parametrize("format_name", ["terminal", "markdown", "sarif"])
def test_signing_never_silently_discards_signature(tmp_path: Path, format_name: str) -> None:
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--sign", "--format", format_name])
    assert result.exit_code == 2


def test_invalid_config_prevents_docgen_artifact(tmp_path: Path) -> None:
    (tmp_path / ".aicomply.yaml").write_text("unknown: true\n", encoding="utf-8")
    output = tmp_path / "draft.md"
    result = CliRunner().invoke(app, ["docgen", str(tmp_path), "--output", str(output)])
    assert result.exit_code == 2
    assert not output.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_report_output_refuses_symlinks_and_restricts_permissions(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("preserve", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        write_report(link, "replacement")
    assert target.read_text() == "preserve"
    write_report(target, "replacement")
    assert target.stat().st_mode & 0o777 == 0o600


def test_markdown_escapes_untrusted_html_and_table_delimiters() -> None:
    value = safe_text("<img src=x>|[click](url)\n# forged\x1b")
    assert "<img" not in value and "|" not in value and "\x1b" not in value
    assert "\n" not in value and "\\[click\\]" in value


def test_display_keeps_control_characters_visible_without_interpreting_them() -> None:
    value = display_text("file\u202ecod.exe\x1b[2J\x7f")
    assert "\u202e" not in value and "\x1b" not in value and "\x7f" not in value
    assert "\\u202e" in value and "\\u001b" in value and "\\u007f" in value


@pytest.mark.skipif(os.name != "posix", reason="POSIX console")
def test_console_report_records_snapshot_exclusions_and_limits(console: Console) -> None:
    (console.root / "image.svg").write_text("<svg/>", encoding="utf-8")
    (console.root / "node_modules").mkdir()
    status, _, body = console.request("/api/scan", b"{}")
    assert status == 200
    report = json.loads(body)
    assert {"image.svg", "node_modules"} <= set(report["exclusions"])
    assert report["effective_config"]["console_limits"]["max_source_bytes"] == 2 * 1024 * 1024


def test_signatures_cover_source_provenance(tmp_path: Path, engine: ScanEngine) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.py").write_text("import openai\n", encoding="utf-8")
    private, public, _ = generate_keypair(tmp_path / "keys")
    bundle = sign_scan_report(engine.scan_path(root), private)
    assert verify_evidence_bundle(bundle.model_dump_json(), public)[0]
    raw = bundle.model_dump()
    raw["report"]["source_imports"] = {}
    assert not verify_evidence_bundle(raw, public)[0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX console")
def test_console_uses_shared_contextual_assessment(console: Console) -> None:
    payload = {"context": {"personal_data": True, "solely_automated_significant_decision": True}}
    status, _, body = console.request("/api/assess", json.dumps(payload).encode())
    result = json.loads(body)
    assert status == 200
    assert "RGPD Art. 22" in result["articles"]
    assert result["tier"] == "unknown" and result["requires_review"]
    assert result["sources"] and result["missing_context"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX console")
@pytest.mark.parametrize("mutation", ["duplicate", "extra", "omitted", "valid"])
def test_console_verifies_original_raw_evidence(
    console: Console, tmp_path: Path, engine: ScanEngine, mutation: str,
) -> None:
    private, public, _ = generate_keypair(tmp_path / "keys")
    bundle = sign_scan_report(engine.scan_path(console.root), private)
    raw = bundle.model_dump_json()
    if mutation == "duplicate":
        raw = raw.replace('"algorithm":', '"algorithm":"Ed25519","algorithm":', 1)
    elif mutation == "extra":
        raw = raw.replace('"report":{', '"report":{"unexpected":"field",', 1)
    elif mutation == "omitted":
        raw = raw.replace('"legal_assessment":"not_assessed",', "", 1)
    payload = {"bundle": raw, "public_key": public.read_text(encoding="utf-8")}
    status, _, body = console.request("/api/verify", json.dumps(payload).encode())
    assert status == 200
    result = json.loads(body)
    assert result["valid"] is (mutation == "valid")
    if mutation != "valid":
        assert result["scan_id"] is None
