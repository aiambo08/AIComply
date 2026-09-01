"""
AIComply - Unit Tests for Asymmetric Cryptographic Signing (Ed25519)
"""

from pathlib import Path
import pytest
from aicomply.evidence.signer import (
    generate_keypair,
    sign_scan_report,
    verify_evidence_bundle,
)
from aicomply.schemas import (
    CodeLocation,
    Confidence,
    Finding,
    RiskTier,
    ScanReport,
    ScanSummary,
    Severity,
)


@pytest.fixture
def sample_report() -> ScanReport:
    loc = CodeLocation(file_path="src/agent.py", start_line=10, end_line=10, start_col=0, end_col=20)
    finding = Finding(
        id="a1b2c3d4e5f600112233445566778899aabbccddeeff00112233445566778899",
        rule_id="EUAIA-ART14-002",
        article="Art. 14(4)(a)",
        severity=Severity.CRITICAL,
        risk_tier=RiskTier.HIGH_RISK,
        title="Unvalidated Tool Execution",
        message="LLM output reaches os.system() directly",
        location=loc,
        code_snippet="os.system(cmd)",
        remediation="Validate output with schema",
        max_fine="35M€ o 7%",
        confidence=Confidence.HIGH,
    )
    summary = ScanSummary(
        total_files_scanned=1,
        total_lines_scanned=25,
        total_findings=1,
        findings_by_tier={RiskTier.HIGH_RISK: 1},
        findings_by_severity={Severity.CRITICAL: 1},
        rules_loaded=10,
        execution_time_ms=12.5,
    )
    return ScanReport(
        scan_id="99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
        timestamp="2026-09-01T10:00:00Z",
        target_path="src/",
        summary=summary,
        findings=[finding],
    )


def test_generate_keypair(tmp_path: Path):
    priv_path, pub_path, fingerprint = generate_keypair(tmp_path, "test_signer")

    assert priv_path.exists()
    assert pub_path.exists()
    assert priv_path.read_text().startswith("-----BEGIN PRIVATE KEY-----")
    assert pub_path.read_text().startswith("-----BEGIN PUBLIC KEY-----")
    assert fingerprint.startswith("SHA256:")


def test_sign_and_verify_valid_bundle(tmp_path: Path, sample_report: ScanReport):
    priv_path, pub_path, _ = generate_keypair(tmp_path, "ci_key")

    # Modificar scan_id en el sample_report para que coincida con el hash real de los hallazgos
    from aicomply.evidence.hasher import compute_scan_hash
    real_hash = compute_scan_hash(sample_report.findings)
    sample_report = sample_report.model_copy(update={"scan_id": real_hash})

    bundle = sign_scan_report(sample_report, priv_path, signer_identity="ci-runner@enterprise.com")

    assert bundle.version == "2.0.0"
    assert bundle.algorithm == "Ed25519"
    assert bundle.signer_identity == "ci-runner@enterprise.com"
    assert len(bundle.signature) > 30

    # Guardar en archivo y verificar
    bundle_file = tmp_path / "report.evidence.json"
    bundle_file.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")

    is_valid, msg = verify_evidence_bundle(bundle_file, pub_path)
    assert is_valid is True
    assert "válida" in msg.lower()


def test_verify_tampered_findings_fails(tmp_path: Path, sample_report: ScanReport):
    from aicomply.evidence.hasher import compute_scan_hash
    sample_report = sample_report.model_copy(update={"scan_id": compute_scan_hash(sample_report.findings)})

    priv_path, pub_path, _ = generate_keypair(tmp_path, "ci_key")
    bundle = sign_scan_report(sample_report, priv_path)

    bundle_dict = bundle.model_dump()
    # Manipular el hallazgo
    bundle_dict["report"]["findings"][0]["title"] = "Tampered Title"

    is_valid, msg = verify_evidence_bundle(bundle_dict, pub_path)
    assert is_valid is False


def test_verify_wrong_public_key_fails(tmp_path: Path, sample_report: ScanReport):
    from aicomply.evidence.hasher import compute_scan_hash
    sample_report = sample_report.model_copy(update={"scan_id": compute_scan_hash(sample_report.findings)})

    priv_1, pub_1, _ = generate_keypair(tmp_path, "key_1")
    priv_2, pub_2, _ = generate_keypair(tmp_path, "key_2")

    bundle = sign_scan_report(sample_report, priv_1)

    # Intentar verificar con la clave pública de key_2
    is_valid, msg = verify_evidence_bundle(bundle, pub_2)
    assert is_valid is False
    assert "Discrepancia en la huella" in msg
