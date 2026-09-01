"""
AIComply - CLI End-to-End Integration Tests
"""

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner
from aicomply.cli import app

runner = CliRunner()


def test_cli_scan_vulnerable_project_exit_code():
    vulnerable_path = Path(__file__).parents[1] / "fixtures" / "vulnerable_project"
    result = runner.invoke(app, ["scan", str(vulnerable_path)])
    
    # Debe fallar con código 1 al contener hallazgos
    assert result.exit_code == 1
    assert "PROHIBIDO (Art. 5)" in result.stdout or "EUAIA-ART05-001" in result.stdout


def test_cli_scan_compliant_project_exit_code():
    compliant_path = Path(__file__).parents[1] / "fixtures" / "compliant_project"
    result = runner.invoke(app, ["scan", str(compliant_path)])
    
    # Debe salir limpio con código 0
    assert result.exit_code == 0
    assert "CONFORMIDAD TÉCNICA VALIDADA" in result.stdout


def test_cli_scan_invalid_path_exit_code():
    result = runner.invoke(app, ["scan", "non_existent_directory_xyz"])
    # Código 2 por error de ruta
    assert result.exit_code == 2


def test_cli_scan_json_format():
    vulnerable_path = Path(__file__).parents[1] / "fixtures" / "vulnerable_project" / "app.py"
    result = runner.invoke(app, ["scan", str(vulnerable_path), "--format", "json"])
    
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "scan_id" in payload
    assert "findings" in payload
    assert len(payload["findings"]) >= 4


def test_cli_scan_sarif_format(tmp_path: Path):
    vulnerable_path = Path(__file__).parents[1] / "fixtures" / "vulnerable_project" / "app.py"
    output_sarif = tmp_path / "report.sarif"
    
    result = runner.invoke(app, [
        "scan", str(vulnerable_path),
        "--format", "sarif",
        "--output", str(output_sarif)
    ])
    
    assert result.exit_code == 1
    assert output_sarif.exists()
    
    sarif_data = json.loads(output_sarif.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 4


def test_cli_determinism_sha256():
    vulnerable_path = Path(__file__).parents[1] / "fixtures" / "vulnerable_project" / "app.py"
    
    res1 = runner.invoke(app, ["scan", str(vulnerable_path), "--format", "json"])
    res2 = runner.invoke(app, ["scan", str(vulnerable_path), "--format", "json"])
    
    data1 = json.loads(res1.stdout)
    data2 = json.loads(res2.stdout)
    
    # Mismo código = Mismo hash de escaneo exactamente
    assert data1["scan_id"] == data2["scan_id"]
    assert len(data1["findings"]) == len(data2["findings"])


def test_cli_docgen_command(tmp_path: Path):
    vulnerable_path = Path(__file__).parents[1] / "fixtures" / "vulnerable_project"
    output_doc = tmp_path / "ANNEX_IV.md"
    
    result = runner.invoke(app, [
        "docgen", str(vulnerable_path),
        "--name", "HR-Screening-System",
        "--version", "1.0.0",
        "--output", str(output_doc)
    ])
    
    assert result.exit_code == 0
    assert output_doc.exists()
    content = output_doc.read_text(encoding="utf-8")
    assert "HR-Screening-System" in content
    assert "SECCIÓN 1 — Identificación y Descripción General del Sistema" in content


def test_cli_keygen_command(tmp_path: Path):
    pki_dir = tmp_path / "pki"
    result = runner.invoke(app, ["keygen", "--out-dir", str(pki_dir), "--name", "secops"])
    
    assert result.exit_code == 0
    assert (pki_dir / "secops.pem").exists()
    assert (pki_dir / "secops.pub").exists()
    assert "SHA256:" in result.stdout


def test_cli_scan_with_sign_and_verify(tmp_path: Path):
    pki_dir = tmp_path / "pki"
    runner.invoke(app, ["keygen", "--out-dir", str(pki_dir), "--name", "testkey"])
    priv_key = pki_dir / "testkey.pem"
    pub_key = pki_dir / "testkey.pub"

    compliant_path = Path(__file__).parents[1] / "fixtures" / "compliant_project"
    evidence_output = tmp_path / "compliant.evidence.json"

    # Escanear y firmar
    scan_res = runner.invoke(app, [
        "scan", str(compliant_path),
        "--format", "json",
        "--sign",
        "--key", str(priv_key),
        "--signer-id", "auditor@compliance.eu",
        "--output", str(evidence_output)
    ])

    assert scan_res.exit_code == 0
    assert evidence_output.exists()

    evidence_data = json.loads(evidence_output.read_text(encoding="utf-8"))
    assert evidence_data["version"] == "2.0.0"
    assert evidence_data["algorithm"] == "Ed25519"
    assert evidence_data["signer_identity"] == "auditor@compliance.eu"

    # Verificar reporte firmado
    verify_res = runner.invoke(app, [
        "verify", str(evidence_output),
        "--public-key", str(pub_key)
    ])

    assert verify_res.exit_code == 0
    assert "VERIFICACIÓN EXITOSA" in verify_res.stdout


def test_cli_verify_tampered_fails(tmp_path: Path):
    pki_dir = tmp_path / "pki"
    runner.invoke(app, ["keygen", "--out-dir", str(pki_dir), "--name", "testkey"])
    priv_key = pki_dir / "testkey.pem"
    pub_key = pki_dir / "testkey.pub"

    compliant_path = Path(__file__).parents[1] / "fixtures" / "compliant_project"
    evidence_output = tmp_path / "tampered.evidence.json"

    runner.invoke(app, [
        "scan", str(compliant_path),
        "--format", "json",
        "--sign",
        "--key", str(priv_key),
        "--output", str(evidence_output)
    ])

    # Manipular el archivo
    data = json.loads(evidence_output.read_text(encoding="utf-8"))
    data["report"]["target_path"] = "manipulated_target_path"
    evidence_output.write_text(json.dumps(data), encoding="utf-8")

    verify_res = runner.invoke(app, [
        "verify", str(evidence_output),
        "--public-key", str(pub_key)
    ])

    assert verify_res.exit_code == 1
    assert "VERIFICACIÓN FALLIDA" in verify_res.stdout