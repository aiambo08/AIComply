from pathlib import Path
import pytest
from aicomply.cli import get_default_rules_dir
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.engine import ScanEngine


@pytest.fixture
def engine() -> ScanEngine:
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    return ScanEngine(catalog=catalog)


def test_detect_hardcoded_api_key(engine: ScanEngine, tmp_path: Path):
    vulnerable_file = tmp_path / "leaked_secret.py"
    vulnerable_file.write_text("OPENAI_API_KEY = 'sk-1234567890abcdef1234567890abcdef'\n", encoding="utf-8")

    report = engine.scan_path(vulnerable_file)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GDPR-ART32-001" in rule_ids


def test_detect_insecure_tls_bypass(engine: ScanEngine, tmp_path: Path):
    vulnerable_file = tmp_path / "insecure_conn.py"
    vulnerable_file.write_text("import requests\nresp = requests.get('https://api.model.internal', verify=False)\n", encoding="utf-8")

    report = engine.scan_path(vulnerable_file)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GDPR-ART32-002" in rule_ids


def test_detect_spanish_dni_leak(engine: ScanEngine, tmp_path: Path):
    vulnerable_file = tmp_path / "pii_leak.py"
    vulnerable_file.write_text("user_prompt = 'Analiza el historial del cliente con DNI 12345678Z'\n", encoding="utf-8")

    report = engine.scan_path(vulnerable_file)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GDPR-ART05-002" in rule_ids


def test_detect_credit_card_pan_leak(engine: ScanEngine, tmp_path: Path):
    vulnerable_file = tmp_path / "pan_leak.py"
    vulnerable_file.write_text("prompt = 'Validar tarjeta 4532015012345678 para pago'\n", encoding="utf-8")

    report = engine.scan_path(vulnerable_file)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GDPR-ART05-003" in rule_ids


def test_detect_unencrypted_http_endpoint(engine: ScanEngine, tmp_path: Path):
    vulnerable_file = tmp_path / "insecure_http.py"
    vulnerable_file.write_text("base_url = 'http://api.remote-llm.org/v1'\n", encoding="utf-8")

    report = engine.scan_path(vulnerable_file)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GDPR-ART32-003" in rule_ids