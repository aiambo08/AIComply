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


def test_rule_hardcoded_ai_secret(engine: ScanEngine, tmp_path: Path):
    # Vulnerable: clave estática > 15 caracteres
    vulnerable_code = """
import openai
client = openai.OpenAI(api_key="sk-proj-9876543210abcdefghijklmnop")
"""
    vuln_file = tmp_path / "vuln_secret.py"
    vuln_file.write_text(vulnerable_code, encoding="utf-8")

    report = engine.scan_path(vuln_file)
    rule_ids = [f.rule_id for f in report.findings]
    assert "EUAIA-ART15-002" in rule_ids

    # Seguro: lectura desde variable de entorno
    safe_code = """
import os
import openai
client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
"""
    safe_file = tmp_path / "safe_secret.py"
    safe_file.write_text(safe_code, encoding="utf-8")

    report_safe = engine.scan_path(safe_file)
    safe_rule_ids = [f.rule_id for f in report_safe.findings]
    assert "EUAIA-ART15-002" not in safe_rule_ids


def test_rule_unsanitized_prompt_injection(engine: ScanEngine, tmp_path: Path):
    # Vulnerable: f-string directo con raw_input
    vulnerable_code = """
prompt = f"Resume el siguiente texto del usuario: {user_raw_input}"
res = client.completions.create(prompt=prompt)
"""
    vuln_file = tmp_path / "vuln_prompt.py"
    vuln_file.write_text(vulnerable_code, encoding="utf-8")

    report = engine.scan_path(vuln_file)
    rule_ids = [f.rule_id for f in report.findings]
    assert "EUAIA-ART15-003" in rule_ids


def test_rule_unmoderated_output_passthrough(engine: ScanEngine, tmp_path: Path):
    # Vulnerable: return directo sin moderación
    vulnerable_code = """
def query_model(q):
    res = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": q}])
    return res.choices[0].message.content
"""
    vuln_file = tmp_path / "vuln_output.py"
    vuln_file.write_text(vulnerable_code, encoding="utf-8")

    report = engine.scan_path(vuln_file)
    rule_ids = [f.rule_id for f in report.findings]
    assert "EUAIA-ART50-002" in rule_ids


def test_rule_pii_payload_interpolation(engine: ScanEngine, tmp_path: Path):
    # Vulnerable: inclusión de DNI y nombre de usuario en prompt sin anonimizar
    vulnerable_code = """
prompt = f"Analiza la solvencia del cliente {user_name} con DNI {dni}"
res = client.chat.completions.create(prompt=prompt)
"""
    vuln_file = tmp_path / "vuln_pii.py"
    vuln_file.write_text(vulnerable_code, encoding="utf-8")

    report = engine.scan_path(vuln_file)
    rule_ids = [f.rule_id for f in report.findings]
    assert "GDPR-ART05-002" in rule_ids


def test_rule_plaintext_logging_of_payload(engine: ScanEngine, tmp_path: Path):
    # Vulnerable: logging del objeto o respuesta completa
    vulnerable_code = """
import logging
res = client.chat.completions.create(model="gpt-4o", messages=[])
logging.info(f"Generated raw output: {res}")
"""
    vuln_file = tmp_path / "vuln_logging.py"
    vuln_file.write_text(vulnerable_code, encoding="utf-8")

    report = engine.scan_path(vuln_file)
    rule_ids = [f.rule_id for f in report.findings]
    assert "GDPR-ART32-001" in rule_ids
