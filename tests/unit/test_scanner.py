from pathlib import Path
import pytest
from aicomply.cli import get_default_rules_dir
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.engine import ScanEngine
from aicomply.schemas import RiskTier, Severity


@pytest.fixture
def engine() -> ScanEngine:
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    return ScanEngine(catalog=catalog)


def test_scan_non_compliant_fixture(engine: ScanEngine):
    fixture_path = Path(__file__).parents[1] / "fixtures" / "non_compliant_app.py"
    report = engine.scan_path(fixture_path)
    
    assert report.summary.total_findings >= 2
    rule_ids = {f.rule_id for f in report.findings}
    
    # Comprobar detección de Art. 5 (Emociones) y Art. 12 (Sin logging)
    assert "EUAIA-ART05-001" in rule_ids
    assert "EUAIA-ART12-001" in rule_ids


def test_scan_compliant_fixture(engine: ScanEngine):
    fixture_path = Path(__file__).parents[1] / "fixtures" / "compliant_pipeline.py"
    report = engine.scan_path(fixture_path)
    
    # No debe disparar EUAIA-ART12-001 porque logging está importado
    rule_ids = {f.rule_id for f in report.findings}
    assert "EUAIA-ART12-001" not in rule_ids


def test_scan_no_duplicate_findings(engine: ScanEngine):
    fixture_path = Path(__file__).parents[1] / "fixtures" / "non_compliant_app.py"
    report = engine.scan_path(fixture_path)
    
    finding_ids = [f.id for f in report.findings]
    assert len(finding_ids) == len(set(finding_ids)), "No debe haber IDs de hallazgos duplicados"


def test_ast_assignment_and_variable_alias(tmp_path: Path):
    from aicomply.schemas import Confidence, PatternType, RiskTier, Rule, RulePattern, Severity
    from aicomply.scanner.ast_parser import PythonASTScanner

    rule_assignment = Rule(
        id="EUAIA-ART13-002",
        article="Art. 13",
        title="Disclaimer deshabilitado por asignación AST",
        severity=Severity.HIGH,
        risk_tier=RiskTier.LIMITED_RISK,
        description="Detección de asignación ai_disclaimer = False mediante AST",
        remediation="Habilitar ai_disclaimer = True",
        max_fine="15M€",
        confidence=Confidence.HIGH,
        patterns=[
            RulePattern(type=PatternType.AST_ASSIGNMENT, target="ai_disclaimer", match_args={"value": False})
        ]
    )

    test_file = tmp_path / "sample_assignment.py"
    test_file.write_text("ai_disclaimer = False\n", encoding="utf-8")

    scanner = PythonASTScanner([rule_assignment])
    findings = scanner.scan_file(test_file)

    assert len(findings) == 1
    assert findings[0].rule_id == "EUAIA-ART13-002"
    assert findings[0].location.start_line == 1


def test_inline_suppression(tmp_path: Path):
    from aicomply.cli import get_default_rules_dir
    from aicomply.rules.loader import load_rules_from_dir
    from aicomply.scanner.ast_parser import PythonASTScanner

    rules = load_rules_from_dir(get_default_rules_dir()).rules
    scanner = PythonASTScanner(rules)

    # Código con supresión inline para Art. 5
    code = "import fer  # aicomply:ignore EUAIA-ART05-001\n"
    test_file = tmp_path / "suppressed.py"
    test_file.write_text(code, encoding="utf-8")

    findings = scanner.scan_file(test_file)
    assert not any(f.rule_id == "EUAIA-ART05-001" for f in findings)


def test_generate_sarif_report(engine: ScanEngine):
    import json
    from aicomply.reporter.sarif_reporter import generate_sarif_report

    fixture_path = Path(__file__).parents[1] / "fixtures" / "non_compliant_app.py"
    report = engine.scan_path(fixture_path)
    sarif_str = generate_sarif_report(report)
    sarif_json = json.loads(sarif_str)

    assert sarif_json["version"] == "2.1.0"
    assert len(sarif_json["runs"]) == 1
    assert sarif_json["runs"][0]["tool"]["driver"]["name"] == "AIComply"
    assert len(sarif_json["runs"][0]["results"]) >= 2
    for res in sarif_json["runs"][0]["results"]:
        assert "ruleIndex" in res
        assert isinstance(res["ruleIndex"], int)
        assert res["ruleIndex"] >= 0


def test_cross_engine_deduplication(tmp_path: Path):
    """Verifica que una misma regla con coincidencia AST y Regex en la misma línea no genere duplicados."""
    from aicomply.cli import get_default_rules_dir
    from aicomply.rules.loader import load_rules_from_dir

    rules = load_rules_from_dir(get_default_rules_dir())
    engine = ScanEngine(catalog=rules)

    # Insecure TLS trigger for both AST (requests.post verify=False) and Regex (verify=False)
    test_code = 'import requests\nrequests.post("https://api.internal/v1", json={}, verify=False)\n'
    test_file = tmp_path / "tls_test.py"
    test_file.write_text(test_code, encoding="utf-8")

    report = engine.scan_path(test_file)
    gdpr_tls_findings = [f for f in report.findings if f.rule_id == "GDPR-ART32-002"]
    # Debería haber exactamente 1 hallazgo gracias a la deduplicación cross-engine
    assert len(gdpr_tls_findings) == 1


def test_sarif_codeflows_export(tmp_path: Path):
    """Verifica que los hallazgos de DataFlow exporten codeFlows con threadFlows a SARIF."""
    import json
    from aicomply.cli import get_default_rules_dir
    from aicomply.reporter.sarif_reporter import generate_sarif_report
    from aicomply.rules.loader import load_rules_from_dir

    rules = load_rules_from_dir(get_default_rules_dir())
    engine = ScanEngine(catalog=rules)

    agent_code = """
import os
import openai

def unsafe_task():
    res = openai.chat.completions.create(model="gpt-4o", messages=[])
    cmd = res.choices[0].message.content
    os.system(cmd)
"""
    agent_file = tmp_path / "agent_flow.py"
    agent_file.write_text(agent_code, encoding="utf-8")

    report = engine.scan_path(agent_file)
    sarif_str = generate_sarif_report(report)
    sarif_data = json.loads(sarif_str)

    results = sarif_data["runs"][0]["results"]
    flow_results = [r for r in results if r["ruleId"] == "EUAIA-ART14-002"]
    assert len(flow_results) >= 1
    assert "codeFlows" in flow_results[0]
    thread_flows = flow_results[0]["codeFlows"][0]["threadFlows"]
    assert len(thread_flows) == 1
    locs = thread_flows[0]["locations"]
    assert len(locs) == 3
    assert "SOURCE" in locs[0]["location"]["message"]["text"]
    assert "PROPAGATION" in locs[1]["location"]["message"]["text"]
    assert "SINK" in locs[2]["location"]["message"]["text"]
