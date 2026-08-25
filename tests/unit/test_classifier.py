from aicomply.classifier.risk_tier import classify_overall_risk
from aicomply.schemas import CodeLocation, Confidence, Finding, RiskTier, Severity


def test_classify_overall_risk_prohibited():
    loc = CodeLocation(file_path="src/main.py", start_line=1, end_line=1)
    findings = [
        Finding(
            id="hash1",
            rule_id="EUAIA-ART12-001",
            article="Art. 12",
            severity=Severity.HIGH,
            risk_tier=RiskTier.HIGH_RISK,
            title="Logging",
            message="msg",
            location=loc,
            remediation="rem",
            max_fine="15M",
            confidence=Confidence.HIGH,
        ),
        Finding(
            id="hash2",
            rule_id="EUAIA-ART05-001",
            article="Art. 5",
            severity=Severity.CRITICAL,
            risk_tier=RiskTier.PROHIBITED,
            title="Emotion",
            message="msg",
            location=loc,
            remediation="rem",
            max_fine="35M",
            confidence=Confidence.HIGH,
        ),
    ]
    # Si hay al menos un hallazgo de práctica prohibida, la postura global es PROHIBITED
    assert classify_overall_risk(findings) == RiskTier.PROHIBITED


def test_classify_overall_risk_empty():
    assert classify_overall_risk([]) == RiskTier.MINIMAL_RISK


def test_render_assessment_report():
    from rich.console import Console
    from aicomply.classifier.assess import AssessmentResult, render_assessment_report

    result = AssessmentResult(
        system_name="Test-LLM-App",
        risk_tier=RiskTier.HIGH_RISK,
        applicable_articles=["Art. 6", "Anexo III"],
        obligations=["Logging obligatorio", "Supervisión humana"],
        compliance_deadline="Agosto 2026",
        rationale="Sistema en dominio de empleo y RRHH.",
    )
    console = Console(record=True, width=80)
    render_assessment_report(result, console=console)
    output = console.export_text()

    assert "Test-LLM-App" in output
    assert "ALTO RIESGO" in output
    assert "Logging obligatorio" in output