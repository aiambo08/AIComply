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