"""
AIComply - Unit Tests for Dependency & Manifest Scanner
"""

from pathlib import Path
import pytest
from aicomply.infra.dependency_scanner import DependencyScanner
from aicomply.rules.loader import load_rules_from_dir


@pytest.fixture
def rules():
    rules_path = Path(__file__).parents[2] / "src" / "aicomply" / "rules" / "eu_ai_act"
    catalog = load_rules_from_dir(rules_path)
    return catalog.rules


def test_scan_requirements_txt_detects_prohibited_package(tmp_path: Path, rules):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi>=0.100.0\ndeepface==0.0.79\nuvicorn\n", encoding="utf-8")

    scanner = DependencyScanner(rules)
    findings = scanner.scan_file(req_file)

    assert len(findings) == 1
    assert findings[0].rule_id == "EUAIA-ART05-003"
    assert findings[0].location.start_line == 2


def test_scan_pyproject_toml_detects_prohibited_package(tmp_path: Path, rules):
    pyproject = tmp_path / "pyproject.toml"
    content = """
[project]
name = "my-ai-app"
version = "1.0.0"
dependencies = [
    "requests",
    "face-recognition>=1.3.0",
]
"""
    pyproject.write_text(content, encoding="utf-8")

    scanner = DependencyScanner(rules)
    findings = scanner.scan_file(pyproject)

    assert len(findings) == 1
    assert findings[0].rule_id == "EUAIA-ART05-003"


def test_scan_uv_lock_detects_prohibited_package(tmp_path: Path, rules):
    uv_lock = tmp_path / "uv.lock"
    content = """
version = 1
revision = 1

[[package]]
name = "fastapi"
version = "0.110.0"

[[package]]
name = "deepface"
version = "0.0.79"
"""
    uv_lock.write_text(content, encoding="utf-8")

    scanner = DependencyScanner(rules)
    findings = scanner.scan_file(uv_lock)

    assert len(findings) == 1
    assert findings[0].rule_id == "EUAIA-ART05-003"


def test_dependency_inline_suppression(tmp_path: Path, rules):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("deepface==0.0.79 # aicomply:ignore EUAIA-ART05-003\n", encoding="utf-8")

    scanner = DependencyScanner(rules)
    findings = scanner.scan_file(req_file)

    assert len(findings) == 0
