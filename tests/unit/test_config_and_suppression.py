from pathlib import Path
import pytest
from aicomply.cli import get_default_rules_dir
from aicomply.config import AIComplyConfig
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.engine import ScanEngine


def test_inline_suppression_regex(tmp_path: Path):
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    engine = ScanEngine(catalog=catalog)

    # Archivo con infracción suprimida mediante comentario inline
    test_file = tmp_path / "app.py"
    test_file.write_text("ai_disclaimer = False  # aicomply:ignore EUAIA-ART13-001\n", encoding="utf-8")

    report = engine.scan_path(test_file)
    assert report.summary.total_findings == 0


def test_ignore_rules_from_config(tmp_path: Path):
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)

    # Ignorar globalmente la regla de transparencia vía configuración
    custom_cfg = AIComplyConfig(ignore_rules=["EUAIA-ART13-001"], exclude_paths=[])
    engine = ScanEngine(catalog=catalog, config=custom_cfg)

    test_file = tmp_path / "app.py"
    test_file.write_text("ai_disclaimer = False\n", encoding="utf-8")

    report = engine.scan_path(test_file)
    assert report.summary.total_findings == 0


def test_exclude_paths_from_config(tmp_path: Path):
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)

    custom_cfg = AIComplyConfig(exclude_paths=["legacy/**"], ignore_rules=[])
    engine = ScanEngine(catalog=catalog, config=custom_cfg)

    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    legacy_file = legacy_dir / "untracked.py"
    legacy_file.write_text("ai_disclaimer = False\n", encoding="utf-8")

    report = engine.scan_path(tmp_path)
    assert report.summary.total_files_scanned == 0
    assert report.summary.total_findings == 0


def test_auto_load_dot_aicomply_yaml_in_target_dir(tmp_path: Path):
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    engine = ScanEngine(catalog=catalog)

    # Crear .aicomply.yaml en el directorio escaneado
    yaml_config = tmp_path / ".aicomply.yaml"
    yaml_config.write_text(
        """
exclude_paths:
  - "legacy/**"
ignore_rules:
  - "EUAIA-ART13-001"
""",
        encoding="utf-8",
    )

    test_file = tmp_path / "main.py"
    test_file.write_text("ai_disclaimer = False\n", encoding="utf-8")

    report = engine.scan_path(tmp_path)
    assert report.summary.total_findings == 0