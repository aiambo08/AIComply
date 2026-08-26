from pathlib import Path
from aicomply.config import AIComplyConfig, load_project_config


def test_default_config():
    cfg = AIComplyConfig()
    assert "tests/**" in cfg.exclude_paths
    assert cfg.ignore_rules == []
    assert cfg.enforce_risk_tier is None


def test_load_project_config_nonexistent(tmp_path: Path):
    cfg = load_project_config(tmp_path)
    assert isinstance(cfg, AIComplyConfig)
    assert "tests/**" in cfg.exclude_paths


def test_load_project_config_yaml_file(tmp_path: Path):
    config_file = tmp_path / ".aicomply.yaml"
    config_file.write_text(
        """
exclude_paths:
  - "legacy/**"
ignore_rules:
  - "EUAIA-ART15-001"
enforce_risk_tier: "high_risk"
""",
        encoding="utf-8",
    )

    cfg = load_project_config(tmp_path)
    assert cfg.exclude_paths == ["legacy/**"]
    assert cfg.ignore_rules == ["EUAIA-ART15-001"]
    assert cfg.enforce_risk_tier == "high_risk"


def test_load_corrupted_config_fallback(tmp_path: Path):
    config_file = tmp_path / ".aicomply.yaml"
    config_file.write_text("corrupted: yaml: : [invalid", encoding="utf-8")

    cfg = load_project_config(tmp_path)
    # Debe retornar la configuración por defecto sin crashear
    assert isinstance(cfg, AIComplyConfig)
    assert "tests/**" in cfg.exclude_paths
