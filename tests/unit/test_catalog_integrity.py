"""
AIComply - Catalog Integrity & Syntax Test
Valida la consistencia normativa, unicidad de IDs y compilación de regex de todas las reglas YAML.
"""

from pathlib import Path
import re
import pytest
from aicomply.cli import get_default_rules_dir
from aicomply.rules.loader import RuleLoadError, load_rules_from_dir
from aicomply.schemas import PatternType, Rule


def test_all_yaml_rules_valid():
    rules_path = get_default_rules_dir()
    assert rules_path.exists(), "El directorio de reglas no existe"

    catalog = load_rules_from_dir(rules_path)
    assert len(catalog.rules) >= 12, "El catálogo debe contener al menos 12 reglas base"

    seen_ids = set()
    for rule in catalog.rules:
        # 1. Unicidad de identificadores
        assert rule.id not in seen_ids, f"ID duplicado detectado: {rule.id}"
        seen_ids.add(rule.id)

        # 2. Formato de identificador
        assert re.match(r"^(EUAIA|GDPR)-(ART\d+|GEN)-\d{3}$", rule.id)

        # 3. Validez y compilación de patrones
        for pattern in rule.patterns:
            if pattern.type == PatternType.REGEX:
                try:
                    re.compile(pattern.target)
                except re.error as e:
                    pytest.fail(f"Regex inválido en regla {rule.id}: '{pattern.target}'. Error: {e}")

            if pattern.type in {PatternType.AST_CALL, PatternType.AST_IMPORT}:
                assert len(pattern.target.strip()) > 0