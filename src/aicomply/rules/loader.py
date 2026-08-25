"""
AIComply - YAML Rules Loader
Carga y valida todas las reglas YAML contra los esquemas Pydantic v2.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml
from aicomply.schemas import Rule


class RuleLoadError(Exception):
    """Error al cargar o validar un archivo de reglas."""
    pass


class RuleCatalog:
    """Catálogo en memoria de todas las reglas del EU AI Act cargadas."""

    def __init__(self, rules: List[Rule]) -> None:
        self._rules = rules
        self._rule_map: Dict[str, Rule] = {rule.id: rule for rule in rules}

    @property
    def rules(self) -> List[Rule]:
        return self._rules

    def get_by_id(self, rule_id: str) -> Optional[Rule]:
        return self._rule_map.get(rule_id.upper())

    def filter_by_articles(self, articles: Set[str]) -> List[Rule]:
        """Filtra reglas por número de artículo (ej. {'5', '12', '13', '50'})."""
        normalized_targets = {
            re.sub(r"[^0-9a-zA-Z]", "", art.lower()).replace("art", "").lstrip("0")
            for art in articles
        }
        filtered: List[Rule] = []

        for rule in self._rules:
            # Extraer números de artículo usando expresiones regulares precisas
            text_to_search = f"{rule.id} {rule.article}"
            # Extrae ocurrencias tipo ART05, Art. 5, Art 50, etc.
            art_matches = set()
            for m in re.finditer(r"(?:art(?:icle)?\.?\s*(\d+))", text_to_search, re.IGNORECASE):
                art_matches.add(m.group(1).lstrip("0"))
            
            # Extraer id token (ej. ART05 -> 5, GEN -> gen)
            id_parts = rule.id.split("-")
            if len(id_parts) >= 2:
                id_art = id_parts[1].lower().replace("art", "").lstrip("0")
                art_matches.add(id_art)

            if any(t in art_matches for t in normalized_targets if t):
                filtered.append(rule)

        return filtered


def load_rules_from_dir(rules_dir: Path) -> RuleCatalog:
    """
    Lee recursivamente archivos .yaml/.yml en el directorio indicado y valida
    cada entrada con el esquema Pydantic Rule.
    """
    if not rules_dir.exists() or not rules_dir.is_dir():
        raise RuleLoadError(f"El directorio de reglas no existe: {rules_dir}")

    loaded_rules: List[Rule] = []
    rule_ids: Set[str] = set()

    for yaml_file in sorted(rules_dir.glob("**/*.y*ml")):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)

            if not content:
                continue

            # Si el archivo contiene una lista de reglas
            raw_rules = content if isinstance(content, list) else [content]

            for idx, raw_rule in enumerate(raw_rules):
                try:
                    rule = Rule.model_validate(raw_rule)
                    if rule.id in rule_ids:
                        raise RuleLoadError(
                            f"ID de regla duplicado '{rule.id}' detectado en {yaml_file.name} (índice {idx})"
                        )
                    rule_ids.add(rule.id)
                    loaded_rules.append(rule)
                except Exception as val_err:
                    raise RuleLoadError(
                        f"Error de validación en {yaml_file.name} [índice {idx}]: {val_err}"
                    ) from val_err

        except yaml.YAMLError as yaml_err:
            raise RuleLoadError(f"Sintaxis YAML inválida en {yaml_file}: {yaml_err}") from yaml_err

    return RuleCatalog(loaded_rules)