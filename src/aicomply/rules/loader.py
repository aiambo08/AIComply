"""
AIComply - YAML Rules Loader
Carga y valida todas las reglas YAML contra los esquemas Pydantic v2.
"""

import os
import re
import stat
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml
from aicomply.config import MAX_POLICY_BYTES, checked_path, load_policy_yaml, read_regular_file
from aicomply.schemas import PatternType, Rule


class RuleLoadError(ValueError):
    """Error al cargar o validar un archivo de reglas."""
    pass


class RuleCatalog:
    """Catálogo en memoria de todas las reglas del EU AI Act cargadas."""

    def __init__(self, rules: List[Rule]) -> None:
        ids = set()
        for rule in rules:
            if rule.id in ids:
                raise RuleLoadError(f"Duplicate rule ID: {rule.id}")
            ids.add(rule.id)
            for pattern in rule.patterns:
                if pattern.type == PatternType.DATA_FLOW:
                    if pattern.data_flow is None:
                        raise RuleLoadError(f"Missing data_flow specification: {rule.id}")
                elif not pattern.target or not pattern.target.strip():
                    raise RuleLoadError(f"Missing pattern target: {rule.id}")
                if pattern.type == PatternType.REGEX:
                    if pattern.target is None:
                        raise RuleLoadError(f"Missing regex target: {rule.id}")
                    try:
                        re.compile(pattern.target)
                    except re.error as exc:
                        raise RuleLoadError(f"Invalid regex pattern: {rule.id}") from exc
        self._rules = list(rules)
        self._rule_map: Dict[str, Rule] = {rule.id: rule for rule in rules}

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

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
    loaded_rules: List[Rule] = []
    yaml_files: List[Path] = []
    entries = 0
    total_bytes = 0

    def walk_error(error: OSError) -> None:
        raise error

    try:
        rules_dir = checked_path(rules_dir)
        if not rules_dir.is_dir():
            raise RuleLoadError(f"Not a rules directory: {rules_dir}")
        for directory, dirs, files in os.walk(rules_dir, onerror=walk_error, followlinks=False):
            for name in dirs + files:
                entries += 1
                if entries > 10000:
                    raise RuleLoadError("Too many rule directory entries")
                path = Path(directory) / name
                mode = path.lstat().st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise RuleLoadError(f"Rules contain a symbolic link or special file: {path}")
                if stat.S_ISREG(mode) and path.suffix.lower() in {".yaml", ".yml"}:
                    yaml_files.append(path)
                    if len(yaml_files) > 1000:
                        raise RuleLoadError("Too many rule files")
        for yaml_file in sorted(yaml_files):
            data = read_regular_file(yaml_file, MAX_POLICY_BYTES)
            total_bytes += len(data)
            if total_bytes > 10 * MAX_POLICY_BYTES:
                raise RuleLoadError("Rule catalog exceeds total byte limit")
            text = data.decode("utf-8-sig")
            content = load_policy_yaml(text)
            raw_rules = content if isinstance(content, list) else [content]
            if not raw_rules:
                raise RuleLoadError(f"Empty rules file: {yaml_file}")
            for raw_rule in raw_rules:
                loaded_rules.append(Rule.model_validate(raw_rule))
                if len(loaded_rules) > 10000:
                    raise RuleLoadError("Too many rules")
        if not loaded_rules:
            raise RuleLoadError(f"No rules found: {rules_dir}")
        return RuleCatalog(loaded_rules)
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise RuleLoadError(f"Unable to load valid rules from: {rules_dir}") from exc


def load_builtin_rules() -> RuleCatalog:
    """Carga el catálogo por defecto de reglas empaquetadas con AIComply."""
    builtin_dir = Path(__file__).parent
    return load_rules_from_dir(builtin_dir)