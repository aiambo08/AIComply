"""
AIComply - AST Parser for Python Source Code
Inspección estática determinista basada en el módulo 'ast' de la librería estándar.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aicomply.evidence.hasher import compute_finding_hash
from aicomply.schemas import (
    CodeLocation,
    Confidence,
    Finding,
    PatternType,
    Rule,
    RulePattern,
)


class ASTContextVisitor(ast.NodeVisitor):
    """
    Recorre el AST recopilando imports, llamadas a funciones y resolviendo
    resoluciones de alias locales.
    """

    def __init__(self, source_code: str, file_path: str) -> None:
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        
        # Mapeo de alias a nombres completos: {"oai": "openai", "analyze": "DeepFace.analyze"}
        self.aliases: Dict[str, str] = {}
        
        # Registros de nodos identificados: (nombre_resuelto, nodo_ast, kwargs_dict)
        self.imports: List[Tuple[str, ast.AST]] = []
        self.calls: List[Tuple[str, ast.Call, Dict[str, Any]]] = []
        self.has_logging: bool = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module_name = alias.name
            imported_as = alias.asname or module_name
            self.aliases[imported_as] = module_name
            self.imports.append((module_name, node))
            if module_name in {"logging", "loguru", "structlog"}:
                self.has_logging = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module in {"logging", "loguru", "structlog"}:
            self.has_logging = True

        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            imported_as = alias.asname or alias.name
            self.aliases[imported_as] = full_name
            self.imports.append((full_name, node))
        self.generic_visit(node)

    def _resolve_call_name(self, node: ast.AST) -> str:
        """Resuelve recursivamente nombres de llamadas como client.chat.completions.create."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            value_str = self._resolve_call_name(node.value)
            return f"{value_str}.{node.attr}"
        return ""

    def _extract_call_args(self, node: ast.Call) -> Dict[str, Any]:
        """Extrae argumentos constantes pasados a una llamada."""
        args_dict: Dict[str, Any] = {}
        for kw in node.keywords:
            if kw.arg is not None:
                if isinstance(kw.value, ast.Constant):
                    args_dict[kw.arg] = kw.value.value
                elif isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    args_dict[kw.arg] = [
                        elt.value for elt in kw.value.elts if isinstance(elt, ast.Constant)
                    ]
        return args_dict

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolve_call_name(node.func)
        args_dict = self._extract_call_args(node)
        
        # Detección básica de logging en llamada
        if any(log_kw in call_name.lower() for log_kw in ["log", "logger", "logging", "audit"]):
            self.has_logging = True

        self.calls.append((call_name, node, args_dict))
        self.generic_visit(node)

    def get_snippet(self, start_line: int, end_line: int) -> str:
        """Extrae el fragmento de código correspondiente a las líneas dadas."""
        if 1 <= start_line <= len(self.source_lines):
            return "\n".join(self.source_lines[start_line - 1 : end_line])
        return ""


class PythonASTScanner:
    """Ejecuta reglas basadas en AST sobre archivos Python."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules = rules

    def scan_file(self, file_path: Path, base_path: Optional[Path] = None) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError):
            # Archivo con sintaxis rota o encoding no válido se omite del análisis AST
            return findings

        visitor = ASTContextVisitor(source, rel_path)
        visitor.visit(tree)

        for rule in self.rules:
            for pattern in rule.patterns:
                matched_findings = self._evaluate_pattern(rule, pattern, visitor, rel_path)
                findings.extend(matched_findings)

        return findings

    def _evaluate_pattern(
        self,
        rule: Rule,
        pattern: RulePattern,
        visitor: ASTContextVisitor,
        rel_path: str
    ) -> List[Finding]:
        results: List[Finding] = []

        if pattern.type == PatternType.AST_IMPORT:
            for imp_name, node in visitor.imports:
                if pattern.target in imp_name:
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        elif pattern.type == PatternType.AST_CALL:
            for call_name, node, kwargs in visitor.calls:
                # Comprobar coincidencia en el nombre de la función / método
                if pattern.target in call_name:
                    if pattern.match_args:
                        # Si requiere argumentos específicos, validar coincidencia exacta o subconjunto
                        if not self._check_match_args(pattern.match_args, kwargs):
                            continue
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        elif pattern.type == PatternType.AST_ABSENCE:
            # Detección de ausencia (ej. LLM calls presentes en el archivo sin logging configurado)
            llm_calls = [
                (name, node) for name, node, _ in visitor.calls 
                if any(provider in name.lower() for provider in ["openai", "anthropic", "langchain", "cohere"])
            ]
            if llm_calls and not visitor.has_logging:
                for _, node in llm_calls:
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        return results

    def _check_match_args(self, required_args: Dict[str, Any], call_args: Dict[str, Any]) -> bool:
        """Verifica si los argumentos extraídos coinciden con la regla."""
        for key, expected_val in required_args.items():
            if key not in call_args:
                return False
            actual_val = call_args[key]
            if isinstance(actual_val, list) and isinstance(expected_val, str):
                if expected_val not in actual_val:
                    return False
            elif actual_val != expected_val:
                return False
        return True

    def _create_finding(
        self,
        rule: Rule,
        pattern: RulePattern,
        node: ast.AST,
        visitor: ASTContextVisitor,
        rel_path: str
    ) -> Finding:
        start_line = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", start_line)
        start_col = getattr(node, "col_offset", 0)
        end_col = getattr(node, "end_col_offset", 0)

        loc = CodeLocation(
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            start_col=start_col,
            end_col=end_col,
        )

        snippet = visitor.get_snippet(start_line, end_line)
        finding_id = compute_finding_hash(rule.id, loc, pattern.target, snippet)

        return Finding(
            id=finding_id,
            rule_id=rule.id,
            article=rule.article,
            severity=rule.severity,
            risk_tier=rule.risk_tier,
            title=rule.title,
            message=f"Patrón detectado '{pattern.target}' en conformidad con {rule.article}.",
            location=loc,
            code_snippet=snippet,
            remediation=rule.remediation,
            max_fine=rule.max_fine,
            confidence=rule.confidence,
        )