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
    Recorre el AST recopilando imports, llamadas a funciones, asignaciones
    y resolviendo referencias de variables locales y alias.
    """

    def __init__(self, source_code: str, file_path: str) -> None:
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path

        # Mapeo de alias a nombres completos: {"oai": "openai", "client": "openai.OpenAI"}
        self.aliases: Dict[str, str] = {}

        # Registros de nodos identificados
        self.imports: List[Tuple[str, ast.AST]] = []
        self.calls: List[Tuple[str, ast.Call, Dict[str, Any]]] = []
        self.assignments: List[Tuple[str, Any, ast.AST]] = []
        self.function_defs: List[Tuple[str, ast.AST]] = []
        self.has_logging: bool = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module_name = alias.name
            imported_as = alias.asname or module_name
            self.aliases[imported_as] = module_name
            self.imports.append((module_name, node))
            if any(log_mod in module_name for log_mod in ["logging", "loguru", "structlog", "telemetry", "audit"]):
                self.has_logging = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if any(log_mod in module for log_mod in ["logging", "loguru", "structlog", "telemetry", "audit"]):
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
            return f"{value_str}.{node.attr}" if value_str else node.attr
        elif isinstance(node, ast.Call):
            return self._resolve_call_name(node.func)
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

    def visit_Assign(self, node: ast.Assign) -> None:
        # 1. Inferencia de tipo por instanciación: client = OpenAI() -> aliases["client"] = "openai.OpenAI"
        if isinstance(node.value, ast.Call):
            call_name = self._resolve_call_name(node.value.func)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases[target.id] = call_name

        # 2. Asignación de alias directo: engine = client -> aliases["engine"] = aliases["client"]
        elif isinstance(node.value, ast.Name):
            source_val = self.aliases.get(node.value.id, node.value.id)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases[target.id] = source_val

        # 3. Asignación de constantes para AST_ASSIGNMENT: ai_disclaimer = False
        for target in node.targets:
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                self.assignments.append((target.id, node.value.value, node))

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            if node.value and isinstance(node.value, ast.Constant):
                self.assignments.append((node.target.id, node.value.value, node))
            elif node.value and isinstance(node.value, ast.Call):
                call_name = self._resolve_call_name(node.value.func)
                self.aliases[node.target.id] = call_name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_defs.append((node.name, node))
        # Comprobar decoradores de logging/auditoría
        for dec in node.decorator_list:
            dec_name = self._resolve_call_name(dec)
            if any(log_kw in dec_name.lower() for log_kw in ["log", "audit", "trace", "telemetry"]):
                self.has_logging = True
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_defs.append((node.name, node))
        for dec in node.decorator_list:
            dec_name = self._resolve_call_name(dec)
            if any(log_kw in dec_name.lower() for log_kw in ["log", "audit", "trace", "telemetry"]):
                self.has_logging = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolve_call_name(node.func)
        args_dict = self._extract_call_args(node)

        # Detección de logging en llamada
        if any(log_kw in call_name.lower() for log_kw in ["log", "logger", "logging", "audit", "structlog"]):
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
        seen_finding_ids: Set[str] = set()
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except Exception:
            # Archivo con sintaxis rota, encoding corrupto o inaccesible se omite de AST
            return findings

        visitor = ASTContextVisitor(source, rel_path)
        visitor.visit(tree)

        for rule in self.rules:
            for pattern in rule.patterns:
                matched_findings = self._evaluate_pattern(rule, pattern, visitor, rel_path)
                for f in matched_findings:
                    if f.id not in seen_finding_ids:
                        seen_finding_ids.add(f.id)
                        findings.append(f)

        return findings

    def _evaluate_pattern(
        self,
        rule: Rule,
        pattern: RulePattern,
        visitor: ASTContextVisitor,
        rel_path: str
    ) -> List[Finding]:
        results: List[Finding] = []
        target_lower = pattern.target.lower()

        if pattern.type == PatternType.AST_IMPORT:
            for imp_name, node in visitor.imports:
                if target_lower in imp_name.lower():
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        elif pattern.type == PatternType.AST_CALL:
            for call_name, node, kwargs in visitor.calls:
                if target_lower in call_name.lower():
                    if pattern.match_args:
                        if not self._check_match_args(pattern.match_args, kwargs):
                            continue
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        elif pattern.type == PatternType.AST_ASSIGNMENT:
            for var_name, var_value, node in visitor.assignments:
                if target_lower == var_name.lower():
                    if pattern.match_args:
                        if not self._check_match_args(pattern.match_args, {"value": var_value}):
                            continue
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        elif pattern.type == PatternType.AST_FUNCTION_DEF:
            for fn_name, node in visitor.function_defs:
                if target_lower in fn_name.lower():
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        elif pattern.type == PatternType.AST_ABSENCE:
            # Detección de ausencia: evaluar llamadas a la librería/API del target cuando no hay logging
            target_parts = [p.lower() for p in pattern.target.split(".") if p]
            target_root = target_parts[0] if target_parts else ""

            matching_calls = [
                (name, node) for name, node, _ in visitor.calls
                if (target_root and target_root in name.lower())
                or any(len(p) > 3 and p in name.lower() for p in target_parts)
            ]
            if matching_calls and not visitor.has_logging:
                for _, node in matching_calls:
                    results.append(self._create_finding(rule, pattern, node, visitor, rel_path))

        return results

    def _check_match_args(self, required_args: Dict[str, Any], call_args: Dict[str, Any]) -> bool:
        """Verifica si los argumentos extraídos coinciden con la regla."""
        for key, expected_val in required_args.items():
            if key not in call_args:
                return False
            actual_val = call_args[key]
            if isinstance(actual_val, list) and isinstance(expected_val, str):
                if expected_val.lower() not in [str(x).lower() for x in actual_val]:
                    return False
            elif str(actual_val).lower() != str(expected_val).lower():
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