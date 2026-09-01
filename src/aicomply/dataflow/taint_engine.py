"""
AIComply - Data Flow (Taint Tracking) Engine
Rastreo determinista de fuentes no confiables (LLMs), propagación por asignaciones,
convergencia pesimista (⊔) y detección de ejecución en sumideros críticos (Sinks).
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aicomply.dataflow.cfg_builder import CFGBuilder, CFGNode, ControlFlowGraph
from aicomply.dataflow.states import TaintEnvironment, TaintState
from aicomply.evidence.hasher import compute_finding_hash
from aicomply.schemas import (
    CodeLocation,
    DataFlowSanitizer,
    DataFlowSink,
    DataFlowSource,
    DataFlowSpec,
    FlowStep,
    Finding,
    PatternType,
    Rule,
)


class DataFlowEngine:
    """Motor de análisis de flujo de datos y taint tracking."""

    def __init__(self, rules: List[Rule], aliases: Optional[Dict[str, str]] = None) -> None:
        self.rules = [r for r in rules if any(p.type == PatternType.DATA_FLOW and p.data_flow for p in r.patterns)]
        self.aliases: Dict[str, str] = aliases or {}
        self.cfg_builder = CFGBuilder()

    def update_aliases(self, aliases: Dict[str, str]) -> None:
        self.aliases.update(aliases)

    def analyze_file(
        self,
        tree: ast.AST,
        source_code: str,
        file_path: str,
        aliases: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Ejecuta el análisis de flujo de datos en todo el módulo/archivo."""
        if not self.rules:
            return []

        if aliases:
            self.update_aliases(aliases)

        source_lines = source_code.splitlines()
        findings: List[Finding] = []

        # 1. Analizar funciones individuales
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cfg = self.cfg_builder.build_for_function(node)
                func_findings = self._analyze_cfg(cfg, source_lines, file_path)
                findings.extend(func_findings)

        # 2. Analizar nivel de módulo (código fuera de funciones)
        if isinstance(tree, ast.Module):
            # Filtrar solo sentencias a nivel superior que no sean definiciones de funciones/clases
            top_level_stmts = [
                s for s in tree.body 
                if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
            if top_level_stmts:
                top_module = ast.Module(body=top_level_stmts, type_ignores=[])
                cfg = self.cfg_builder.build_for_module(top_module)
                module_findings = self._analyze_cfg(cfg, source_lines, file_path)
                findings.extend(module_findings)

        return findings

    def _resolve_name(self, node: ast.AST) -> str:
        """Resuelve nombres y atributos utilizando la tabla de alias de Fase 1."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        elif isinstance(node, ast.Call):
            return self._resolve_name(node.func)
        return ""

    def _get_snippet(self, source_lines: List[str], start_line: int, end_line: int) -> str:
        if 1 <= start_line <= len(source_lines):
            return "\n".join(source_lines[start_line - 1 : end_line])
        return ""

    def _create_location(self, node: ast.AST, file_path: str) -> CodeLocation:
        start_line = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", start_line)
        start_col = getattr(node, "col_offset", 0)
        end_col = getattr(node, "end_col_offset", 0)
        return CodeLocation(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            start_col=start_col,
            end_col=end_col,
        )

    def _analyze_cfg(
        self,
        cfg: ControlFlowGraph,
        source_lines: List[str],
        file_path: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Para cada regla con especificación DataFlow
        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern.type == PatternType.DATA_FLOW and pattern.data_flow:
                    rule_findings = self._evaluate_rule_on_cfg(
                        rule=rule,
                        spec=pattern.data_flow,
                        cfg=cfg,
                        source_lines=source_lines,
                        file_path=file_path,
                    )
                    findings.extend(rule_findings)

        return findings

    def _matches_any_target(self, call_name: str, targets: List[str]) -> bool:
        call_lower = call_name.lower()
        for target in targets:
            target_lower = target.lower()
            if target_lower in call_lower or call_lower.endswith(target_lower):
                return True
        return False

    def _extract_assigned_var(self, target_node: ast.AST) -> Optional[str]:
        """Extrae el nombre de la variable objetivo de una asignación."""
        if isinstance(target_node, ast.Name):
            return target_node.id
        elif isinstance(target_node, ast.Attribute):
            return self._resolve_name(target_node)
        return None

    def _expression_contains_var(self, expr_node: ast.AST, var_name: str) -> bool:
        """Comprueba si una expresión AST referencia a la variable dada."""
        for child in ast.walk(expr_node):
            if isinstance(child, ast.Name) and child.id == var_name:
                return True
            elif isinstance(child, ast.Attribute) and child.attr == var_name:
                return True
        return False

    def _evaluate_rule_on_cfg(
        self,
        rule: Rule,
        spec: DataFlowSpec,
        cfg: ControlFlowGraph,
        source_lines: List[str],
        file_path: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        source_targets = [s.target for s in spec.sources]
        sink_targets = [s.target for s in spec.sinks]
        sanitizer_targets = [s.target for s in spec.sanitizers]

        # Mapeo de entornos de taint por nodo
        node_env_in: Dict[int, TaintEnvironment] = {}
        node_env_out: Dict[int, TaintEnvironment] = {}
        var_traces: Dict[str, List[FlowStep]] = {}

        # Orden de evaluación topológica del CFG
        nodes = cfg.get_topological_order()

        for node in nodes:
            # 1. Calcular Environment IN mediante unión pesimista (⊔) de los predecesores
            if not node.predecessors:
                current_env = TaintEnvironment()
            elif len(node.predecessors) == 1:
                pred = node.predecessors[0]
                current_env = node_env_out.get(pred.node_id, TaintEnvironment()).copy()
            else:
                # NODO PHI: Convergencia de múltiples ramas -> Aplicar Join Pesimista
                current_env = TaintEnvironment()
                for pred in node.predecessors:
                    pred_env = node_env_out.get(pred.node_id, TaintEnvironment())
                    current_env = current_env.join(pred_env)

            # Si este nodo es una compuerta humana (rama THEN de un IF con human approval)
            if node.is_human_gate:
                # Promover todas las variables activas a HUMAN_GATED en este scope
                for var, st in list(current_env._mapping.items()):
                    if st == TaintState.TAINTED_UNSAFE:
                        current_env.set(var, TaintState.HUMAN_GATED)

            node_env_in[node.node_id] = current_env.copy()
            out_env = current_env.copy()

            # 2. Evaluar la sentencia AST del nodo
            if node.ast_node and isinstance(node.ast_node, ast.stmt):
                stmt = node.ast_node

                # A. Caso Asignación (Assign / AnnAssign)
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    value_node = stmt.value if isinstance(stmt, ast.Assign) else stmt.value
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]

                    if value_node:
                        # Comprobar si el valor es una llamada directa a SOURCE
                        call_name = self._resolve_name(value_node)
                        is_source = self._matches_any_target(call_name, source_targets)

                        # Comprobar si el valor es una llamada a SANITIZER
                        is_sanitizer = self._matches_any_target(call_name, sanitizer_targets)

                        # Comprobar si el valor propaga taint desde una variable existente
                        propagates_from: Optional[str] = None
                        for var_name, state in out_env._mapping.items():
                            if state == TaintState.TAINTED_UNSAFE:
                                if self._expression_contains_var(value_node, var_name):
                                    propagates_from = var_name
                                    break

                        for tgt in targets:
                            var_assigned = self._extract_assigned_var(tgt)
                            if not var_assigned:
                                continue

                            loc = self._create_location(stmt, file_path)
                            snippet = self._get_snippet(source_lines, loc.start_line, loc.end_line)

                            if is_source:
                                out_env.set(var_assigned, TaintState.TAINTED_UNSAFE)
                                step = FlowStep(
                                    step_type="source",
                                    message=f"Origen de datos IA no validado: '{call_name}'",
                                    location=loc,
                                    code_snippet=snippet,
                                )
                                var_traces[var_assigned] = [step]

                            elif is_sanitizer:
                                out_env.set(var_assigned, TaintState.SANITIZED)
                                if propagates_from and propagates_from in var_traces:
                                    step = FlowStep(
                                        step_type="sanitizer",
                                        message=f"Saneamiento aplicado mediante '{call_name}'",
                                        location=loc,
                                        code_snippet=snippet,
                                    )
                                    var_traces[var_assigned] = var_traces[propagates_from] + [step]

                            elif propagates_from:
                                out_env.set(var_assigned, TaintState.TAINTED_UNSAFE)
                                step = FlowStep(
                                    step_type="propagation",
                                    message=f"Propagación de datos de IA a la variable '{var_assigned}'",
                                    location=loc,
                                    code_snippet=snippet,
                                )
                                prev_trace = var_traces.get(propagates_from, [])
                                var_traces[var_assigned] = prev_trace + [step]

                # B. Caso llamada en expresión (Expr(Call)) o dentro del stmt -> Detección de Sinks y Sanitizers in-place
                for call_node in ast.walk(stmt):
                    if isinstance(call_node, ast.Call):
                        call_name = self._resolve_name(call_node.func)

                        # B.1. Sanitizer in-place (ej. guardrails.validate(cmd) o moderation(cmd))
                        if self._matches_any_target(call_name, sanitizer_targets):
                            for arg in call_node.args:
                                if isinstance(arg, ast.Name) and out_env.is_tainted(arg.id):
                                    out_env.set(arg.id, TaintState.SANITIZED)

                        # B.2. Detección de Sumidero Crítico (Sink)
                        elif self._matches_any_target(call_name, sink_targets):
                            # Comprobar si algún argumento pasado está TAINTED_UNSAFE
                            tainted_arg: Optional[str] = None
                            for arg in call_node.args:
                                for var_name, state in out_env._mapping.items():
                                    if state == TaintState.TAINTED_UNSAFE:
                                        if self._expression_contains_var(arg, var_name):
                                            tainted_arg = var_name
                                            break
                                if tainted_arg:
                                    break

                            # También comprobar argumentos con nombre (kwargs)
                            if not tainted_arg:
                                for kw in call_node.keywords:
                                    for var_name, state in out_env._mapping.items():
                                        if state == TaintState.TAINTED_UNSAFE:
                                            if self._expression_contains_var(kw.value, var_name):
                                                tainted_arg = var_name
                                                break
                                    if tainted_arg:
                                        break

                            if tainted_arg:
                                loc = self._create_location(call_node, file_path)
                                snippet = self._get_snippet(source_lines, loc.start_line, loc.end_line)
                                sink_step = FlowStep(
                                    step_type="sink",
                                    message=f"Invocación de sumidero crítico '{call_name}' con variable no validada '{tainted_arg}'",
                                    location=loc,
                                    code_snippet=snippet,
                                )

                                full_trace = var_traces.get(tainted_arg, []) + [sink_step]
                                finding_id = compute_finding_hash(
                                    rule_id=rule.id,
                                    location=loc,
                                    target=call_name,
                                    snippet=snippet,
                                )

                                finding = Finding(
                                    id=finding_id,
                                    rule_id=rule.id,
                                    article=rule.article,
                                    severity=rule.severity,
                                    risk_tier=rule.risk_tier,
                                    title=rule.title,
                                    message=(
                                        f"Flujo de datos no validado detectado desde LLM hasta sumidero crítico '{call_name}' "
                                        f"a través de '{tainted_arg}' ({rule.article})."
                                    ),
                                    location=loc,
                                    code_snippet=snippet,
                                    remediation=rule.remediation,
                                    max_fine=rule.max_fine,
                                    confidence=rule.confidence,
                                    flow_steps=full_trace,
                                )
                                findings.append(finding)

            node_env_out[node.node_id] = out_env

        return findings
