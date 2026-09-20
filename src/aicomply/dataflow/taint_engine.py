"""Intra-procedural, conservative tracking of configured AI data flows."""

import ast
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from aicomply.dataflow.cfg_builder import CFGBuilder, CFGNode, ControlFlowGraph
from aicomply.dataflow.states import TaintState, pessimistic_join
from aicomply.evidence.hasher import compute_finding_hash
from aicomply.schemas import (
    CodeLocation,
    DataFlowSpec,
    Finding,
    FlowStep,
    PatternType,
    Rule,
)


@dataclass(frozen=True)
class _Value:
    state: TaintState = TaintState.CLEAN
    trace: tuple[FlowStep, ...] = ()


def _join(left: _Value, right: _Value) -> _Value:
    state = pessimistic_join(left.state, right.state)
    candidates = [value for value in (left, right) if value.state == state]
    return min(
        candidates,
        key=lambda value: (
            len(value.trace),
            tuple(
                (s.location.start_line, s.location.start_col, s.message)
                for s in value.trace
            ),
        ),
    )


def _merge(left: dict[str, _Value], right: dict[str, _Value]) -> dict[str, _Value]:
    return {
        name: _join(left.get(name, _Value()), right.get(name, _Value()))
        for name in sorted(left.keys() | right.keys())
    }


class DataFlowEngine:
    """Tracks configured sources and sanitizer return values; no runtime guarantees."""

    def __init__(
        self, rules: List[Rule], aliases: Optional[Dict[str, str]] = None
    ) -> None:
        self.rules = [
            r
            for r in rules
            if any(p.type == PatternType.DATA_FLOW and p.data_flow for p in r.patterns)
        ]
        self.aliases: Dict[str, str] = dict(aliases or {})
        self.resolved_calls: dict[ast.Call, str] = {}
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
        if aliases is not None:
            self.aliases = dict(aliases)
        if not self.rules:
            return []
        source_lines = source_code.splitlines()
        graphs = [
            self.cfg_builder.build_for_function(node)
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if isinstance(tree, ast.Module):
            graphs.append(self.cfg_builder.build_for_module(tree))
        findings: dict[str, Finding] = {}
        for graph in graphs:
            for finding in self._analyze_cfg(graph, source_lines, file_path):
                findings[finding.id] = finding
        return sorted(findings.values(), key=lambda f: (f.location.start_line, f.id))

    def _resolve_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self.resolved_calls.get(node, self._resolve_name(node.func))
        return ""

    def _matches_any_target(self, call_name: str, targets: List[str]) -> bool:
        name = call_name.lower()
        return any(
            target and (name == target.lower() or name.endswith("." + target.lower()))
            for target in targets
        )

    def _create_location(
        self, node: ast.expr | ast.stmt, file_path: str
    ) -> CodeLocation:
        return CodeLocation(
            file_path=file_path,
            start_line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            start_col=node.col_offset,
            end_col=node.end_col_offset or 0,
        )

    def _get_snippet(
        self, source_lines: List[str], start_line: int, end_line: int
    ) -> str:
        return "\n".join(source_lines[start_line - 1 : end_line])

    def _analyze_cfg(
        self, cfg: ControlFlowGraph, source_lines: List[str], file_path: str
    ) -> List[Finding]:
        findings = []
        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern.type == PatternType.DATA_FLOW and pattern.data_flow:
                    findings.extend(
                        self._evaluate_rule_on_cfg(
                            rule, pattern.data_flow, cfg, source_lines, file_path
                        )
                    )
        return findings

    def _evaluate_rule_on_cfg(
        self,
        rule: Rule,
        spec: DataFlowSpec,
        cfg: ControlFlowGraph,
        source_lines: List[str],
        file_path: str,
    ) -> List[Finding]:
        sources = [s.target for s in spec.sources]
        sanitizers = [s.target for s in spec.sanitizers]
        sinks = [s.target for s in spec.sinks]
        findings: dict[str, Finding] = {}

        def step(kind: str, node: ast.expr | ast.stmt, message: str) -> FlowStep:
            loc = self._create_location(node, file_path)
            return FlowStep(
                step_type=kind,
                message=message,
                location=loc,
                code_snippet=self._get_snippet(
                    source_lines, loc.start_line, loc.end_line
                ),
            )

        def append(value: _Value, next_step: FlowStep) -> _Value:
            if next_step in value.trace:
                return value
            return _Value(value.state, (*value.trace, next_step))

        def report(call: ast.Call, value: _Value) -> None:
            name = self._resolve_name(call)
            sink_step = step(
                "sink", call, f"Sumidero crítico '{name}' con datos IA no validados"
            )
            loc = sink_step.location
            snippet = sink_step.code_snippet or ""
            finding_id = compute_finding_hash(rule.id, loc, name, snippet)
            findings[finding_id] = Finding(
                id=finding_id,
                rule_id=rule.id,
                article=rule.article,
                severity=rule.severity,
                risk_tier=rule.risk_tier,
                title=rule.title,
                message=f"Flujo de datos IA no validado hasta '{name}' ({rule.article}).",
                location=loc,
                code_snippet=snippet,
                remediation=rule.remediation,
                max_fine=rule.max_fine,
                confidence=rule.confidence,
                flow_steps=[*value.trace, sink_step],
            )

        def storage_name(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                base = storage_name(node.value)
                return f"{base}.{node.attr}" if base else ""
            return ""

        def assign(target: ast.expr, value: _Value, env: dict[str, _Value]) -> None:
            if isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    assign(item, value, env)
            elif isinstance(target, ast.Starred):
                assign(target.value, value, env)
            elif isinstance(target, ast.Subscript):
                name = storage_name(target.value)
                if name:
                    env[name] = _join(env.get(name, _Value()), value)
            else:
                name = storage_name(target)
                if name:
                    for key in list(env):
                        if key.startswith(name + "."):
                            del env[key]
                    env[name] = value

        def expression(
            node: ast.AST | None,
            env: dict[str, _Value],
            emit: Callable[[ast.Call, _Value], None],
        ) -> _Value:
            if node is None or isinstance(node, (ast.Constant, ast.Lambda)):
                return _Value()
            if isinstance(node, ast.Name):
                return env.get(node.id, _Value())
            if isinstance(node, ast.NamedExpr):
                value = expression(node.value, env, emit)
                assign(node.target, value, env)
                return value
            if isinstance(node, ast.IfExp):
                expression(node.test, env, emit)
                then_env, else_env = env.copy(), env.copy()
                value = _join(
                    expression(node.body, then_env, emit),
                    expression(node.orelse, else_env, emit),
                )
                env.update(_merge(then_env, else_env))
                return value
            if isinstance(node, ast.Call):
                value = _Value()
                if isinstance(node.func, ast.Attribute):
                    value = expression(node.func.value, env, emit)
                arguments = _Value()
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    arguments = _join(arguments, expression(arg, env, emit))
                name = self._resolve_name(node)
                if (
                    self._matches_any_target(name, sinks)
                    and arguments.state == TaintState.TAINTED_UNSAFE
                ):
                    emit(node, arguments)
                if self._matches_any_target(name, sources):
                    return _Value(
                        TaintState.TAINTED_UNSAFE,
                        (
                            step(
                                "source",
                                node,
                                f"Origen de datos IA no validado: '{name}'",
                            ),
                        ),
                    )
                value = _join(value, arguments)
                if self._matches_any_target(name, sanitizers):
                    return _Value(TaintState.SANITIZED)
                return value
            if isinstance(
                node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
            ):
                local = env.copy()
                for generator in node.generators:
                    value = expression(generator.iter, local, emit)
                    assign(generator.target, value, local)
                    for condition in generator.ifs:
                        expression(condition, local, emit)
                if isinstance(node, ast.DictComp):
                    return _join(
                        expression(node.key, local, emit),
                        expression(node.value, local, emit),
                    )
                return expression(node.elt, local, emit)
            if isinstance(node, ast.BoolOp):
                value = _Value()
                for operand in node.values:
                    before = env.copy()
                    value = _join(value, expression(operand, env, emit))
                    env.update(_merge(before, env))
                return value
            value = env.get(storage_name(node), _Value())
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, ast.stmt):
                    value = _join(value, expression(child, env, emit))
            return value

        def transfer(
            node: CFGNode,
            incoming: dict[str, _Value],
            emit: Callable[[ast.Call, _Value], None],
        ) -> dict[str, _Value]:
            env = incoming.copy()
            stmt = node.ast_node
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                if stmt.value is None:
                    return env
                value = expression(stmt.value, env, emit)
                targets = (
                    stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                )
                if isinstance(stmt, ast.AugAssign):
                    value = _join(value, expression(stmt.target, env, emit))
                if value.state == TaintState.TAINTED_UNSAFE and (
                    not value.trace
                    or value.trace[-1].location.start_line != stmt.lineno
                ):
                    value = append(
                        value, step("propagation", stmt, "Propagación por asignación")
                    )
                for target in targets:
                    assign(target, value, env)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                value = expression(stmt.iter, env, emit)
                # The iterator may be empty, so retain the previous binding.
                previous = env.copy()
                assign(stmt.target, value, env)
                env = _merge(previous, env)
            elif isinstance(stmt, ast.While):
                expression(stmt.test, env, emit)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    value = expression(item.context_expr, env, emit)
                    if item.optional_vars:
                        assign(item.optional_vars, value, env)
            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    assign(target, _Value(), env)
            elif stmt is not None:
                expression(stmt, env, emit)
            return env

        def incoming(node: CFGNode) -> dict[str, _Value]:
            env: dict[str, _Value] = {}
            for pred in node.predecessors:
                env = _merge(env, outputs.get(pred.node_id, {}))
            return env

        outputs: dict[int, dict[str, _Value]] = {}
        queue = deque([cfg.entry])
        queued = {cfg.entry.node_id}
        while queue:
            node = queue.popleft()
            queued.remove(node.node_id)
            env = transfer(node, incoming(node), lambda call, value: None)
            if node.node_id not in outputs or outputs[node.node_id] != env:
                outputs[node.node_id] = env
                for successor in node.successors:
                    if successor.node_id not in queued:
                        queue.append(successor)
                        queued.add(successor.node_id)

        for node in cfg.get_topological_order():
            if node.node_id in outputs:
                transfer(node, incoming(node), report)
        return list(findings.values())
