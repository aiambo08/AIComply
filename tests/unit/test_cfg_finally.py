import ast
from textwrap import dedent, indent

import pytest

from aicomply.dataflow.cfg_builder import CFGBuilder, CFGNode
from aicomply.dataflow.taint_engine import DataFlowEngine
from aicomply.rules.loader import load_builtin_rules
from aicomply.schemas import Finding, Rule


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return load_builtin_rules().rules


def analyze(body: str, rules: list[Rule]) -> list[Finding]:
    code = "def agent(flag):\n" + indent(dedent(body).strip(), "    ")
    return [
        finding
        for finding in DataFlowEngine(rules).analyze_file(
            ast.parse(code), code, "agent.py"
        )
        if finding.rule_id == "EUAIA-ART14-002"
    ]


@pytest.mark.parametrize(
    "body",
    [
        "cmd = model.generate()\ntry:\n    return\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    raise ValueError()\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\nwhile flag:\n    try:\n        break\n    finally:\n        cleanup()\n    os.system(cmd)",
        "cmd = model.generate()\nwhile flag:\n    try:\n        continue\n    finally:\n        cleanup()\n    os.system(cmd)",
        "cmd = ''\ntry:\n    if flag:\n        cmd = model.generate()\n        return\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    pass\nexcept:\n    return\nelse:\n    return\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    raise ValueError()\nexcept:\n    return\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    try:\n        return\n    finally:\n        inner_cleanup()\nfinally:\n    outer_cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    while flag:\n        break\n    cmd = ''\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    while flag:\n        continue\n    cmd = ''\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = ''\nwhile flag:\n    cmd = model.generate()\n    try:\n        break\n    finally:\n        return\nos.system(cmd)",
        "cmd = ''\nwhile flag:\n    os.system(cmd)\n    try:\n        cmd = model.generate()\n        continue\n    finally:\n        return",
        "cmd = ''\nwhile flag:\n    cmd = model.generate()\n    try:\n        break\n    finally:\n        cmd = ''\nos.system(cmd)",
        "cmd = ''\nwhile flag:\n    os.system(cmd)\n    try:\n        cmd = model.generate()\n        continue\n    finally:\n        cmd = ''",
    ],
    ids=[
        "return", "raise", "break", "continue", "separate-normal-path",
        "else-return", "handler-return", "nested-finally",
        "internal-break", "internal-continue", "finally-overrides-break",
        "finally-overrides-continue", "finally-clears-before-break",
        "finally-clears-before-continue",
    ],
)
def test_finally_does_not_revive_unreachable_or_stale_taint(
    body: str, rules: list[Rule]
) -> None:
    assert analyze(body, rules) == []


@pytest.mark.parametrize(
    "body",
    [
        "cmd = model.generate()\ntry:\n    pass\nfinally:\n    cleanup()\nos.system(cmd)",
        "cmd = model.generate()\ntry:\n    return\nfinally:\n    os.system(cmd)",
        "cmd = model.generate()\ntry:\n    raise ValueError()\nfinally:\n    os.system(cmd)",
        "cmd = model.generate()\nwhile flag:\n    try:\n        break\n    finally:\n        os.system(cmd)",
        "cmd = model.generate()\nwhile flag:\n    try:\n        continue\n    finally:\n        os.system(cmd)",
        "cmd = ''\nwhile flag:\n    try:\n        break\n    finally:\n        cmd = model.generate()\nos.system(cmd)",
        "cmd = ''\nwhile flag:\n    os.system(cmd)\n    try:\n        continue\n    finally:\n        cmd = model.generate()",
        "cmd = ''\nwhile flag:\n    cmd = model.generate()\n    try:\n        return\n    finally:\n        break\nos.system(cmd)",
        "cmd = ''\nwhile flag:\n    os.system(cmd)\n    cmd = model.generate()\n    try:\n        raise ValueError()\n    finally:\n        continue",
        "cmd = model.generate()\ntry:\n    try:\n        return\n    finally:\n        cleanup()\nfinally:\n    os.system(cmd)",
        "cmd = model.generate()\ntry:\n    if flag:\n        return\nfinally:\n    os.system(cmd)",
    ],
    ids=[
        "normal", "return", "raise", "break", "continue", "break-destination",
        "continue-destination", "finally-overrides-return",
        "finally-overrides-raise", "outer-finally", "deduplicate-finally",
    ],
)
def test_finally_preserves_reachable_findings(body: str, rules: list[Rule]) -> None:
    findings = analyze(body, rules)
    assert len(findings) == 1
    assert findings[0].flow_steps[0].step_type == "source"
    assert findings[0].flow_steps[-1].step_type == "sink"


def reachable_without_calls(start: CFGNode) -> set[CFGNode]:
    visited: set[CFGNode] = set()
    pending = [start]
    while pending:
        node = pending.pop()
        if node in visited:
            continue
        visited.add(node)
        if not isinstance(node.ast_node, ast.Expr):
            pending.extend(node.successors)
    return visited


@pytest.mark.parametrize("transfer", ["return", "raise ValueError()", "break", "continue"])
def test_abrupt_destination_cannot_bypass_finally(transfer: str) -> None:
    code = (
        "def agent(flag):\n"
        "    while flag:\n"
        "        try:\n"
        f"            {transfer}\n"
        "        finally:\n"
        "            cleanup()\n"
        "        unreachable()\n"
    )
    function = ast.parse(code).body[0]
    assert isinstance(function, ast.FunctionDef)
    graph = CFGBuilder().build_for_function(function)
    abrupt = next(
        node for node in graph.nodes
        if isinstance(node.ast_node, (ast.Return, ast.Raise, ast.Break, ast.Continue))
    )
    before_cleanup = reachable_without_calls(abrupt)
    assert graph.exit_node not in before_cleanup
    assert not any(
        isinstance(node.ast_node, ast.While) or node.label == "LOOP_EXIT"
        for node in before_cleanup
    )
    calls = [
        node.ast_node.value
        for node in graph.get_topological_order()
        if isinstance(node.ast_node, ast.Expr)
        and isinstance(node.ast_node.value, ast.Call)
    ]
    assert len(calls) == 1
    assert isinstance(calls[0].func, ast.Name)
    assert calls[0].func.id == "cleanup"
    for node in graph.nodes:
        assert all(node in successor.predecessors for successor in node.successors)
        assert all(node in predecessor.successors for predecessor in node.predecessors)
