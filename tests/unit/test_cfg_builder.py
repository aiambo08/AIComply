"""
AIComply - Unit Tests for CFG Builder & State Machine
"""

import ast
import pytest
from aicomply.dataflow.cfg_builder import CFGBuilder
from aicomply.dataflow.states import TaintEnvironment, TaintState, pessimistic_join


def test_pessimistic_join_lattice():
    # Soundness: Any tainted branch makes the union tainted
    assert pessimistic_join(TaintState.TAINTED_UNSAFE, TaintState.SANITIZED) == TaintState.TAINTED_UNSAFE
    assert pessimistic_join(TaintState.SANITIZED, TaintState.TAINTED_UNSAFE) == TaintState.TAINTED_UNSAFE
    assert pessimistic_join(TaintState.TAINTED_UNSAFE, TaintState.HUMAN_GATED) == TaintState.TAINTED_UNSAFE
    assert pessimistic_join(TaintState.TAINTED_UNSAFE, TaintState.CLEAN) == TaintState.TAINTED_UNSAFE

    # Both safe branches remain safe
    assert pessimistic_join(TaintState.SANITIZED, TaintState.SANITIZED) == TaintState.SANITIZED
    assert pessimistic_join(TaintState.SANITIZED, TaintState.HUMAN_GATED) == TaintState.SANITIZED
    assert pessimistic_join(TaintState.HUMAN_GATED, TaintState.HUMAN_GATED) == TaintState.HUMAN_GATED

    # Clean joins
    assert pessimistic_join(TaintState.CLEAN, TaintState.CLEAN) == TaintState.CLEAN
    assert pessimistic_join(TaintState.CLEAN, TaintState.SANITIZED) == TaintState.SANITIZED


def test_taint_environment_join():
    env1 = TaintEnvironment({"cmd": TaintState.TAINTED_UNSAFE, "other": TaintState.CLEAN})
    env2 = TaintEnvironment({"cmd": TaintState.SANITIZED, "other": TaintState.SANITIZED})

    joined = env1.join(env2)
    assert joined.get("cmd") == TaintState.TAINTED_UNSAFE
    assert joined.get("other") == TaintState.SANITIZED


def test_cfg_builder_if_else_phi_structure():
    code = """
def process(x):
    if x > 10:
        a = 1
    else:
        a = 2
    return a
"""
    tree = ast.parse(code)
    func_node = tree.body[0]
    builder = CFGBuilder()
    cfg = builder.build_for_function(func_node)

    phi_nodes = [n for n in cfg.nodes if n.is_phi]
    assert len(phi_nodes) == 1
    phi = phi_nodes[0]
    assert len(phi.predecessors) == 2  # Then branch and Else branch


def test_cfg_builder_human_gate_detection():
    code = """
def execute_plan(cmd, is_human_approved):
    if is_human_approved:
        run_cmd(cmd)
"""
    tree = ast.parse(code)
    func_node = tree.body[0]
    builder = CFGBuilder()
    cfg = builder.build_for_function(func_node)

    cond_nodes = [n for n in cfg.nodes if n.is_branch_condition]
    assert len(cond_nodes) == 1
    assert cond_nodes[0].is_human_gate is True
