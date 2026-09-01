"""
AIComply - Unit Tests for DataFlow & Taint Engine
Valida el rastreo de fuentes (LLMs), resolución de alias, compuertas humanas,
operador pesimista de unión (⊔) y trazas de flujo (FlowStep).
"""

import ast
from pathlib import Path
import pytest
from aicomply.dataflow.taint_engine import DataFlowEngine
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.ast_parser import PythonASTScanner


@pytest.fixture
def rules():
    rules_path = Path(__file__).parents[2] / "src" / "aicomply" / "rules" / "eu_ai_act"
    catalog = load_rules_from_dir(rules_path)
    return catalog.rules


def test_taint_unvalidated_tool_execution(rules):
    code = """
import os
import openai

def autonomous_agent():
    response = openai.chat.completions.create(model="gpt-4o", messages=[])
    cmd = response.choices[0].message.content
    os.system(cmd)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules)
    findings = engine.analyze_file(tree, code, "agent.py")

    assert len(findings) >= 1
    f = [f for f in findings if f.rule_id == "EUAIA-ART14-002"][0]
    assert "os.system" in f.message
    assert f.flow_steps is not None
    assert len(f.flow_steps) == 3
    assert f.flow_steps[0].step_type == "source"
    assert f.flow_steps[1].step_type == "propagation"
    assert f.flow_steps[2].step_type == "sink"


def test_taint_alias_resolution(rules):
    code = """
import subprocess
from openai import OpenAI

def run_task():
    client = OpenAI()
    result = client.chat.completions.create(model="gpt-4o", messages=[])
    task_str = result.choices[0].message.content
    subprocess.run(task_str, shell=True)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules, aliases={"client": "openai.OpenAI"})
    findings = engine.analyze_file(tree, code, "agent.py", aliases={"client": "openai.OpenAI"})

    assert len(findings) >= 1
    assert any(f.rule_id == "EUAIA-ART14-002" for f in findings)


def test_taint_sanitization_prevents_violation(rules):
    code = """
import os
import openai
import guardrails

def safe_agent():
    response = openai.chat.completions.create(model="gpt-4o", messages=[])
    raw_cmd = response.choices[0].message.content
    clean_cmd = guardrails.validate(raw_cmd)
    os.system(clean_cmd)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules)
    findings = engine.analyze_file(tree, code, "agent.py")

    # Al haber sido saneado con guardrails.validate, no debe existir finding para clean_cmd
    art14_findings = [f for f in findings if f.rule_id == "EUAIA-ART14-002"]
    assert len(art14_findings) == 0


def test_pessimistic_join_flags_partial_sanitization(rules):
    """
    Si solo una rama del if/else sanea la variable, la convergencia (⊔)
    debe mantener el estado TAINTED_UNSAFE y disparar el hallazgo.
    """
    code = """
import os
import openai
import guardrails

def conditionally_unsafe(flag):
    response = openai.chat.completions.create(model="gpt-4o", messages=[])
    cmd = response.choices[0].message.content
    
    if flag:
        cmd = guardrails.validate(cmd)
    else:
        # Rama sin saneamiento
        pass
        
    os.system(cmd)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules)
    findings = engine.analyze_file(tree, code, "agent.py")

    art14_findings = [f for f in findings if f.rule_id == "EUAIA-ART14-002"]
    assert len(art14_findings) >= 1


def test_pessimistic_join_passes_when_all_branches_sanitized(rules):
    """
    Si el 100% de las ramas de bifurcación sanean la variable,
    la convergencia (⊔) es SANITIZED y no dispara hallazgo.
    """
    code = """
import os
import openai
import guardrails

def fully_safe(flag):
    response = openai.chat.completions.create(model="gpt-4o", messages=[])
    cmd = response.choices[0].message.content
    
    if flag:
        cmd = guardrails.validate(cmd)
    else:
        cmd = guardrails.validate(cmd)
        
    os.system(cmd)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules)
    findings = engine.analyze_file(tree, code, "agent.py")

    art14_findings = [f for f in findings if f.rule_id == "EUAIA-ART14-002"]
    assert len(art14_findings) == 0


def test_human_in_the_loop_gate_prevents_violation(rules):
    code = """
import os
import openai

def gated_agent(is_human_approved):
    response = openai.chat.completions.create(model="gpt-4o", messages=[])
    cmd = response.choices[0].message.content
    
    if is_human_approved:
        os.system(cmd)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules)
    findings = engine.analyze_file(tree, code, "agent.py")

    art14_findings = [f for f in findings if f.rule_id == "EUAIA-ART14-002"]
    assert len(art14_findings) == 0


def test_art50_synthetic_output_taint(rules):
    code = """
import openai
from flask import jsonify

def chat_api():
    response = openai.chat.completions.create(model="gpt-4o", messages=[])
    text = response.choices[0].message.content
    return jsonify(text)
"""
    tree = ast.parse(code)
    engine = DataFlowEngine(rules)
    findings = engine.analyze_file(tree, code, "api.py")

    art50_findings = [f for f in findings if f.rule_id == "EUAIA-ART50-003"]
    assert len(art50_findings) >= 1
