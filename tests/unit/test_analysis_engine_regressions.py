import ast
from pathlib import Path
from textwrap import dedent

import pytest

from aicomply.dataflow.taint_engine import DataFlowEngine
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.ast_parser import PythonASTScanner


@pytest.fixture
def rules():
    return load_builtin_rules().rules


def analyze(body, rules):
    code = "async def agent(flag=True, is_human_approved=False):\n"
    code += "\n".join(f"    {line}" for line in dedent(body).strip().splitlines())
    findings = DataFlowEngine(rules).analyze_file(ast.parse(code), code, "agent.py")
    return [f for f in findings if f.rule_id == "EUAIA-ART14-002"]


@pytest.mark.parametrize(
    "body",
    [
        "cmd = await model.generate()\nos.system(cmd)",
        "cmd = str(model.generate())\nos.system(cmd)",
        "os.system(model.generate())",
        "os.system(command=await model.generate())",
        "cmd = ''\ncmd += model.generate()\nos.system(cmd)",
        "cmd, other = model.generate(), ''\nos.system(cmd)",
        "cmd = [model.generate() for _ in range(2)]\nos.system(cmd[0])",
        "if (cmd := model.generate()):\n    os.system(cmd)",
        "cmd = ''\nwhile flag:\n    os.system(cmd)\n    cmd = model.generate()",
        "cmd = ''\nfor _ in range(2):\n    os.system(cmd)\n    cmd = model.generate()",
        "for cmd in [model.generate()]:\n    os.system(cmd)",
        "async for cmd in model.generate():\n    os.system(cmd)",
        "cmd = model.generate()\nfor _ in []:\n    cmd = ''\nos.system(cmd)",
        "cmd = model.generate()\nguardrails.validate(cmd)\nos.system(cmd)",
        "cmd = model.generate()\nclean = guardrails.validate(cmd)\nos.system(cmd)",
        "cmd = model.generate()\ncmd = not_guardrails.validate(cmd)\nos.system(cmd)",
        "cmd = model.generate()\nif is_human_approved:\n    os.system(cmd)",
        "cmd = model.generate()\nif not is_human_approved:\n    os.system(cmd)",
        "cmd = model.generate()\nif is_human_approved:\n    pass\nelse:\n    os.system(cmd)",
        "cmd = model.generate()\nif is_human_approved or flag:\n    os.system(cmd)",
        "with resource():\n    cmd = model.generate()\n    os.system(cmd)",
        "cmd = model.generate()\ntry:\n    pass\nfinally:\n    os.system(cmd)",
        "cmd = model.generate()\ntry:\n    return\nfinally:\n    os.system(cmd)",
        "cmd = model.generate()\ntry:\n    raise ValueError()\nexcept:\n    return\nfinally:\n    os.system(cmd)",
        "cmd = ''\nwhile flag:\n    cmd = model.generate()\n    break\nos.system(cmd)",
        "cmd = ''\nwhile flag:\n    os.system(cmd)\n    cmd = model.generate()\n    continue",
        "cmd = model.generate()\nwhile flag:\n    break\nelse:\n    cmd = ''\nos.system(cmd)",
    ],
)
def test_unsafe_flows_are_reported(body, rules):
    findings = analyze(body, rules)
    assert len(findings) == 1
    assert findings[0].flow_steps[0].step_type == "source"
    assert findings[0].flow_steps[-1].step_type == "sink"


@pytest.mark.parametrize(
    "body",
    [
        "cmd = model.generate()\ncmd = 'fixed'\nos.system(cmd)",
        "cmd = model.generate()\ncmd = guardrails.validate(cmd)\nos.system(cmd)",
        "cmd = model.generate()\nos.system(guardrails.validate(cmd))",
        "cmd = model.generate()\nreturn\nos.system(cmd)",
        "cmd = model.generate()\nif flag:\n    return\nelse:\n    cmd = ''\nos.system(cmd)",
    ],
)
def test_reassignment_and_termination_do_not_leave_stale_taint(body, rules):
    assert analyze(body, rules) == []


def test_alias_keeps_original_taint_after_reassignment(rules):
    findings = analyze(
        "cmd = model.generate()\ncopy = cmd\ncmd = ''\nos.system(copy)", rules
    )
    assert len(findings) == 1
    assert [s.step_type for s in findings[0].flow_steps] == [
        "source", "propagation", "sink"
    ]


def test_unsafe_branch_trace_is_not_replaced_by_sanitized_branch(rules):
    findings = analyze(
        """
        cmd = model.generate()
        if flag:
            cmd = guardrails.validate(cmd)
        os.system(cmd)
        """,
        rules,
    )
    assert len(findings) == 1
    assert all(step.step_type != "sanitizer" for step in findings[0].flow_steps)


def test_scanner_aliases_do_not_leak_between_files(tmp_path: Path, rules):
    first = tmp_path / "first.py"
    first.write_text("import other as model\n", encoding="utf-8")
    second = tmp_path / "second.py"
    second.write_text("cmd = model.generate()\nos.system(cmd)\n", encoding="utf-8")
    scanner = PythonASTScanner(rules)
    scanner.scan_file(first)
    findings = scanner.scan_file(second)
    assert any(f.rule_id == "EUAIA-ART14-002" for f in findings)


def test_scanner_resolves_calls_before_later_alias_reassignment(tmp_path: Path, rules):
    path = tmp_path / "agent.py"
    path.write_text(
        "import openai as ai\ncmd = ai.chat.completions.create()\n"
        "os.system(cmd)\nai = other_client\n",
        encoding="utf-8",
    )
    findings = PythonASTScanner(rules).scan_file(path)
    assert any(f.rule_id == "EUAIA-ART14-002" for f in findings)


def test_function_local_alias_does_not_shadow_other_function(tmp_path: Path, rules):
    path = tmp_path / "agent.py"
    path.write_text(
        "import openai as ai\n"
        "def unrelated():\n    ai = other_client\n"
        "def agent():\n    cmd = ai.chat.completions.create()\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    findings = PythonASTScanner(rules).scan_file(path)
    assert any(f.rule_id == "EUAIA-ART14-002" for f in findings)


@pytest.mark.parametrize(
    "code",
    [
        "def agent(default=compute_social_score()):\n    pass\n",
        "@decorate(compute_social_score())\ndef agent():\n    pass\n",
        "mapping[compute_social_score()] = 0\n",
    ],
)
def test_alias_scope_changes_preserve_call_visits(tmp_path: Path, rules, code):
    path = tmp_path / "agent.py"
    path.write_text(code, encoding="utf-8")
    assert any(
        finding.rule_id == "EUAIA-ART05-002"
        for finding in PythonASTScanner(rules).scan_file(path)
    )
