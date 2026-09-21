"""Synthetic client projects: source is parsed, never imported or executed."""

import json
from pathlib import Path
from textwrap import indent

import pytest

from aicomply.reporter.sarif_reporter import generate_sarif_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine


SDK_CALLS = [
    ("from openai import OpenAI as AI\nclient = AI()", "client.chat.completions.create()", False),
    ("from openai import OpenAI as AI\nclient = AI()", "client.responses.create()", False),
    ("from openai import AsyncOpenAI\nclient = AsyncOpenAI()", "await client.responses.create()", True),
    ("from openai import AsyncOpenAI\nclient = AsyncOpenAI()", "await client.chat.completions.create()", True),
    ("from openai import AzureOpenAI\nclient = AzureOpenAI()", "client.chat.completions.create()", False),
    ("from openai import AzureOpenAI\nclient = AzureOpenAI()", "client.responses.create()", False),
    ("from openai import AsyncAzureOpenAI\nclient = AsyncAzureOpenAI()", "await client.responses.create()", True),
    ("from openai import AsyncAzureOpenAI\nclient = AsyncAzureOpenAI()", "await client.chat.completions.create()", True),
    ("import openai", "openai.responses.create()", False),
    ("from anthropic import Anthropic as AI\nclient = AI()", "client.messages.create()", False),
    ("from anthropic import AsyncAnthropic\nclient = AsyncAnthropic()", "await client.messages.create()", True),
    ("from google import genai\nclient = genai.Client()", "client.models.generate_content()", False),
    ("from google import genai\nclient = genai.Client()", "await client.aio.models.generate_content()", True),
]


@pytest.fixture
def engine() -> ScanEngine:
    return ScanEngine(load_builtin_rules())


@pytest.mark.parametrize("setup,call,is_async", SDK_CALLS)
@pytest.mark.parametrize(
    "sink,rule_id",
    [
        ("subprocess.run(result.output_text, shell=True)", "EUAIA-ART14-002"),
        ("return jsonify(result.content)", "EUAIA-ART50-003"),
    ],
)
def test_sdk_outputs_reach_reviewable_sinks(
    tmp_path: Path, engine: ScanEngine, setup: str, call: str, is_async: bool,
    sink: str, rule_id: str,
) -> None:
    source = tmp_path / "service.py"
    source.write_text(
        "import subprocess\nfrom flask import jsonify\n"
        + ("async " if is_async else "") + "def handle():\n"
        + indent(f"{setup}\nresult = {call}\n{sink}\n", "    "),
        encoding="utf-8",
    )
    report = engine.scan_path(source)
    flows = [finding for finding in report.findings if finding.rule_id == rule_id]
    assert len(flows) == 1
    assert flows[0].flow_steps[0].step_type == "source"
    assert flows[0].flow_steps[-1].step_type == "sink"
    assert flows[0].location.file_path == "service.py"
    assert flows[0].remediation
    assert report.legal_assessment == "not_assessed"
    assert any(f.rule_id == "EUAIA-ART12-001" for f in report.findings)
    sarif = json.loads(generate_sarif_report(report))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == rule_id)
    assert len(result["codeFlows"][0]["threadFlows"][0]["locations"]) >= 2


@pytest.mark.parametrize("setup,call,is_async", SDK_CALLS)
def test_fixed_action_selection_does_not_execute_model_text(
    tmp_path: Path, engine: ScanEngine, setup: str, call: str, is_async: bool,
) -> None:
    source = tmp_path / "bounded.py"
    source.write_text(
        "import subprocess\n"
        + ("async " if is_async else "") + "def handle():\n"
        + indent(
            f"{setup}\nresult = {call}\n"
            "if result.output_text == 'status':\n"
            "    subprocess.run(['service', 'status'], shell=False)\n",
            "    ",
        ),
        encoding="utf-8",
    )
    report = engine.scan_path(source)
    assert not any(f.rule_id == "EUAIA-ART14-002" for f in report.findings)
    assert report.legal_assessment == "not_assessed"


@pytest.mark.parametrize("call", ["client.responses.create()", "client.models.generate_content()"])
def test_unrelated_clients_are_not_assumed_to_be_ai(
    tmp_path: Path, engine: ScanEngine, call: str,
) -> None:
    source = tmp_path / "unrelated.py"
    source.write_text(
        "from internal_inventory import Client\nimport subprocess\n"
        f"client = Client()\nresult = {call}\nsubprocess.run(result, shell=True)\n",
        encoding="utf-8",
    )
    assert not any(
        f.rule_id in {"EUAIA-ART14-002", "EUAIA-ART50-003", "EUAIA-ART12-001"}
        for f in engine.scan_path(source).findings
    )
