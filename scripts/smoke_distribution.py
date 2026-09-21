"""Exercise an installed distribution with synthetic, unexecuted client code."""

import argparse
from importlib.metadata import distribution
from importlib.resources import files
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import aicomply
from aicomply.classifier.assess import SystemContext, assess_context
from aicomply.rules.loader import load_builtin_rules


def cli(directory: Path, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, "-I", "-m", "aicomply.cli", *args],
        cwd=directory, capture_output=True, text=True, encoding="utf-8", timeout=45,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"{args[0]}: expected exit {expected}, got {result.returncode}\n"
            + result.stdout + result.stderr
        )
    return result.stdout


def check_install(expected_version: str) -> None:
    installed = distribution("aicomply-cli")
    assert installed.version == expected_version, installed.version
    assert Path(aicomply.__file__).resolve().is_relative_to(Path(sys.prefix))
    assert load_builtin_rules().rules
    for name in ("app.html", "app.js", "app.css"):
        assert files("aicomply").joinpath("ui/static", name).read_bytes()
    assert {"aicomply", "aicomply-cli"} <= {e.name for e in installed.entry_points}
    for entry in ("aicomply", "aicomply-cli"):
        executable = Path(sys.executable).parent / (
            entry + ".exe" if os.name == "nt" else entry
        )
        subprocess.run([str(executable), "--help"], check=True, capture_output=True, timeout=30)


def check_scenarios(directory: Path) -> None:
    client = directory / "client project"
    client.mkdir()
    source = client / "service.py"
    source.write_text("raise RuntimeError('Client code must never run')\n", encoding="utf-8")
    report = json.loads(cli(directory, "scan", str(client), "--format", "json"))
    assert report["findings"] == []
    assert report["legal_assessment"] == "not_assessed"
    assert report["analysis_status"] == "completed"
    assert len(report["source_manifest"]) == 1
    original_hash = report["source_manifest_hash"]

    source.write_text(
        "import subprocess\n"
        "from openai import AsyncOpenAI\n"
        "async def handle():\n"
        "    client = AsyncOpenAI()\n"
        "    result = await client.responses.create(input='synthetic')\n"
        "    subprocess.run(result.output_text, shell=True)\n",
        encoding="utf-8",
    )
    report = json.loads(cli(directory, "scan", str(client), "--format", "json", expected=1))
    ids = {finding["rule_id"] for finding in report["findings"]}
    assert {"EUAIA-ART14-002", "EUAIA-ART12-001"} <= ids
    assert report["source_manifest_hash"] != original_hash
    sarif = json.loads(cli(directory, "scan", str(client), "--format", "sarif", expected=1))
    assert sarif["version"] == "2.1.0"
    flow = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "EUAIA-ART14-002")
    assert len(flow["codeFlows"][0]["threadFlows"][0]["locations"]) >= 2
    markdown = cli(directory, "scan", str(client), "--format", "markdown", expected=1)
    assert "EUAIA-ART14-002" in markdown

    dossier = directory / "annex.md"
    cli(directory, "docgen", str(client), "--name", "Synthetic assistant", "--output", str(dossier))
    assert dossier.read_text(encoding="utf-8").count("## SECCIÓN ") == 9
    assert "Clasificación jurídica: PENDIENTE" in dossier.read_text(encoding="utf-8")

    keys = directory / "keys"
    cli(directory, "keygen", "--out-dir", str(keys), "--name", "reviewer")
    evidence = directory / "signed.json"
    cli(directory, "scan", str(client), "--format", "json", "--sign",
        "--key", str(keys / "reviewer.pem"), "--output", str(evidence), expected=1)
    cli(directory, "verify", str(evidence), "--public-key", str(keys / "reviewer.pub"))
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["report"]["target_path"] = "tampered"
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    cli(directory, "verify", str(evidence), "--public-key", str(keys / "reviewer.pub"), expected=1)

    source.write_text(
        "import logging\nimport subprocess\nfrom openai import OpenAI\n"
        "client = OpenAI()\nresult = client.responses.create(input='synthetic')\n"
        "if result.output_text == 'status':\n"
        "    subprocess.run(['service', 'status'], shell=False)\n",
        encoding="utf-8",
    )
    report = json.loads(cli(directory, "scan", str(client), "--format", "json"))
    assert report["findings"] == []
    assert report["legal_assessment"] == "not_assessed"

    for validator, value in (
        ("ToolSchema.model_validate({'command': raw})", "parsed.command"),
        ("ToolSchema.model_validate_json(raw)", "parsed.command"),
        ("pydantic(raw)", "parsed"),
        ("is_safe_command(command=raw)", "parsed"),
        ("human_gate(raw)", "parsed"),
    ):
        source.write_text(
            "import logging\nimport os\nfrom openai import OpenAI\n"
            "from pydantic import BaseModel\n"
            "from client_controls import pydantic, is_safe_command, human_gate\n"
            "class ToolSchema(BaseModel):\n"
            "    command: str\n"
            "client = OpenAI()\nraw = client.responses.create().output_text\n"
            f"parsed = {validator}\nos.system({value})\n",
            encoding="utf-8",
        )
        report = json.loads(cli(directory, "scan", str(client), "--format", "json", expected=1))
        flow, = [f for f in report["findings"] if f["rule_id"] == "EUAIA-ART14-002"]
        assert [step["step_type"] for step in flow["flow_steps"]] == [
            "source", "propagation", "sink",
        ]
        assert report["legal_assessment"] == "not_assessed"

    source.write_text(
        "prompt = 'DNI ficticio 12345678Z'\n"
        "import requests\nrequests.post('https://example.invalid', verify=False)\n",
        encoding="utf-8",
    )
    report = json.loads(cli(directory, "scan", str(client), "--format", "json", expected=1))
    assert {"GDPR-ART05-002", "GDPR-ART32-002"} <= {f["rule_id"] for f in report["findings"]}
    config = client / ".aicomply.yaml"
    config.write_text("unknown_policy: true\n", encoding="utf-8")
    failed_report = directory / "failed.json"
    cli(directory, "scan", str(client), "--format", "json", "--output", str(failed_report), expected=2)
    assert not failed_report.exists()
    config.unlink()
    source.write_text("def broken(:\n", encoding="utf-8")
    cli(directory, "scan", str(client), "--format", "json", "--output", str(failed_report), expected=2)
    assert not failed_report.exists()

    for purpose in ("Evaluación de solvencia", "Clasificación de candidaturas"):
        assessment = assess_context(SystemContext(
            intended_purpose=purpose, role="deployer", is_ai=True, eu_scope=True,
            annex_iii_use=True, profiling=True, personal_data=True,
            solely_automated_significant_decision=True,
        ))
        assert {"Art. 26", "RGPD Art. 22"} <= set(assessment.applicable_articles)
        assert assessment.status == "requires_review"
    assert assess_context(SystemContext()).risk_tier is None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    check_install(args.expected_version)
    with tempfile.TemporaryDirectory(prefix="aicomply-smoke-", dir=Path.cwd()) as scratch:
        check_scenarios(Path(scratch))
    print(f"Installed {args.expected_version}: client scenarios, evidence and entry points passed.")


if __name__ == "__main__":
    main()
