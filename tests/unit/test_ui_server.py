"""Unit tests for AIComply Local Interactive UI Server."""

import json
import threading
import urllib.request
from pathlib import Path

import pytest

from aicomply.evidence.signer import generate_keypair, sign_scan_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine
from aicomply.ui.server import start_ui_server


@pytest.fixture(scope="module")
def ui_server(tmp_path_factory):
    target = tmp_path_factory.mktemp("ui_target")
    # Add a sample python file
    sample_file = target / "agent.py"
    sample_file.write_text("import openai\nres = openai.chat.completions.create(model='gpt-4')\n", encoding="utf-8")

    server = start_ui_server(target_path=target, host="127.0.0.1", port=8991, open_browser=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield "http://127.0.0.1:8991", target

    server.shutdown()
    server.server_close()


def test_ui_server_get_html(ui_server):
    base_url, _ = ui_server
    req = urllib.request.Request(f"{base_url}/")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "<!DOCTYPE html>" in content
        assert "AICOMPLY" in content
        assert "DataFlow Matrix" in content


def test_ui_server_api_scan_json(ui_server):
    base_url, target = ui_server
    req = urllib.request.Request(
        f"{base_url}/api/scan",
        data=json.dumps({"path": str(target)}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "findings" in data
        assert "scan_id" in data
        assert "summary" in data


def test_ui_server_api_scan_sarif(ui_server):
    base_url, _ = ui_server
    req = urllib.request.Request(f"{base_url}/api/scan?format=sarif")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("version") == "2.1.0"
        assert len(data.get("runs", [])) > 0


def test_ui_server_api_assess(ui_server):
    base_url, _ = ui_server
    # Test prohibited
    req_proh = urllib.request.Request(
        f"{base_url}/api/assess",
        data=json.dumps({"name": "TestSys", "q1": "social_scoring"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_proh) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert res.get("tier") == "prohibited"

    # Test high risk
    req_hr = urllib.request.Request(
        f"{base_url}/api/assess",
        data=json.dumps({"name": "TestSys", "q1": "none", "q2": "credit_scoring"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_hr) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert res.get("tier") == "high_risk"


def test_ui_server_api_verify(ui_server, tmp_path):
    base_url, target = ui_server
    # Generate keys and signed report
    priv_key, pub_key, _ = generate_keypair(tmp_path, "test_signer")
    engine = ScanEngine(catalog=load_builtin_rules())
    report = engine.scan_path(target)
    bundle = sign_scan_report(report, priv_key, signer_identity="auditor@firm.com")

    # Verify valid
    req = urllib.request.Request(
        f"{base_url}/api/verify",
        data=json.dumps({
            "bundle": bundle.model_dump(),
            "public_key": pub_key.read_text(encoding="utf-8"),
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert res.get("valid") is True
        assert res.get("signer_id") == "auditor@firm.com"


def test_ui_server_api_docgen(ui_server):
    base_url, _ = ui_server
    req = urllib.request.Request(
        f"{base_url}/api/docgen",
        data=json.dumps({"name": "FintechModel", "version": "2.0.0"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert "markdown" in res
        assert "FintechModel" in res["markdown"]
