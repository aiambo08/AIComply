"""HTTP regressions for the loopback console's untrusted-input boundary."""

import http.client
import json
import os
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aicomply.evidence.signer import generate_keypair, sign_scan_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine
from aicomply.ui import server as ui

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Safe console snapshots require POSIX")


@dataclass
class Console:
    server: ui.AIComplyHTTPServer
    root: Path

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.server.server_port}"

    def request(
        self, path: str = "/api/assess", body: bytes = b"{}", method: str = "POST",
        headers: list[tuple[str, str]] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for key, value in headers if headers is not None else [
                ("Host", self.host), ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ]:
                connection.putheader(key, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()


@pytest.fixture
def console(tmp_path: Path) -> Iterator[Console]:
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.py").write_text("import openai\n", encoding="utf-8")
    server = ui.start_ui_server(root, port=0, open_browser=False)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield Console(server, root)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.1", "::", "localhost.example.com"])
def test_non_loopback_bind_is_rejected(tmp_path: Path, host: str) -> None:
    with pytest.raises(ValueError, match="must bind"):
        ui.start_ui_server(tmp_path, host=host, port=0, open_browser=False)


@pytest.mark.parametrize("host", ["evil.example", "localhost.evil", "127.0.0.1", "127.0.0.1:1", "localhost@evil"])
def test_untrusted_host_cannot_read_console(console: Console, host: str) -> None:
    status, _, _ = console.request("/", method="GET", headers=[("Host", host)])
    assert status == 403


def test_missing_and_duplicate_host_are_rejected(console: Console) -> None:
    for headers in [[], [("Host", console.host), ("Host", console.host)]]:
        assert console.request("/", method="GET", headers=headers)[0] == 403


@pytest.mark.parametrize("origin", ["null", "https://evil.example", "http://localhost:1", "http://127.0.0.1:1"])
def test_cross_origin_request_is_rejected(console: Console, origin: str) -> None:
    status, headers, _ = console.request(headers=[
        ("Host", console.host), ("Origin", origin), ("Content-Type", "application/json"),
        ("Content-Length", "2"),
    ])
    assert status == 403
    assert "Access-Control-Allow-Origin" not in headers


def test_browser_same_origin_and_no_cors(console: Console) -> None:
    status, headers, body = console.request(headers=[
        ("Host", console.host), ("Origin", f"http://{console.host}"),
        ("Sec-Fetch-Site", "same-origin"), ("Content-Type", "application/json"),
        ("Content-Length", "2"),
    ])
    assert status == 200
    result = json.loads(body)
    assert result["provisional"] is True
    assert result["requires_review"] is True
    assert result["tier"] == "unknown"
    assert "Access-Control-Allow-Origin" not in headers
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in headers["Content-Security-Policy"]


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_fetch_metadata_blocks_other_sites(console: Console, site: str) -> None:
    assert console.request("/", method="GET", headers=[
        ("Host", console.host), ("Sec-Fetch-Site", site),
    ])[0] == 403


def test_preflight_has_no_cors(console: Console) -> None:
    status, headers, _ = console.request(method="OPTIONS")
    assert status == 405
    assert "Access-Control-Allow-Origin" not in headers


@pytest.mark.parametrize("body", [
    b"", b"{", b"[]", b"null", b'"string"', b'{"q1":"none","q1":"social_scoring"}',
    b'{"q1":NaN}', b'{"q1":Infinity}', b'{"q1":1e999}', b'{"q1":"\xff"}',
    b'{"q1":true}', b'{"q1":7}', b'{"q1":"invalid"}', b'{"extra":1}',
    b'{"name":""}', b'{"name":"' + b"x" * 201 + b'"}',
    b'{"q1":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
    b'{"q1":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}",
    b'{"q1":[' + b"0," * ui.MAX_JSON_NODES + b"0]}",
])
def test_invalid_json_or_schema_is_rejected(console: Console, body: bytes) -> None:
    status, _, response = console.request(body=body)
    assert status == 400
    assert "error" in json.loads(response)


@pytest.mark.parametrize(("extra", "expected"), [
    ([("Content-Length", str(ui.MAX_BODY_BYTES + 1))], 413),
    ([("Content-Length", "999999999999999999999999")], 413),
    ([("Content-Length", "-1")], 400),
    ([("Content-Length", "2"), ("Content-Length", "2")], 400),
    ([], 400),
    ([("Content-Length", "2"), ("Transfer-Encoding", "chunked")], 400),
    ([("Content-Length", "2"), ("Content-Encoding", "gzip")], 400),
])
def test_body_framing_is_bounded(console: Console, extra: list[tuple[str, str]], expected: int) -> None:
    assert console.request(headers=[
        ("Host", console.host), ("Content-Type", "application/json"), *extra,
    ])[0] == expected


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "application/json;charset=utf-16"])
def test_simple_cross_site_content_types_are_rejected(console: Console, content_type: str) -> None:
    assert console.request(headers=[
        ("Host", console.host), ("Content-Type", content_type), ("Content-Length", "2"),
    ])[0] == 415


def test_paths_are_confined_to_root(console: Console) -> None:
    outside = console.root.parent / "outside.py"
    outside.write_text("outside_marker = True\n", encoding="utf-8")
    for path in [str(outside), "../outside.py", str(console.root.parent)]:
        status, _, body = console.request("/api/scan", json.dumps({"path": path}).encode())
        assert status == 403
        assert b"outside_marker" not in body
    status, _, body = console.request("/api/scan", b'{"path":"app.py"}')
    assert status == 200
    assert json.loads(body)["target_path"] == str(console.root / "app.py")
    assert console.request("/api/docgen", json.dumps({"path": str(outside)}).encode())[0] == 400


@pytest.mark.parametrize("endpoint", ["/api/scan", "/api/docgen"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "oversized"])
def test_unsafe_tree_fails_closed(console: Console, endpoint: str, kind: str) -> None:
    path = console.root / "unsafe.py"
    outside = console.root.parent / "private.py"
    outside.write_text("OUTSIDE_PRIVATE_MARKER\n", encoding="utf-8")
    if kind == "symlink":
        path.symlink_to(outside)
        assert console.request("/api/scan", b'{"path":"unsafe.py"}')[0] == 403
    elif kind == "hardlink":
        os.link(outside, path)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        with path.open("wb") as stream:
            stream.truncate(2 * 1024 * 1024 + 1)
    status, _, body = console.request(endpoint)
    assert status == 422
    assert "error" in json.loads(body)
    assert b"OUTSIDE_PRIVATE_MARKER" not in body


def test_symlink_to_in_root_file_is_also_rejected(console: Console) -> None:
    (console.root / "alias.py").symlink_to(console.root / "app.py")
    assert console.request("/api/scan", b'{"path":"alias.py"}')[0] == 403


def test_root_descriptor_survives_path_replacement(console: Console) -> None:
    original = console.root.with_name("original")
    console.root.rename(original)
    console.root.mkdir()
    (console.root / "replacement.py").write_text("social_score = 42\n", encoding="utf-8")
    status, _, body = console.request("/api/scan")
    assert status == 200
    assert b"replacement.py" not in body
    assert json.loads(body)["summary"]["total_files_scanned"] == 1


def test_client_key_path_is_not_read(console: Console, tmp_path: Path) -> None:
    private_key, public_key, _ = generate_keypair(tmp_path, "test")
    report = ScanEngine(load_builtin_rules()).scan_path(console.root)
    bundle = sign_scan_report(report, private_key)
    payload = {"bundle": bundle.model_dump(), "public_key": str(public_key)}
    assert console.request("/api/verify", json.dumps(payload).encode())[0] == 400


def test_verifier_receives_validated_pem_bytes(console: Console, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    private_key, public_key, _ = generate_keypair(tmp_path, "test")
    report = ScanEngine(load_builtin_rules()).scan_path(console.root)
    bundle = sign_scan_report(report, private_key, signer_identity="<img src=x onerror=alert(1)>")
    observed: list[bytes] = []
    original = ui.verify_evidence_bundle

    def verify(bundle: ui.SignedEvidenceBundle, pem: bytes) -> tuple[bool, str]:
        assert isinstance(pem, bytes)
        observed.append(pem)
        return original(bundle, pem)

    monkeypatch.setattr(ui, "verify_evidence_bundle", verify)
    payload = {"bundle": bundle.model_dump(), "public_key": public_key.read_text()}
    status, _, response = console.request("/api/verify", json.dumps(payload).encode())
    assert status == 200
    result = json.loads(response)
    assert result["valid"] is True
    assert result["signer_id"] == bundle.signer_identity
    assert "legal correctness and trusted time are not established" in result["message"]
    assert observed == [public_key.read_bytes().strip()]
    payload["bundle"] = bundle.model_copy(update={"signature": "invalid"}).model_dump()
    status, _, response = console.request("/api/verify", json.dumps(payload).encode())
    assert status == 200
    assert json.loads(response)["valid"] is False


def test_non_ed25519_public_pem_is_rejected(console: Console) -> None:
    key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert console.request("/api/verify", json.dumps({"bundle": {}, "public_key": key.decode()}).encode())[0] == 400


def test_only_one_analysis_runs_at_once(console: Console) -> None:
    with console.server.job_lock:
        assert console.request("/api/scan")[0] == 429
        assert console.request("/api/docgen")[0] == 429
        assert console.request("/api/scan?format=sarif", method="GET")[0] == 429
        assert console.request()[0] == 200


def test_job_timeout_cleans_snapshot_and_releases_lock(console: Console, monkeypatch: pytest.MonkeyPatch) -> None:
    directories: list[Path] = []

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        payload = kwargs["input"]
        assert isinstance(payload, bytes)
        request = json.loads(payload)
        directories.append(Path(request["snapshot_dir"]))
        raise subprocess.TimeoutExpired("worker", 30)

    monkeypatch.setattr(ui.subprocess, "run", timeout)
    assert console.request("/api/scan")[0] == 504
    assert directories and all(not path.exists() for path in directories)
    assert console.server.job_lock.acquire(blocking=False)
    console.server.job_lock.release()


def test_unexpected_error_does_not_expose_exception(console: Console, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    def fail(*args: object, **kwargs: object) -> bytes:
        raise RuntimeError("private_source_or_key_material")

    monkeypatch.setattr(console.server, "run_job", fail)
    status, _, body = console.request("/api/scan")
    assert status == 500
    assert b"private_source_or_key_material" not in body
    assert "private_source_or_key_material" not in caplog.text


class AssetParser(HTMLParser):
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            assert not name.startswith("on")
            assert name != "style"
            if name in {"src", "href"}:
                assert value and value.startswith("/")
        if tag == "script":
            assert dict(attrs).get("src") == "/static/app.js"


def test_static_assets_are_offline_and_restrict_injection(console: Console) -> None:
    status, _, body = console.request("/", method="GET")
    assert status == 200
    AssetParser().feed(body.decode())
    status, _, script = console.request("/static/app.js", method="GET")
    assert status == 200
    for forbidden in [b"innerHTML", b"outerHTML", b"insertAdjacentHTML", b"eval(", b"https://", b"http://"]:
        assert forbidden not in script
    assert b"textContent" in script and b"replaceChildren" in script
    status, _, css = console.request("/static/app.css", method="GET")
    assert status == 200
    assert b"@import" not in css and b"url(" not in css
    assert console.request("/static/../../schemas.py", method="GET")[0] == 404
