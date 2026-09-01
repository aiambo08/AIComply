"""AIComply Built-in Local UI Web Server.

Provides a zero-dependency, high-assurance local compliance cockpit serving
interactive data flow graphs, SARIF codeFlows, statutory decision wizards,
and Ed25519 cryptographic verification.
"""

from __future__ import annotations

import http.server
import json
import logging
import threading
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from aicomply.evidence.signer import compute_public_key_fingerprint, verify_evidence_bundle
from aicomply.generator.annex_iv import AnnexIVGenerator
from aicomply.reporter.sarif_reporter import generate_sarif_report
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner.engine import ScanEngine
from aicomply.schemas import SignedEvidenceBundle

logger = logging.getLogger(__name__)


class AIComplyHTTPServer(http.server.ThreadingHTTPServer):
    """Threading HTTP Server holding contextual server metadata."""

    def __init__(self, server_address: tuple[str, int], target_path: Path):
        super().__init__(server_address, AIComplyUIHandler)
        self.target_path = target_path.resolve()


class AIComplyUIHandler(http.server.BaseHTTPRequestHandler):
    """Request handler for AIComply interactive console."""

    server: AIComplyHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress noisy default console logging."""
        return

    def _send_json_response(self, data: Any, status_code: int = 200) -> None:
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html_response(self, html_content: str, status_code: int = 200) -> None:
        payload = html_content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html", "/app"):
            static_html_path = Path(__file__).parent / "static" / "app.html"
            if static_html_path.exists():
                self._send_html_response(static_html_path.read_text(encoding="utf-8"))
            else:
                self._send_json_response({"error": "app.html not found"}, status_code=404)
            return

        if path == "/api/scan":
            query = parse_qs(parsed.query)
            if query.get("format", [""])[0] == "sarif":
                engine = ScanEngine(catalog=load_builtin_rules())
                report = engine.scan_path(self.server.target_path)
                sarif_json = generate_sarif_report(report)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="aicomply-results.sarif"')
                self.end_headers()
                self.wfile.write(sarif_json.encode("utf-8"))
                return

        self._send_json_response({"error": "Not Found"}, status_code=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}

        if path == "/api/scan":
            target = Path(payload.get("path", self.server.target_path))
            if not target.is_absolute():
                target = (self.server.target_path / target).resolve()

            engine = ScanEngine(catalog=load_builtin_rules())
            report = engine.scan_path(target)
            self._send_json_response(report.model_dump())
            return

        if path == "/api/verify":
            bundle_dict = payload.get("bundle")
            pubkey_pem = payload.get("public_key") or ""

            if not bundle_dict:
                self._send_json_response({"valid": False, "error": "No evidence bundle provided"}, status_code=400)
                return

            try:
                bundle = SignedEvidenceBundle.model_validate(bundle_dict)
                is_valid, msg = verify_evidence_bundle(bundle, pubkey_pem if pubkey_pem.strip() else None)
                fingerprint = bundle.public_key_fingerprint
                if pubkey_pem.strip():
                    fingerprint = compute_public_key_fingerprint(pubkey_pem)

                self._send_json_response({
                    "valid": is_valid,
                    "message": msg,
                    "signer_id": bundle.signer_identity,
                    "signed_at": bundle.timestamp,
                    "scan_id": bundle.report.scan_id,
                    "fingerprint": fingerprint,
                })
            except Exception as e:
                self._send_json_response({"valid": False, "error": str(e)})
            return

        if path == "/api/assess":
            q1 = payload.get("q1", "none")
            q2 = payload.get("q2", "none")
            q3 = payload.get("q3", "none")

            if q1 != "none":
                res = {
                    "tier": "prohibited",
                    "tier_badge": "PROHIBITED (ART. 5)",
                    "badge_class": "bg-hazard-crimson/20 border-hazard-crimson text-red-300",
                    "title": "PROHIBITED AI PRACTICE (§ Art. 5(1))",
                    "obligations": [
                        {"article": "Art. 5(1)", "desc": "Strict market prohibition across the European Union."},
                        {"article": "Art. 99(3)", "desc": "Maximum statutory sanction up to €35,000,000 or 7% global turnover."},
                        {"article": "Remediation", "desc": "Decommission algorithm or remove prohibited feature immediately."}
                    ]
                }
            elif q2 != "none":
                res = {
                    "tier": "high_risk",
                    "tier_badge": "HIGH RISK (ART. 6)",
                    "badge_class": "bg-alert-amber/20 border-alert-amber text-amber-300",
                    "title": "HIGH-RISK AI SYSTEM (§ Art. 6 & Annex III)",
                    "obligations": [
                        {"article": "Art. 9 (Risk Management)", "desc": "Implement continuous testing, error logging, and risk mitigations."},
                        {"article": "Art. 11 & Annex IV", "desc": "Maintain detailed Technical Documentation dossier prior to deployment."},
                        {"article": "Art. 12 (Automatic Logging)", "desc": "Record model operations and inputs/outputs automatically."},
                        {"article": "Art. 14 (Human Oversight)", "desc": "Implement mandatory human authorization gate or override control."},
                        {"article": "Art. 15 (Cybersecurity & Robustness)", "desc": "Secure container infrastructure, enforce TLS, and prevent prompt injection."}
                    ]
                }
            elif q3 != "none":
                res = {
                    "tier": "limited_risk",
                    "tier_badge": "LIMITED RISK (ART. 50)",
                    "badge_class": "bg-neon-cyan/20 border-neon-cyan text-cyan-300",
                    "title": "LIMITED RISK / TRANSPARENCY (§ Art. 50)",
                    "obligations": [
                        {"article": "Art. 50(1)", "desc": "Explicitly inform natural persons that they are interacting with an AI system."},
                        {"article": "Art. 50(2)", "desc": "Mark synthetic audio/video/text in a machine-readable format and disclose artificial generation."}
                    ]
                }
            else:
                res = {
                    "tier": "minimal_risk",
                    "tier_badge": "MINIMAL RISK",
                    "badge_class": "bg-cyber-emerald/20 border-cyber-emerald text-cyber-emerald",
                    "title": "MINIMAL / NO SPECIFIC STATUTORY RISK",
                    "obligations": [
                        {"article": "Voluntary Code of Conduct", "desc": "Adhere to ethical AI guidelines and standard GDPR data protection principles."}
                    ]
                }

            self._send_json_response(res)
            return

        if path == "/api/docgen":
            sys_name = payload.get("name", "AIComply-Target-System")
            version = payload.get("version", "2.0.0")

            engine = ScanEngine(catalog=load_builtin_rules())
            report = engine.scan_path(self.server.target_path)
            docgen = AnnexIVGenerator(report, system_name=sys_name, version=version)
            md = docgen.generate_markdown_dossier()

            self._send_json_response({"markdown": md})
            return

        self._send_json_response({"error": "Not Found"}, status_code=404)


def start_ui_server(
    target_path: Path,
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = True,
) -> AIComplyHTTPServer:
    """Instantiate and start the AIComply interactive UI server."""
    server = AIComplyHTTPServer((host, port), target_path=target_path)
    url = f"http://{host}:{port}"
    logger.info("AIComply UI Server running at %s", url)

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    return server
