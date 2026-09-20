"""Loopback-only console for local source review; not an authenticated service."""

from __future__ import annotations

import http.server
import json
import logging
import math
import os
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from aicomply.classifier.assess import SystemContext, assess_context
from aicomply.evidence.signer import compute_public_key_fingerprint, verify_evidence_bundle
from aicomply.schemas import SignedEvidenceBundle

logger = logging.getLogger(__name__)
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
REQUEST_TIMEOUT = 5
JOB_TIMEOUT = 30
MAX_CONNECTIONS = 8
STATIC_DIR = Path(__file__).parent / "static"


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ScanRequest(RequestModel):
    path: str | None = Field(default=None, min_length=1, max_length=4096)


class VerifyRequest(RequestModel):
    bundle: dict[str, JsonValue] | str
    public_key: str = Field(min_length=1, max_length=4096)


class AssessRequest(RequestModel):
    context: SystemContext | None = None
    name: str = Field(default="AI System", min_length=1, max_length=200)
    q1: Literal[
        "none", "social_scoring", "emotion_workplace",
        "biometric_scraping", "subliminal_manipulation",
    ] = "none"
    q2: Literal[
        "none", "recruitment", "credit_scoring", "critical_infra", "biometric_id",
    ] = "none"
    q3: Literal["none", "text_gen", "chat_interaction"] = "none"


class DocgenRequest(RequestModel):
    name: str = Field(default="AIComply-Target-System", min_length=1, max_length=200)
    version: str = Field(default="unspecified", min_length=1, max_length=64)


def _json_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON value")


def _check_json_limits(value: JsonValue) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_NODES:
            raise RequestError(400, "JSON structure exceeds console limits")
        if isinstance(item, float) and not math.isfinite(item):
            raise RequestError(400, "Non-finite JSON values are not allowed")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def provisional_assessment(request: AssessRequest) -> dict[str, JsonValue]:
    context = request.context or SystemContext(
        system_name=request.name,
        prohibited_practice=True if request.q1 != "none" else None,
        annex_iii_use=True if request.q2 != "none" else None,
        transparency=True if request.q3 != "none" else None,
    )
    result = assess_context(context)
    tier = result.risk_tier.value if result.risk_tier else "unknown"
    concerns: list[JsonValue] = [
        {"article": "Review", "desc": obligation} for obligation in result.obligations
    ]
    concerns.extend([
        {"article": "Pending context", "desc": ", ".join(result.missing_context)},
        {"article": "Timeline", "desc": result.compliance_deadline},
        {"article": "Sources", "desc": "\n".join(result.sources)},
        {"article": "Review date", "desc": result.reviewed_on},
    ])
    return {
        "tier": tier, "tier_badge": "PROVISIONAL — NOT A LEGAL CONCLUSION",
        "badge_class": "bg-alert-amber/20 border-alert-amber text-amber-300",
        "title": f"{tier.upper()} — REQUIERE REVISIÓN", "obligations": concerns,
        "provisional": True, "requires_review": True,
        "missing_context": [name for name in result.missing_context],
        "sources": [source for source in result.sources],
        "reviewed_on": result.reviewed_on,
        "articles": [article for article in result.applicable_articles],
    }


class AIComplyHTTPServer(http.server.ThreadingHTTPServer):
    """Bounded local connections and one expensive operation at a time."""

    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, server_address: tuple[str, int], target_path: Path):
        host, port = server_address
        if host not in {"127.0.0.1", "localhost"}:
            raise ValueError("The console must bind to 127.0.0.1 or localhost")
        self.target_path = target_path.resolve(strict=True)
        if not (self.target_path.is_dir() or self.target_path.is_file()):
            raise ValueError("The console target must be a regular file or directory")
        self.connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.job_lock = threading.Lock()
        self.target_fd = (
            os.open(self.target_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            if os.name == "posix" else None
        )
        super().__init__(("127.0.0.1", port), AIComplyUIHandler)
        actual_port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}"}
        if actual_port == 80:
            self.allowed_hosts.update({"127.0.0.1", "localhost"})

    def server_close(self) -> None:
        super().server_close()
        if self.target_fd is not None:
            os.close(self.target_fd)
            self.target_fd = None

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(REQUEST_TIMEOUT)
        return connection, address

    def process_request(self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]) -> None:
        if not isinstance(request, socket.socket):
            raise TypeError("The local console accepts TCP connections only")
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()

    def run_job(self, operation: str, target: Path, name: str = "", version: str = "") -> bytes:
        if not self.job_lock.acquire(blocking=False):
            raise RequestError(429, "Another scan or document operation is running")
        try:
            if self.target_fd is None:
                raise RequestError(422, "Safe console scans currently require POSIX filesystem support")
            with TemporaryDirectory(prefix="aicomply-console-") as directory:
                result = subprocess.run(
                    [sys.executable, "-m", "aicomply.ui.worker"],
                    input=json.dumps({
                        "operation": operation, "target": str(target),
                        "root_fd": self.target_fd,
                        "relative_parts": target.relative_to(self.target_path).parts,
                        "snapshot_dir": directory, "name": name, "version": version,
                    }).encode("utf-8"),
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    pass_fds=(self.target_fd,),
                    cwd=Path(__file__).parent, timeout=JOB_TIMEOUT, check=False,
                )
            if result.returncode != 0:
                raise RequestError(422, "Local analysis failed; no complete result is available")
            if len(result.stdout) > MAX_RESPONSE_BYTES:
                raise RequestError(413, "Result exceeds console limits")
            response = json.loads(result.stdout)
            if "error" in response:
                raise RequestError(response["status"], response["error"])
            return result.stdout
        except subprocess.TimeoutExpired:
            raise RequestError(504, "Local analysis exceeded the time limit") from None
        finally:
            self.job_lock.release()


class AIComplyUIHandler(http.server.BaseHTTPRequestHandler):
    server: AIComplyHTTPServer
    server_version = "AIComply"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, payload: bytes, content_type: str, status: int = 200) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; font-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
        )
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, data: object, status: int = 200) -> None:
        self._send(json.dumps(data, allow_nan=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def _validate_request(self) -> None:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0].lower() not in self.server.allowed_hosts:
            raise RequestError(403, "Unrecognized local Host")
        origins = self.headers.get_all("Origin", [])
        if origins and (len(origins) != 1 or origins[0].lower() != f"http://{hosts[0].lower()}"):
            raise RequestError(403, "A same-origin request is required")
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        if fetch_sites and (len(fetch_sites) != 1 or fetch_sites[0] not in {"same-origin", "none"}):
            raise RequestError(403, "Cross-site requests are not allowed")
        if self.path.startswith("//") or not self.path.startswith("/"):
            raise RequestError(400, "An origin-form request target is required")
        if len(self.path) > 8192:
            raise RequestError(414, "Request target is too long")

    def _read_json(self) -> dict[str, JsonValue]:
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Encoding"):
            raise RequestError(400, "Encoded request bodies are not supported")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            raise RequestError(400, "One valid Content-Length is required")
        if len(lengths[0]) > 10 or int(lengths[0]) > MAX_BODY_BYTES:
            raise RequestError(413, "Request body exceeds console limits")
        length = int(lengths[0])
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or types[0].lower() not in {
            "application/json", "application/json; charset=utf-8",
        }:
            raise RequestError(415, "Content-Type must be application/json with UTF-8")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise RequestError(400, "Incomplete request body")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            raise RequestError(400, "Invalid JSON body") from None
        if not isinstance(value, dict):
            raise RequestError(400, "JSON body must be an object")
        _check_json_limits(value)
        return value

    def _target(self, supplied: str | None) -> Path:
        root = self.server.target_path
        if supplied is None:
            target = root
        else:
            if "\x00" in supplied:
                raise RequestError(400, "Invalid scan path")
            requested = Path(supplied)
            if not requested.is_absolute():
                requested = root / requested if root.is_dir() else root.parent / requested
            target = requested.resolve(strict=True)
            if target != root and (root.is_file() or not target.is_relative_to(root)):
                raise RequestError(403, "Scan path is outside the configured root")
            for part in (requested, *requested.parents):
                if part == root:
                    break
                if part.is_symlink():
                    raise RequestError(403, "Symbolic links are not supported by the console")
        return target

    def _dispatch(self) -> None:
        self._validate_request()
        parsed = urlsplit(self.path)
        if self.command == "GET":
            assets = {
                "/": ("app.html", "text/html; charset=utf-8"),
                "/index.html": ("app.html", "text/html; charset=utf-8"),
                "/app": ("app.html", "text/html; charset=utf-8"),
                "/static/app.css": ("app.css", "text/css; charset=utf-8"),
                "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
            }
            if parsed.path in assets and not parsed.query:
                filename, content_type = assets[parsed.path]
                self._send((STATIC_DIR / filename).read_bytes(), content_type)
                return
            if parsed.path == "/api/scan" and parse_qs(parsed.query) == {"format": ["sarif"]}:
                self._send(self.server.run_job("sarif", self._target(None)), "application/json; charset=utf-8")
                return
            raise RequestError(404, "Not found")
        if self.command != "POST":
            raise RequestError(405, "Method not allowed")
        if parsed.query:
            raise RequestError(400, "Query parameters are not supported")
        if parsed.path not in {"/api/scan", "/api/docgen", "/api/assess", "/api/verify"}:
            raise RequestError(404, "Not found")
        payload = self._read_json()
        if parsed.path == "/api/scan":
            scan = ScanRequest.model_validate(payload)
            self._send(self.server.run_job("scan", self._target(scan.path)), "application/json; charset=utf-8")
        elif parsed.path == "/api/docgen":
            docgen = DocgenRequest.model_validate(payload)
            self._send(self.server.run_job("docgen", self._target(None), docgen.name, docgen.version),
                       "application/json; charset=utf-8")
        elif parsed.path == "/api/assess":
            self._send_json(provisional_assessment(AssessRequest.model_validate(payload)))
        else:
            request = VerifyRequest.model_validate(payload)
            try:
                pem = request.public_key.strip().encode("ascii")
                if not pem.startswith(b"-----BEGIN PUBLIC KEY-----") or not pem.endswith(b"-----END PUBLIC KEY-----"):
                    raise ValueError("Expected a public PEM key")
                if pem.count(b"-----BEGIN") != 1:
                    raise ValueError("Expected one public key")
                public_key = serialization.load_pem_public_key(pem)
                if not isinstance(public_key, Ed25519PublicKey):
                    raise ValueError("Expected Ed25519")
            except (ValueError, TypeError):
                raise RequestError(400, "A valid evidence bundle and trusted Ed25519 public PEM are required") from None
            bundle_input: str | dict[str, object] = (
                request.bundle if isinstance(request.bundle, str) else dict[str, object](request.bundle)
            )
            valid, _ = verify_evidence_bundle(bundle_input, pem)
            bundle = None
            if valid:
                bundle = (
                    SignedEvidenceBundle.model_validate_json(request.bundle)
                    if isinstance(request.bundle, str)
                    else SignedEvidenceBundle.model_validate(request.bundle)
                )
            self._send_json({
                "valid": valid,
                "message": "Signature matches the supplied key; legal correctness and trusted time are not established."
                           if valid else "Evidence verification failed for the supplied key.",
                "signer_id": bundle.signer_identity if bundle else None,
                "signed_at": bundle.timestamp if bundle else None,
                "scan_id": bundle.report.scan_id if bundle else None,
                "fingerprint": compute_public_key_fingerprint(pem),
            })

    def _handle(self) -> None:
        try:
            self._dispatch()
        except RequestError as error:
            self._send_json({"error": str(error)}, error.status)
        except ValidationError:
            self._send_json({"error": "Invalid request fields"}, 400)
        except (FileNotFoundError, NotADirectoryError):
            self._send_json({"error": "Requested local resource is unavailable"}, 404)
        except PermissionError:
            self._send_json({"error": "Local resource is not readable"}, 403)
        except (TimeoutError, BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            logger.error("Local console operation failed")
            self._send_json({"error": "Local operation failed; no complete result is available"}, 500)

    do_GET = _handle
    do_POST = _handle
    do_OPTIONS = _handle


def start_ui_server(
    target_path: Path, host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True,
) -> AIComplyHTTPServer:
    server = AIComplyHTTPServer((host, port), target_path)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    logger.info("AIComply local review console running at %s", url)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    return server
