"""Security boundaries for locally generated keys and signed evidence."""

import base64
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from aicomply.evidence.hasher import compute_finding_hash, compute_scan_hash
from aicomply.evidence.signer import (
    compute_public_key_fingerprint,
    generate_keypair,
    sign_scan_report,
    verify_evidence_bundle,
)
from aicomply.schemas import (
    CodeLocation,
    Confidence,
    Finding,
    RiskTier,
    ScanReport,
    ScanSummary,
    Severity,
    SignedEvidenceBundle,
)


@pytest.fixture
def report() -> ScanReport:
    location = CodeLocation(file_path="agent.py", start_line=1, end_line=1)
    finding = Finding(
        id=compute_finding_hash(
            "EUAIA-ART14-002", location, "os.system", "os.system(cmd)"
        ),
        rule_id="EUAIA-ART14-002",
        article="Art. 14(4)(a)",
        severity=Severity.CRITICAL,
        risk_tier=RiskTier.HIGH_RISK,
        title="Unvalidated tool execution",
        message="Unvalidated output reaches a command.",
        location=location,
        code_snippet="os.system(cmd)",
        remediation="Validate output.",
        max_fine="Context dependent",
        confidence=Confidence.HIGH,
    )
    return ScanReport(
        scan_id=compute_scan_hash([finding]),
        timestamp="2026-09-01T10:00:00Z",
        target_path="src/",
        summary=ScanSummary(total_findings=1, total_files_scanned=1),
        findings=[finding],
    )


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    private = ed25519.Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )


@pytest.fixture
def bundle(report: ScanReport, keypair: tuple[bytes, bytes]) -> SignedEvidenceBundle:
    return sign_scan_report(report, keypair[0], signer_identity="local-ci")


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../escape",
        "dir/key",
        r"..\escape",
        r"C:\key",
        "/absolute",
        "a\0b",
        "x" * 129,
    ],
)
def test_keygen_rejects_unsafe_names_before_creating_directory(
    tmp_path: Path, name: str
):
    output = tmp_path / "keys"
    with pytest.raises(ValueError):
        generate_keypair(output, name)
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("suffix", [".pem", ".pub"])
def test_keygen_does_not_replace_existing_files(tmp_path: Path, suffix: str):
    existing = tmp_path / f"key{suffix}"
    existing.write_bytes(b"must remain unchanged")
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path, "key")
    assert existing.read_bytes() == b"must remain unchanged"
    assert set(tmp_path.iterdir()) == {existing}


@pytest.mark.parametrize("suffix", [".pem", ".pub"])
@pytest.mark.parametrize("dangling", [False, True])
def test_keygen_rejects_symlinks(tmp_path: Path, suffix: str, dangling: bool):
    target = tmp_path / "target"
    if not dangling:
        target.write_bytes(b"untouched")
    link = tmp_path / f"key{suffix}"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path, "key")
    assert link.is_symlink()
    assert target.exists() is not dangling
    if not dangling:
        assert target.read_bytes() == b"untouched"
    other = ".pub" if suffix == ".pem" else ".pem"
    assert not (tmp_path / f"key{other}").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_private_key_is_restricted_at_creation_with_permissive_umask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    real_open = os.open
    creation_modes = []

    def observe_open(path: Path, flags: int, mode: int):
        fd = real_open(path, flags, mode)
        creation_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return fd

    monkeypatch.setattr(os, "open", observe_open)
    old_umask = os.umask(0)
    try:
        private, public, fingerprint = generate_keypair(tmp_path / "keys", "key")
    finally:
        os.umask(old_umask)
    assert creation_modes == [0o600, 0o600]
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(private.parent.stat().st_mode) == 0o700
    assert compute_public_key_fingerprint(public) == fingerprint


def test_keygen_cleans_its_files_after_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def fail_sync(fd: int):
        raise OSError("simulated write failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises(OSError, match="simulated write failure"):
        generate_keypair(tmp_path, "key")
    assert list(tmp_path.iterdir()) == []


def test_concurrent_keygen_never_replaces_the_winning_pair(tmp_path: Path):
    def generate():
        try:
            return generate_keypair(tmp_path, "key")
        except FileExistsError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: generate(), range(4)))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    private, public, fingerprint = winners[0]
    assert compute_public_key_fingerprint(public) == fingerprint
    assert private.exists()
    assert set(tmp_path.iterdir()) == {private, public}


def test_long_json_and_pem_strings_are_content(
    report: ScanReport, keypair: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
):
    def forbid_filesystem(*args, **kwargs):
        raise AssertionError("Literal input must not access the filesystem")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "exists", forbid_filesystem)
        patch.setattr(Path, "read_bytes", forbid_filesystem)
        patch.setattr(Path, "read_text", forbid_filesystem)
        private, public = keypair
        signed = sign_scan_report(report, "\n" * 4096 + private.decode())
        assert verify_evidence_bundle(
            signed.model_dump_json(), "\n" * 4096 + public.decode()
        )[0]
        assert not verify_evidence_bundle("x" * 10000, public)[0]
        assert not verify_evidence_bundle(signed, "x" * 10000)[0]


def test_only_explicit_paths_read_files(
    tmp_path: Path, report: ScanReport, monkeypatch: pytest.MonkeyPatch
):
    private, public, _ = generate_keypair(tmp_path)
    signed = sign_scan_report(report, private)
    evidence = tmp_path / "evidence.json"
    evidence.write_text(signed.model_dump_json(), encoding="utf-8-sig")
    assert verify_evidence_bundle(evidence, public)[0]

    def forbid_filesystem(*args, **kwargs):
        raise AssertionError("String paths must not access the filesystem")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", forbid_filesystem)
        patch.setattr(Path, "read_text", forbid_filesystem)
        assert not verify_evidence_bundle(signed, str(public))[0]
        assert not verify_evidence_bundle(str(evidence), b"irrelevant")[0]
        with pytest.raises(ValueError):
            compute_public_key_fingerprint(str(public))
        with pytest.raises(ValueError):
            sign_scan_report(report, str(private))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "3.0.0"),
        ("version", ""),
        ("version", None),
        ("version", 2),
        ("algorithm", "none"),
        ("algorithm", "ed25519"),
        ("algorithm", None),
        ("algorithm", ["Ed25519"]),
        ("scan_id", "0" * 64),
        ("timestamp", "2026-09-02T10:00:00Z"),
        ("timestamp", "not a date"),
        ("timestamp", "2026-09-01T10:00:00"),
        ("public_key_fingerprint", "SHA256:" + "0" * 64),
        ("signer_identity", "different signer"),
        ("signer_identity", ""),
        ("signer_identity", None),
    ],
)
def test_rejects_altered_envelope(
    bundle: SignedEvidenceBundle,
    keypair: tuple[bytes, bytes],
    field: str,
    value: object,
):
    raw = bundle.model_dump()
    raw[field] = value
    assert not verify_evidence_bundle(raw, keypair[1])[0]


@pytest.mark.parametrize("field", list(SignedEvidenceBundle.model_fields))
def test_requires_explicit_envelope_fields(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], field: str
):
    raw = bundle.model_dump()
    del raw[field]
    assert not verify_evidence_bundle(raw, keypair[1])[0]


def test_rejects_model_with_implicit_protocol_defaults(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes]
):
    raw = bundle.model_dump()
    del raw["version"]
    defaulted = SignedEvidenceBundle.model_validate(raw)
    assert not verify_evidence_bundle(defaulted, keypair[1])[0]


@pytest.mark.parametrize(
    "location", ["envelope", "report", "summary", "finding", "location"]
)
def test_rejects_unknown_fields_at_every_level(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], location: str
):
    raw = bundle.model_dump()
    targets = {
        "envelope": raw,
        "report": raw["report"],
        "summary": raw["report"]["summary"],
        "finding": raw["report"]["findings"][0],
        "location": raw["report"]["findings"][0]["location"],
    }
    targets[location]["unverified_claim"] = "legally certified"
    assert not verify_evidence_bundle(raw, keypair[1])[0]


@pytest.mark.parametrize("kind", ["title", "path", "summary", "finding_id", "scan_id"])
def test_rejects_altered_report(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], kind: str
):
    raw = bundle.model_dump()
    if kind == "title":
        raw["report"]["findings"][0]["title"] = "Changed title"
    elif kind == "path":
        raw["report"]["target_path"] = "other-project/"
    elif kind == "summary":
        raw["report"]["summary"]["total_files_scanned"] = 99
    elif kind == "finding_id":
        raw["report"]["findings"][0]["id"] = "0" * 64
    else:
        raw["report"]["scan_id"] = "0" * 64
    assert not verify_evidence_bundle(raw, keypair[1])[0]


@pytest.mark.parametrize(
    "kind", ["string_int", "bool_int", "int_float", "missing_default"]
)
def test_rejects_normalization_ambiguities(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], kind: str
):
    raw = bundle.model_dump()
    summary = raw["report"]["summary"]
    if kind == "string_int":
        summary["total_findings"] = "1"
    elif kind == "bool_int":
        summary["total_findings"] = True
    elif kind == "int_float":
        summary["total_findings"] = 1.0
    else:
        del summary["execution_time_ms"]
    assert not verify_evidence_bundle(raw, keypair[1])[0]


@pytest.mark.parametrize(
    "field", ["version", "scan_id", "target_path", "total_findings", "title"]
)
def test_duplicate_json_keys_are_rejected(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], field: str
):
    text = bundle.model_dump_json()
    token = f'"{field}":'
    text = text.replace(token, f'{token}"ignored",{token}', 1)
    assert not verify_evidence_bundle(text, keypair[1])[0]


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity"])
def test_rejects_nonfinite_json_numbers(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], number: str
):
    text = bundle.model_dump_json().replace(
        '"execution_time_ms":0.0', f'"execution_time_ms":{number}'
    )
    assert not verify_evidence_bundle(text, keypair[1])[0]


@pytest.mark.parametrize(
    "mutation",
    [
        "punctuation",
        "space",
        "newline",
        "extra_padding",
        "pad_bits",
        "short",
        "long",
        "unicode",
    ],
)
def test_rejects_noncanonical_or_invalid_base64(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes], mutation: str
):
    signature = bundle.signature
    if mutation == "punctuation":
        signature = "!" + signature
    elif mutation == "space":
        signature = " " + signature
    elif mutation == "newline":
        signature = signature[:20] + "\n" + signature[20:]
    elif mutation == "extra_padding":
        signature += "="
    elif mutation == "pad_bits":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        signature = signature[:-3] + alphabet[alphabet.index(signature[-3]) + 1] + "=="
        assert base64.b64decode(signature) == base64.b64decode(bundle.signature)
    elif mutation == "short":
        signature = base64.b64encode(b"x" * 63).decode()
    elif mutation == "long":
        signature = base64.b64encode(b"x" * 65).decode()
    else:
        signature = "é" + signature
    raw = bundle.model_dump()
    raw["signature"] = signature
    assert not verify_evidence_bundle(raw, keypair[1])[0]


def test_modified_signature_and_wrong_key_fail(
    bundle: SignedEvidenceBundle, keypair: tuple[bytes, bytes]
):
    raw = bundle.model_dump()
    signature = bytearray(base64.b64decode(bundle.signature))
    signature[0] ^= 1
    raw["signature"] = base64.b64encode(signature).decode()
    assert not verify_evidence_bundle(raw, keypair[1])[0]
    wrong_key = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    assert not verify_evidence_bundle(bundle, wrong_key)[0]


def test_explicit_legacy_v2_signature_remains_compatible(
    report: ScanReport, keypair: tuple[bytes, bytes]
):
    timestamp = "2026-09-01T10:00:00+00:00"
    payload = {
        "report": report.model_dump(),
        "timestamp": timestamp,
        "signer_identity": "",
    }
    key = serialization.load_pem_private_key(keypair[0], password=None)
    assert isinstance(key, ed25519.Ed25519PrivateKey)
    signature = key.sign(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    raw = {
        "version": "2.0.0",
        "algorithm": "Ed25519",
        "scan_id": report.scan_id,
        "timestamp": timestamp,
        "signer_identity": None,
        "public_key_fingerprint": compute_public_key_fingerprint(keypair[1]),
        "signature": base64.b64encode(signature).decode(),
        "report": report.model_dump(),
    }
    assert verify_evidence_bundle(raw, keypair[1])[0]
    assert verify_evidence_bundle("\ufeff" + json.dumps(raw, indent=4), keypair[1])[0]
    raw["signer_identity"] = ""
    assert not verify_evidence_bundle(raw, keypair[1])[0]


def test_signer_rejects_inconsistent_finding_set_hash(
    report: ScanReport, keypair: tuple[bytes, bytes]
):
    altered = report.model_copy(update={"scan_id": "0" * 64})
    with pytest.raises(ValueError, match="scan_id"):
        sign_scan_report(altered, keypair[0])


def test_signer_rejects_nonfinite_report_and_empty_identity(
    report: ScanReport, keypair: tuple[bytes, bytes]
):
    with pytest.raises(ValueError, match="identidad"):
        sign_scan_report(report, keypair[0], signer_identity="")
    report.summary.execution_time_ms = float("nan")
    with pytest.raises(ValueError):
        sign_scan_report(report, keypair[0])


def test_signing_snapshots_report_and_preserves_finding_hash_contract(
    report: ScanReport, keypair: tuple[bytes, bytes]
):
    signed = sign_scan_report(report, keypair[0])
    report.summary.total_findings = 0
    report.findings.clear()
    assert signed.report.summary.total_findings == 1
    assert len(signed.report.findings) == 1
    assert verify_evidence_bundle(signed, keypair[1])[0]
    other = signed.report.model_copy(update={"target_path": "another-project"})
    assert other.scan_id == signed.scan_id
    other_signed = sign_scan_report(other, keypair[0])
    assert other_signed.signature != signed.signature
    assert verify_evidence_bundle(other_signed, keypair[1])[0]


def test_rejects_non_ed25519_keys(report: ScanReport, bundle: SignedEvidenceBundle):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError, match="Ed25519"):
        sign_scan_report(report, private_pem)
    assert not verify_evidence_bundle(bundle, public_pem)[0]


@pytest.mark.parametrize(
    "text", ["[]", "null", "true", '"string"', "0", "{", "[" * 2000]
)
def test_malformed_bundles_fail_without_exceptions(
    text: str, keypair: tuple[bytes, bytes]
):
    assert not verify_evidence_bundle(text, keypair[1])[0]


def test_verification_errors_do_not_echo_untrusted_content(
    keypair: tuple[bytes, bytes],
):
    secret = "sensitive-client-snippet"
    valid, message = verify_evidence_bundle({"report": secret}, keypair[1])
    assert not valid
    assert secret not in message
