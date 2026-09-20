"""Ed25519 evidence for a separately trusted public key.

Protocol 2.0.0 signs UTF-8 JSON of ``report``, ``timestamp`` and
``signer_identity or ""``, with sorted keys, ASCII escapes and compact separators.
The complete schema-normalized report is covered, not the original JSON layout
or source files. The report's scan_id remains a finding-set identifier.

The envelope version and algorithm are fixed accepted constants; its scan_id
must match the signed report and finding-set hash, and its fingerprint must
match the externally supplied key. Other envelope/report fields, duplicate JSON
keys, normalization changes and ambiguous empty signer identities are rejected.
Existing explicit 2.0.0 bundles meeting these constraints remain compatible.

Verification proves integrity relative to the supplied key. It does not certify
legal correctness, source/rule/config provenance absent from the report, signer
accreditation, trusted time, freshness, revocation or judicial admissibility.
Only explicit Path inputs read files; strings and bytes are literal content.
"""

import base64
import hashlib
import json
import os
import re
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from aicomply.evidence.hasher import compute_scan_hash
from aicomply.schemas import ScanReport, SignedEvidenceBundle


_PROTOCOL_VERSION = "2.0.0"
_ALGORITHM = "Ed25519"
_ENVELOPE_FIELDS = frozenset(
    {
        "version",
        "algorithm",
        "scan_id",
        "timestamp",
        "signer_identity",
        "public_key_fingerprint",
        "signature",
        "report",
    }
)


def compute_public_key_fingerprint(
    public_key: Union[ed25519.Ed25519PublicKey, bytes, str, Path],
) -> str:
    """Calcula la huella digital SHA-256 de una clave pública Ed25519."""
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key = _load_public_key(public_key)
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"SHA256:{hashlib.sha256(raw_bytes).hexdigest()}"


def generate_keypair(
    out_dir: Path, key_name: str = "aicomply"
) -> Tuple[Path, Path, str]:
    """
    Genera un nuevo par de claves asimétricas Ed25519 (privada PKCS8 PEM y pública SubjectPublicKeyInfo PEM).
    Retorna (ruta_clave_privada, ruta_clave_publica, fingerprint).
    Nunca reemplaza archivos existentes. En POSIX ambas claves nacen con modo
    0600 (o más restrictivo por umask); el directorio debe ser de confianza.
    En otros sistemas los controles de acceso dependen también de sus ACL.
    """
    if not isinstance(key_name, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key_name
    ):
        raise ValueError(
            "El nombre de clave debe ser un nombre simple de 1 a 128 caracteres ASCII."
        )

    out_dir = out_dir.resolve()
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = out_dir / f"{key_name}.pem"
    pub_path = out_dir / f"{key_name}.pub"

    created: list[tuple[Path, os.stat_result]] = []
    try:
        with ExitStack() as stack:
            streams = []
            for path in (priv_path, pub_path):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created.append((path, os.fstat(fd)))
                streams.append(stack.enter_context(os.fdopen(fd, "wb")))
            for stream, contents in zip(streams, (priv_pem, pub_pem)):
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for path, original in reversed(created):
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == (
                    original.st_dev,
                    original.st_ino,
                ):
                    path.unlink()
            except FileNotFoundError:
                pass
        raise

    fingerprint = compute_public_key_fingerprint(public_key)
    return priv_path, pub_path, fingerprint


def canonicalize_report_payload(
    report: ScanReport,
    timestamp: str,
    signer_identity: Optional[str] = None,
) -> bytes:
    """Construye los bytes canónicos deterministas a firmar incluyendo todo el reporte."""
    canonical_dict = {
        "report": report.model_dump(),
        "timestamp": timestamp,
        "signer_identity": signer_identity or "",
    }
    return _canonical_json(canonical_dict)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _key_bytes(key_input: Union[bytes, str, Path]) -> bytes:
    if isinstance(key_input, Path):
        return key_input.read_bytes()
    if isinstance(key_input, str):
        return key_input.encode("utf-8")
    if isinstance(key_input, bytes):
        return key_input
    raise TypeError("Se requiere contenido PEM o una ruta Path explícita.")


def _load_private_key(key_input: Union[bytes, str, Path]) -> ed25519.Ed25519PrivateKey:
    """Carga PEM literal; solo Path permite leer un archivo local."""
    key = serialization.load_pem_private_key(_key_bytes(key_input), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada proporcionada no es de tipo Ed25519.")
    return key


def _load_public_key(key_input: Union[bytes, str, Path]) -> ed25519.Ed25519PublicKey:
    """Carga PEM literal; solo Path permite leer un archivo local."""
    key = serialization.load_pem_public_key(_key_bytes(key_input))
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("La clave pública proporcionada no es de tipo Ed25519.")
    return key


def sign_scan_report(
    report: ScanReport,
    private_key_input: Union[bytes, str, Path],
    signer_identity: Optional[str] = None,
) -> SignedEvidenceBundle:
    """
    Firma asimétricamente un reporte de escaneo ScanReport con una clave privada Ed25519.
    Retorna un SignedEvidenceBundle con una copia independiente del reporte.
    """
    report = ScanReport.model_validate(report.model_dump())
    if report.scan_id != compute_scan_hash(report.findings):
        raise ValueError(
            "El scan_id no coincide con el hash del conjunto de hallazgos."
        )
    if signer_identity is not None and (
        not isinstance(signer_identity, str) or not signer_identity
    ):
        raise ValueError("La identidad del firmante debe ser texto no vacío o None.")

    private_key = _load_private_key(private_key_input)
    public_key = private_key.public_key()
    fingerprint = compute_public_key_fingerprint(public_key)

    sign_timestamp = datetime.now(timezone.utc).isoformat()
    canonical_bytes = canonicalize_report_payload(
        report, sign_timestamp, signer_identity
    )

    raw_signature = private_key.sign(canonical_bytes)
    sig_b64 = base64.b64encode(raw_signature).decode("ascii")

    return SignedEvidenceBundle(
        version=_PROTOCOL_VERSION,
        algorithm=_ALGORITHM,
        scan_id=report.scan_id,
        timestamp=sign_timestamp,
        signer_identity=signer_identity,
        public_key_fingerprint=fingerprint,
        signature=sig_b64,
        report=report,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("El JSON contiene claves duplicadas.")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("El JSON contiene un número no finito.")


def _parse_bundle(
    bundle_input: Union[SignedEvidenceBundle, dict[str, object], str, Path],
) -> SignedEvidenceBundle:
    if isinstance(bundle_input, Path):
        bundle_input = bundle_input.read_text(encoding="utf-8-sig")
    if isinstance(bundle_input, str):
        raw = json.loads(
            bundle_input.removeprefix("\ufeff"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    elif isinstance(bundle_input, SignedEvidenceBundle):
        if bundle_input.model_fields_set != _ENVELOPE_FIELDS:
            raise ValueError("El sobre debe declarar todos sus campos explícitamente.")
        raw = bundle_input.model_dump()
    elif isinstance(bundle_input, dict):
        raw = bundle_input
    else:
        raise TypeError("Tipo de entrada de paquete de evidencias no válido.")

    if not isinstance(raw, dict) or raw.keys() != _ENVELOPE_FIELDS:
        raise ValueError("El sobre contiene campos ausentes o no admitidos.")
    if raw["version"] != _PROTOCOL_VERSION or raw["algorithm"] != _ALGORITHM:
        raise ValueError("Versión de protocolo o algoritmo no admitidos.")
    if raw["signer_identity"] == "":
        raise ValueError("La identidad vacía es ambigua; se requiere null.")

    bundle = SignedEvidenceBundle.model_validate(raw)
    if _canonical_json(raw) != _canonical_json(bundle.model_dump()):
        raise ValueError(
            "El paquete contiene campos omitidos, no admitidos o normalizados."
        )
    timestamp = datetime.fromisoformat(bundle.timestamp)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("La fecha de firma debe incluir zona horaria.")
    return bundle


def verify_evidence_bundle(
    bundle_input: Union[SignedEvidenceBundle, dict[str, object], str, Path],
    public_key_input: Union[bytes, str, Path],
) -> Tuple[bool, str]:
    """
    Verifica integridad respecto a una clave pública obtenida por un canal de confianza.
    Para entradas no confiables, pasar JSON/dict sin validarlo previamente: un
    modelo ya validado puede haber descartado campos antes de llegar aquí.
    Retorna (es_valido, mensaje_descriptivo), sin incluir el contenido de entradas.
    """
    try:
        bundle = _parse_bundle(bundle_input)
    except (ValueError, TypeError, OSError, RecursionError):
        return (
            False,
            "Error al parsear el paquete de evidencias: formato, protocolo o algoritmo no válido.",
        )

    try:
        public_key = _load_public_key(public_key_input)
    except (ValueError, TypeError, OSError, UnsupportedAlgorithm):
        return (
            False,
            "Error al cargar la clave pública Ed25519: se requiere PEM válido o un Path explícito.",
        )

    computed_fp = compute_public_key_fingerprint(public_key)
    if bundle.public_key_fingerprint != computed_fp:
        return False, "Discrepancia en la huella de la clave pública."

    recalculated_scan_hash = compute_scan_hash(bundle.report.findings)
    if (
        recalculated_scan_hash != bundle.scan_id
        or bundle.report.scan_id != bundle.scan_id
    ):
        return (
            False,
            "Integridad comprometida: el hash de los hallazgos no coincide con el scan_id firmado.",
        )

    try:
        sig_bytes = base64.b64decode(bundle.signature.encode("ascii"), validate=True)
        if (
            len(sig_bytes) != 64
            or base64.b64encode(sig_bytes).decode("ascii") != bundle.signature
        ):
            return (
                False,
                "Firma Ed25519 no válida: se requieren 64 bytes en base64 canónico.",
            )
        canonical_bytes = canonicalize_report_payload(
            bundle.report, bundle.timestamp, bundle.signer_identity
        )
        public_key.verify(sig_bytes, canonical_bytes)
        return (
            True,
            "Firma Ed25519 válida: integridad del reporte respecto a la clave proporcionada.",
        )
    except InvalidSignature:
        return (
            False,
            "Firma criptográfica inválida: el contenido del reporte ha sido modificado tras su firma.",
        )
    except (ValueError, TypeError, RecursionError):
        return False, "Error durante la verificación: firma o contenido no válido."
