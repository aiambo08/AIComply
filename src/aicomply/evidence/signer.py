"""
AIComply - Asymmetric Cryptographic Signing (Ed25519)
Genera pares de claves, firma paquetes de evidencia deterministas
y permite la verificación offline independiente por parte de auditores y comités de riesgo.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from aicomply.evidence.hasher import compute_scan_hash
from aicomply.schemas import ScanReport, SignedEvidenceBundle


def compute_public_key_fingerprint(public_key: ed25519.Ed25519PublicKey) -> str:
    """Calcula la huella digital SHA-256 de una clave pública Ed25519."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"SHA256:{hashlib.sha256(raw_bytes).hexdigest()}"


def generate_keypair(out_dir: Path, key_name: str = "aicomply") -> Tuple[Path, Path, str]:
    """
    Genera un nuevo par de claves asimétricas Ed25519 (privada PKCS8 PEM y pública SubjectPublicKeyInfo PEM).
    Retorna (ruta_clave_privada, ruta_clave_publica, fingerprint).
    """
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

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

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

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
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_private_key(key_input: Union[bytes, str, Path]) -> ed25519.Ed25519PrivateKey:
    """Carga una clave privada Ed25519 desde bytes, texto o ruta de archivo."""
    if isinstance(key_input, Path) or (isinstance(key_input, str) and Path(key_input).exists()):
        key_bytes = Path(key_input).read_bytes()
    elif isinstance(key_input, str):
        key_bytes = key_input.encode("utf-8")
    else:
        key_bytes = key_input

    key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada proporcionada no es de tipo Ed25519.")
    return key


def _load_public_key(key_input: Union[bytes, str, Path]) -> ed25519.Ed25519PublicKey:
    """Carga una clave pública Ed25519 desde bytes, texto o ruta de archivo."""
    if isinstance(key_input, Path) or (isinstance(key_input, str) and Path(key_input).exists()):
        key_bytes = Path(key_input).read_bytes()
    elif isinstance(key_input, str):
        key_bytes = key_input.encode("utf-8")
    else:
        key_bytes = key_input

    key = serialization.load_pem_public_key(key_bytes)
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
    Retorna un paquete inmutable SignedEvidenceBundle.
    """
    private_key = _load_private_key(private_key_input)
    public_key = private_key.public_key()
    fingerprint = compute_public_key_fingerprint(public_key)

    sign_timestamp = datetime.now(timezone.utc).isoformat()
    canonical_bytes = canonicalize_report_payload(report, sign_timestamp, signer_identity)

    raw_signature = private_key.sign(canonical_bytes)
    sig_b64 = base64.b64encode(raw_signature).decode("ascii")

    return SignedEvidenceBundle(
        version="2.0.0",
        algorithm="Ed25519",
        scan_id=report.scan_id,
        timestamp=sign_timestamp,
        signer_identity=signer_identity,
        public_key_fingerprint=fingerprint,
        signature=sig_b64,
        report=report,
    )


def verify_evidence_bundle(
    bundle_input: Union[SignedEvidenceBundle, Dict[str, Any], str, Path],
    public_key_input: Union[bytes, str, Path],
) -> Tuple[bool, str]:
    """
    Verifica matemáticamente la autenticidad e integridad de un paquete de evidencias firmado.
    Retorna (es_valido, mensaje_descriptivo).
    """
    # 1. Parsear el paquete a SignedEvidenceBundle
    if isinstance(bundle_input, Path) or (isinstance(bundle_input, str) and Path(bundle_input).exists()):
        raw_text = Path(bundle_input).read_text(encoding="utf-8")
        bundle_dict = json.loads(raw_text)
        bundle = SignedEvidenceBundle.model_validate(bundle_dict)
    elif isinstance(bundle_input, str):
        bundle_dict = json.loads(bundle_input)
        bundle = SignedEvidenceBundle.model_validate(bundle_dict)
    elif isinstance(bundle_input, dict):
        bundle = SignedEvidenceBundle.model_validate(bundle_input)
    elif isinstance(bundle_input, SignedEvidenceBundle):
        bundle = bundle_input
    else:
        return False, "Tipo de entrada de paquete de evidencias no válido."

    # 2. Cargar clave pública
    try:
        public_key = _load_public_key(public_key_input)
    except Exception as exc:
        return False, f"Error al cargar la clave pública Ed25519: {exc}"

    # 3. Comprobar huella digital (Fingerprint)
    computed_fp = compute_public_key_fingerprint(public_key)
    if bundle.public_key_fingerprint != computed_fp:
        return (
            False,
            f"Discrepancia en la huella de la clave pública. Esperada: {bundle.public_key_fingerprint}, Obtenida: {computed_fp}",
        )

    # 4. Comprobar integridad del scan_id
    recalculated_scan_hash = compute_scan_hash(bundle.report.findings)
    if recalculated_scan_hash != bundle.scan_id or bundle.report.scan_id != bundle.scan_id:
        return False, "Integridad comprometida: el hash de los hallazgos no coincide con el scan_id firmado."

    # 5. Reconstruir bytes canónicos y verificar firma
    canonical_bytes = canonicalize_report_payload(bundle.report, bundle.timestamp, bundle.signer_identity)
    try:
        sig_bytes = base64.b64decode(bundle.signature.encode("ascii"))
        public_key.verify(sig_bytes, canonical_bytes)
        return True, "Firma digital Ed25519 válida. El reporte es auténtico, íntegro e inalterado."
    except InvalidSignature:
        return False, "Firma criptográfica inválida: el contenido del reporte ha sido modificado tras su firma."
    except Exception as err:
        return False, f"Error durante la verificación de la firma: {err}"
