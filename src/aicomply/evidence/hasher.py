"""
AIComply - Cryptographic Evidence & Hasher
Genera identificadores SHA-256 deterministas para hallazgos individuales
y para el conjunto del reporte de auditoría.
"""

import hashlib
import json
from typing import Any, Dict, List
from aicomply.schemas import CodeLocation, Finding


def compute_finding_hash(
    rule_id: str,
    location: CodeLocation,
    target: str,
    snippet: str = ""
) -> str:
    """
    Calcula un hash SHA-256 determinista para un hallazgo específico.
    Normaliza rutas relativas y elimina variaciones de espacios en blanco.
    """
    normalized_snippet = snippet.replace("\r\n", "\n").replace("\r", "\n").strip()
    canonical_payload = {
        "rule_id": rule_id.strip().upper(),
        "file_path": location.file_path.replace("\\", "/").strip(),
        "start_line": location.start_line,
        "end_line": location.end_line,
        "target": target.strip(),
        "snippet_normalized": normalized_snippet,
    }
    
    encoded = json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_scan_hash(findings: List[Finding]) -> str:
    """
    Calcula un hash SHA-256 consolidado para la ejecución completa del escaneo.
    Se ordenan los IDs de los hallazgos para asegurar determinismo.
    """
    if not findings:
        return hashlib.sha256(b"AIComply_EMPTY_CLEAN_SCAN").hexdigest()

    sorted_hashes = sorted([f.id for f in findings])
    consolidated_payload = "|".join(sorted_hashes).encode("utf-8")
    return hashlib.sha256(consolidated_payload).hexdigest()