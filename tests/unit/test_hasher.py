import pytest
from aicomply.evidence.hasher import compute_finding_hash, compute_scan_hash
from aicomply.schemas import CodeLocation, Confidence, Finding, RiskTier, Severity


def test_compute_finding_hash_deterministic():
    loc = CodeLocation(file_path="src/main.py", start_line=10, end_line=12)
    hash_1 = compute_finding_hash("EUAIA-ART05-001", loc, "DeepFace.analyze", "DeepFace.analyze()")
    hash_2 = compute_finding_hash("EUAIA-ART05-001", loc, "DeepFace.analyze", "DeepFace.analyze()")
    
    assert hash_1 == hash_2
    assert len(hash_1) == 64


def test_compute_scan_hash_empty():
    empty_hash = compute_scan_hash([])
    assert len(empty_hash) == 64