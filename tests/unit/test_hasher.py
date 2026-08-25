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


def test_crlf_lf_hash_determinism():
    loc = CodeLocation(file_path="src/main.py", start_line=10, end_line=12)
    snippet_crlf = "def analyze():\r\n    return False\r\n"
    snippet_lf = "def analyze():\n    return False\n"
    
    hash_crlf = compute_finding_hash("EUAIA-ART05-001", loc, "target", snippet_crlf)
    hash_lf = compute_finding_hash("EUAIA-ART05-001", loc, "target", snippet_lf)
    
    assert hash_crlf == hash_lf


def test_path_separator_normalization():
    loc_win = CodeLocation(file_path="src\\sub\\module.py", start_line=5, end_line=5)
    loc_posix = CodeLocation(file_path="src/sub/module.py", start_line=5, end_line=5)
    
    hash_win = compute_finding_hash("EUAIA-ART12-001", loc_win, "target", "client = OpenAI()")
    hash_posix = compute_finding_hash("EUAIA-ART12-001", loc_posix, "target", "client = OpenAI()")
    
    assert hash_win == hash_posix