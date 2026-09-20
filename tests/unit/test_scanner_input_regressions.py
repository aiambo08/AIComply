import os
import time
from pathlib import Path

import pytest
import yaml

from aicomply.infra import input_reader
from aicomply.infra.dependency_scanner import DependencyScanner
from aicomply.infra.docker_scanner import DockerScanner
from aicomply.rules.loader import load_builtin_rules
from aicomply.scanner import regex_matcher
from aicomply.scanner.ast_parser import PythonASTScanner
from aicomply.scanner.regex_matcher import RegexScanner
from aicomply.schemas import PatternType, RulePattern


@pytest.fixture
def rules():
    return load_builtin_rules().rules


@pytest.mark.parametrize(
    "scanner_type,filename,content",
    [
        (PythonASTScanner, "broken.py", "def f(:"),
        (DependencyScanner, "pyproject.toml", "[project"),
        (DependencyScanner, "pyproject.toml", "[project]\ndependencies = 1"),
        (DependencyScanner, "uv.lock", "[[package]]\nversion = '1'"),
        (DependencyScanner, "Pipfile", "[packages"),
        (DependencyScanner, "Pipfile.lock", "{"),
        (DependencyScanner, "Pipfile.lock", "[]"),
        (DockerScanner, "compose.yml", "services: ["),
        (DockerScanner, "compose.yml", "services: []"),
        (DockerScanner, "compose.yml", "services:\n  worker: true"),
        (DockerScanner, "compose.yml", "defaults: &defaults {user: root}\nservices:\n  app: *defaults"),
    ],
)
def test_invalid_or_unsupported_input_never_looks_clean(
    tmp_path, rules, scanner_type, filename, content
):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    with pytest.raises((ValueError, SyntaxError, yaml.YAMLError)):
        scanner_type(rules).scan_file(path, tmp_path)


@pytest.mark.parametrize(
    "scanner_type,filename",
    [
        (PythonASTScanner, "app.py"),
        (RegexScanner, "app.txt"),
        (DependencyScanner, "requirements.txt"),
        (DockerScanner, "Dockerfile"),
    ],
)
@pytest.mark.parametrize("failure", ["missing", "encoding", "oversize", "symlink", "fifo"])
def test_scanner_input_boundaries(tmp_path, monkeypatch, rules, scanner_type, filename, failure):
    path = tmp_path / filename
    if failure == "encoding":
        path.write_bytes(b"\xff")
    elif failure == "oversize":
        path.write_text("a" * 100, encoding="utf-8")
        monkeypatch.setattr(input_reader, "MAX_INPUT_BYTES", 50)
    elif failure == "symlink":
        target = tmp_path / "target"
        target.write_text("", encoding="utf-8")
        path.symlink_to(target)
    elif failure == "fifo":
        if os.name != "posix":
            pytest.skip("POSIX special-file boundary")
        os.mkfifo(path)
    with pytest.raises((ValueError, OSError)):
        scanner_type(rules).scan_file(path, tmp_path)


def test_read_rejects_paths_outside_scan_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    path = tmp_path / "outside.txt"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        input_reader.read_scan_text(path, root)


@pytest.mark.parametrize("user", ["root", "0", "0:1000", "root:staff", "$APP_USER"])
def test_final_docker_user_is_checked(tmp_path, rules, user):
    path = tmp_path / "Dockerfile"
    path.write_text(f"FROM python:3.11\nUSER app\nUSER {user}\n", encoding="utf-8")
    findings = DockerScanner(rules).scan_file(path)
    roots = [finding for finding in findings if finding.rule_id == "EUAIA-ART15-004"]
    assert len(roots) == 1
    assert roots[0].location.start_line == 3


def test_multistage_user_does_not_leak(tmp_path, rules):
    path = tmp_path / "Dockerfile"
    path.write_text(
        "FROM python:3.11 AS build\nUSER app\nFROM python:3.11\n", encoding="utf-8"
    )
    assert any(
        finding.rule_id == "EUAIA-ART15-004"
        for finding in DockerScanner(rules).scan_file(path)
    )


@pytest.mark.parametrize("user", ["root:staff", "0:1000"])
def test_compose_root_with_nonroot_group(tmp_path, rules, user):
    path = tmp_path / "compose.yml"
    path.write_text(f"services:\n  app:\n    user: '{user}'\n", encoding="utf-8")
    assert any(
        finding.rule_id == "EUAIA-ART15-006"
        for finding in DockerScanner(rules).scan_file(path)
    )


@pytest.mark.parametrize(
    "filename,content,expected",
    [
        ("requirements.txt", "Face.Recognition==1.0\n", True),
        ("pyproject.toml", "[project]\ndependencies=['face_recognition==1.0']", True),
        ("Pipfile", "[packages]\nface_recognition='*'", True),
        ("Pipfile", "# deepface is intentionally absent\n[packages]\nrequests='*'", False),
        ("Pipfile.lock", '{"default":{"deepface":{"version":"==1.0"}}}', True),
        ("Pipfile.lock", '{"_meta":{"description":"deepface"},"default":{}}', False),
    ],
)
def test_dependency_names_and_pipfile_tables(tmp_path, rules, filename, content, expected):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    assert bool(DependencyScanner(rules).scan_file(path)) is expected


def regex_rule(rules, target):
    return rules[0].model_copy(update={
        "patterns": [RulePattern(type=PatternType.REGEX, target=target)]
    })


def test_invalid_regex_is_rejected(rules):
    with pytest.raises(ValueError, match="Invalid regex"):
        RegexScanner([regex_rule(rules, "[")])


def test_regex_budget_terminates_expensive_pattern(tmp_path, rules, monkeypatch):
    monkeypatch.setattr(regex_matcher, "REGEX_TIMEOUT_SECONDS", 0.2)
    path = tmp_path / "input.txt"
    path.write_text("a" * 80 + "!", encoding="utf-8")
    scanner = RegexScanner([regex_rule(rules, "(a+)+$")])
    started = time.monotonic()
    with pytest.raises(ValueError, match="time budget"):
        scanner.scan_file(path)
    assert time.monotonic() - started < 5


def test_regex_worker_preserves_locations_and_suppression(tmp_path: Path, rules):
    rule = regex_rule(rules, "unsafe")
    path = tmp_path / "input.txt"
    path.write_text(
        f"unsafe # aicomply:ignore {rule.id}\n  unsafe\n", encoding="utf-8"
    )
    findings = RegexScanner([rule]).scan_file(path)
    assert len(findings) == 1
    assert findings[0].location.start_line == 2
    assert findings[0].location.start_col == 2
    assert findings[0].location.end_col == 8
