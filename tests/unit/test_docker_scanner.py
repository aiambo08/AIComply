"""
AIComply - Unit Tests for Container Infrastructure Scanner (Dockerfile & Compose)
"""

from pathlib import Path
import pytest
from aicomply.infra.docker_scanner import DockerScanner
from aicomply.rules.loader import load_rules_from_dir


@pytest.fixture
def rules():
    rules_path = Path(__file__).parents[2] / "src" / "aicomply" / "rules" / "eu_ai_act"
    catalog = load_rules_from_dir(rules_path)
    return catalog.rules


def test_dockerfile_missing_user_directive(tmp_path: Path, rules):
    dockerfile = tmp_path / "Dockerfile"
    content = """FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "main.py"]
"""
    dockerfile.write_text(content, encoding="utf-8")

    scanner = DockerScanner(rules)
    findings = scanner.scan_file(dockerfile)

    root_findings = [f for f in findings if f.rule_id == "EUAIA-ART15-004"]
    assert len(root_findings) == 1
    assert root_findings[0].severity.value == "HIGH"


def test_dockerfile_compliant_user_directive(tmp_path: Path, rules):
    dockerfile = tmp_path / "Dockerfile"
    content = """FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN useradd -m appuser
USER appuser
CMD ["python", "main.py"]
"""
    dockerfile.write_text(content, encoding="utf-8")

    scanner = DockerScanner(rules)
    findings = scanner.scan_file(dockerfile)

    root_findings = [f for f in findings if f.rule_id == "EUAIA-ART15-004"]
    assert len(root_findings) == 0


def test_dockerfile_insecure_http_expose(tmp_path: Path, rules):
    dockerfile = tmp_path / "Dockerfile"
    content = """FROM python:3.11-slim
USER appuser
EXPOSE 8000
CMD ["uvicorn", "api:app", "--port", "8000"]
"""
    dockerfile.write_text(content, encoding="utf-8")

    scanner = DockerScanner(rules)
    findings = scanner.scan_file(dockerfile)

    expose_findings = [f for f in findings if f.rule_id == "EUAIA-ART15-005"]
    assert len(expose_findings) == 1


def test_docker_compose_privileged_service(tmp_path: Path, rules):
    compose = tmp_path / "docker-compose.yml"
    content = """version: '3.8'
services:
  inference_worker:
    image: vllm/vllm-openai
    privileged: true
    ports:
      - "8000:8000"
"""
    compose.write_text(content, encoding="utf-8")

    scanner = DockerScanner(rules)
    findings = scanner.scan_file(compose)

    rule_ids = {f.rule_id for f in findings}
    assert "EUAIA-ART15-006" in rule_ids  # privileged mode
    assert "EUAIA-ART15-005" in rule_ids  # insecure port 8000:8000


def test_dockerfile_inline_suppression(tmp_path: Path, rules):
    dockerfile = tmp_path / "Dockerfile"
    content = """FROM python:3.11-slim
USER appuser
EXPOSE 8000 # aicomply:ignore EUAIA-ART15-005
CMD ["uvicorn", "api:app"]
"""
    dockerfile.write_text(content, encoding="utf-8")

    scanner = DockerScanner(rules)
    findings = scanner.scan_file(dockerfile)

    expose_findings = [f for f in findings if f.rule_id == "EUAIA-ART15-005"]
    assert len(expose_findings) == 0
