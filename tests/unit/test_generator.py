from pathlib import Path
import pytest
from aicomply.cli import get_default_rules_dir
from aicomply.generator.annex_iv import AnnexIVGenerator
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.engine import ScanEngine


def test_annex_iv_generation():
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    engine = ScanEngine(catalog=catalog)
    
    fixture_path = Path(__file__).parents[1] / "fixtures" / "non_compliant_app.py"
    report = engine.scan_path(fixture_path)
    
    generator = AnnexIVGenerator(report, system_name="Enterprise LLM Gateway", version="2.4.0")
    dossier = generator.generate_markdown_dossier()

    # Validar secciones obligatorias del Anexo IV
    assert "SECCIÓN 1 — Identificación y Descripción General del Sistema" in dossier
    assert "SECCIÓN 2 — Métodos de Desarrollo y Componentes de Software" in dossier
    assert "SECCIÓN 3 — Monitorización, Registro y Trazabilidad" in dossier
    assert "Enterprise LLM Gateway" in dossier
    assert "2.4.0" in dossier
    assert report.scan_id in dossier


def test_annex_iv_stack_detection_on_compliant_code(tmp_path: Path):
    rules_path = get_default_rules_dir()
    catalog = load_rules_from_dir(rules_path)
    engine = ScanEngine(catalog=catalog)

    # Crear pipeline conforme con múltiples imports
    code = """
import logging
import openai
import torch
import langchain
from transformers import AutoModelForCausalLM

logger = logging.getLogger(__name__)

def run_agent():
    logger.info("Executing safe inference")
"""
    test_file = tmp_path / "compliant_rag.py"
    test_file.write_text(code, encoding="utf-8")

    report = engine.scan_path(test_file)
    generator = AnnexIVGenerator(report, system_name="RAG Assistant", version="1.0.0")
    dossier = generator.generate_markdown_dossier()

    # Validar que los SDKs y componentes de IA fueron detectados desde el AST
    assert "OpenAI SDK" in dossier
    assert "PyTorch" in dossier
    assert "LangChain" in dossier
    assert "Hugging Face Transformers" in dossier
    assert "Sistema de Registro y Auditoría" in dossier
    assert "Conformidad Plena" in dossier