"""
AIComply - Precision & Recall Benchmark Suite (EU AI Act & GDPR SAST Engine)
Evalúa formalmente la precisión (P), exhaustividad/recall (R) y F1-score del motor multimotor v2.0.
Objetivo de Calidad: Precision >= 95%, Recall >= 95%, F1-Score >= 95%.
"""

from pathlib import Path
from typing import Dict, List, NamedTuple
import pytest

from aicomply.cli import get_default_rules_dir
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.engine import ScanEngine


class BenchmarkCase(NamedTuple):
    case_id: str
    file_name: str
    content: str
    expected_violation: bool
    expected_rule_id: str = ""
    description: str = ""


# 15 Casos Positivos Reales (True Positives esperados)
TRUE_POSITIVE_CASES: List[BenchmarkCase] = [
    BenchmarkCase(
        case_id="TP-01",
        file_name="agent_cmd.py",
        content="""import openai, os
def run():
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    os.system(res.choices[0].message.content)
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART14-002",
        description="Propagación directa de salida de LLM a os.system",
    ),
    BenchmarkCase(
        case_id="TP-02",
        file_name="agent_subproc.py",
        content="""from anthropic import Anthropic
import subprocess
client = Anthropic()
def execute():
    msg = client.messages.create(model='claude-3', messages=[])
    raw = msg.content
    subprocess.run(raw, shell=True)
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART14-002",
        description="Salida de Anthropic propagada a subprocess.run",
    ),
    BenchmarkCase(
        case_id="TP-03",
        file_name="synthetic_out.py",
        content="""import openai
from flask import jsonify
def generate_user_reply():
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    text = res.choices[0].message.content
    return jsonify(text=text)
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART50-003",
        description="Salida sintética emitida a sink directo jsonify sin moderación ni marca de agua",
    ),
    BenchmarkCase(
        case_id="TP-04",
        file_name="emotion.py",
        content="""import fer
detector = fer.FER()
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART05-001",
        description="Importación de librería de reconocimiento de emociones fer",
    ),
    BenchmarkCase(
        case_id="TP-05",
        file_name="social_score.py",
        content="""def evaluate_candidate():
    score = compute_social_score(user_data)
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART05-002",
        description="Invocación de función prohibida de puntuación social",
    ),
    BenchmarkCase(
        case_id="TP-06",
        file_name="api_secret.py",
        content='openai_api_key = "sk-proj-abcdef1234567890abcdef1234567890"\n',
        expected_violation=True,
        expected_rule_id="EUAIA-ART15-002",
        description="Clave de API de OpenAI hardcodeada en texto plano",
    ),
    BenchmarkCase(
        case_id="TP-07",
        file_name="prompt_inj.py",
        content='prompt = f"System prompt... User query: {user_input}"\n',
        expected_violation=True,
        expected_rule_id="EUAIA-ART15-003",
        description="Interpolación no sanitizada en prompt f-string",
    ),
    BenchmarkCase(
        case_id="TP-08",
        file_name="pii_dni.py",
        content='user_dni = "12345678Z"\npayload = f"Process DNI: {user_dni}"\n',
        expected_violation=True,
        expected_rule_id="GDPR-ART05-002",
        description="Fuga de DNI español en código fuente",
    ),
    BenchmarkCase(
        case_id="TP-09",
        file_name="tls_bypass.py",
        content='import requests\nrequests.post("https://api.model/v1", json={}, verify=False)\n',
        expected_violation=True,
        expected_rule_id="GDPR-ART32-002",
        description="Desactivación de verificación TLS (verify=False)",
    ),
    BenchmarkCase(
        case_id="TP-10",
        file_name="requirements.txt",
        content="fastapi>=0.100.0\ndeepface==0.0.79\n",
        expected_violation=True,
        expected_rule_id="EUAIA-ART05-003",
        description="Dependencia prohibida deepface en requirements.txt",
    ),
    BenchmarkCase(
        case_id="TP-11",
        file_name="pyproject.toml",
        content="""[project]
name = "ai-app"
version = "1.0.0"
dependencies = ["face-recognition>=1.3.0"]
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART05-003",
        description="Dependencia prohibida face-recognition en pyproject.toml",
    ),
    BenchmarkCase(
        case_id="TP-12",
        file_name="Dockerfile",
        content="""FROM python:3.11-slim
WORKDIR /app
COPY . .
CMD ["python", "main.py"]
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART15-004",
        description="Dockerfile sin directiva USER (ejecución como root)",
    ),
    BenchmarkCase(
        case_id="TP-13",
        file_name="Dockerfile.insecure",
        content="""FROM python:3.11-slim
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app"]
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART15-005",
        description="Dockerfile exponiendo puerto HTTP de inferencia 8000 sin TLS",
    ),
    BenchmarkCase(
        case_id="TP-14",
        file_name="docker-compose.yml",
        content="""version: '3.8'
services:
  llm_server:
    image: vllm/vllm
    privileged: true
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART15-006",
        description="Servicio en docker-compose con privileged: true",
    ),
    BenchmarkCase(
        case_id="TP-15",
        file_name="partial_branch_leak.py",
        content="""import openai, os
def branch_test(flag):
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    cmd = res.choices[0].message.content
    if flag:
        cmd = guardrails.validate(cmd)
    # En la rama else cmd sigue TAINTED_UNSAFE (operador join pesimista)
    os.system(cmd)
""",
        expected_violation=True,
        expected_rule_id="EUAIA-ART14-002",
        description="Bifurcación condicional parcialmente sanitizada detectada por operador join pesimista",
    ),
]


# 15 Casos Negativos Reales / Conformidad (True Negatives esperados)
TRUE_NEGATIVE_CASES: List[BenchmarkCase] = [
    BenchmarkCase(
        case_id="TN-01",
        file_name="clean_guardrails.py",
        content="""import openai, os, guardrails, logging
def clean_run():
    logging.info("Iniciando llamada auditada")
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    raw = res.choices[0].message.content
    safe_cmd = guardrails.validate(raw)
    os.system(safe_cmd)
""",
        expected_violation=False,
        description="Salida sanitizada con guardrails.validate y logging auditado",
    ),
    BenchmarkCase(
        case_id="TN-02",
        file_name="clean_pydantic.py",
        content="""import openai, os, logging
from pydantic import BaseModel
class ToolSchema(BaseModel):
    command: str
def safe_exec():
    logging.info("Ejecutando inferencia registrada")
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    model = ToolSchema.model_validate(res.choices[0].message.content)
    os.system(model.command)
""",
        expected_violation=False,
        description="Salida validada mediante esquema estricto Pydantic y con logging",
    ),
    BenchmarkCase(
        case_id="TN-03",
        file_name="clean_human_gate.py",
        content="""import openai, os, logging
def human_reviewed():
    logging.info("Llamada con supervisión registrada")
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    cmd = res.choices[0].message.content
    if human_approved:
        os.system(cmd)
""",
        expected_violation=False,
        description="Ejecución de herramienta protegida por compuerta de autorización humana y logging",
    ),
    BenchmarkCase(
        case_id="TN-04",
        file_name="clean_synthetic_watermark.py",
        content="""import openai, logging
def compliant_output():
    logging.info("Generación de contenido sintético registrada")
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    text = res.choices[0].message.content
    safe_text = ai_watermark(text)
    print(safe_text)
""",
        expected_violation=False,
        description="Salida sintética con marca de agua/disclaimer de IA y logging",
    ),
    BenchmarkCase(
        case_id="TN-05",
        file_name="clean_synthetic_moderation.py",
        content="""import openai, logging
def moderated_output():
    logging.info("Generación moderada auditada")
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    text = res.choices[0].message.content
    clean_text = guardrails.validate(text)
    print(clean_text)
""",
        expected_violation=False,
        description="Salida sintética validada con filtro de moderación y logging",
    ),
    BenchmarkCase(
        case_id="TN-06",
        file_name="clean_env_secrets.py",
        content='import os\napi_key = os.environ.get("OPENAI_API_KEY")\n',
        expected_violation=False,
        description="Credencial cargada de forma segura desde variable de entorno",
    ),
    BenchmarkCase(
        case_id="TN-07",
        file_name="clean_structured_messages.py",
        content='messages = [{"role": "system", "content": "You are a helpful assistant"}]\n',
        expected_violation=False,
        description="Mensajes estructurados sin interpolación vulnerable",
    ),
    BenchmarkCase(
        case_id="TN-08",
        file_name="clean_tls.py",
        content='import requests\nrequests.post("https://api.model/v1", json={}, verify=True)\n',
        expected_violation=False,
        description="Petición HTTPS segura con verificación de certificados TLS activada",
    ),
    BenchmarkCase(
        case_id="TN-09",
        file_name="clean_Dockerfile",
        content="""FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN useradd -m appuser
USER appuser
CMD ["python", "main.py"]
""",
        expected_violation=False,
        description="Dockerfile conforme con directiva USER appuser no privilegiada",
    ),
    BenchmarkCase(
        case_id="TN-10",
        file_name="clean_docker_compose.yml",
        content="""version: '3.8'
services:
  web_api:
    image: myorg/api:1.0
    user: "1000:1000"
""",
        expected_violation=False,
        description="Servicio docker-compose con usuario restringido y sin privileged",
    ),
    BenchmarkCase(
        case_id="TN-11",
        file_name="clean_requirements.txt",
        content="fastapi>=0.110.0\npydantic>=2.7.0\ntorch>=2.2.0\n",
        expected_violation=False,
        description="Dependencias estándar y versiones robustas sin librerías prohibidas",
    ),
    BenchmarkCase(
        case_id="TN-12",
        file_name="clean_pyproject.toml",
        content="""[project]
name = "safe-nlp-system"
version = "1.0.0"
dependencies = ["transformers>=4.40.0", "litellm>=1.30.0"]
""",
        expected_violation=False,
        description="Manifiesto pyproject.toml limpio y conforme",
    ),
    BenchmarkCase(
        case_id="TN-13",
        file_name="clean_full_branches.py",
        content="""import openai, os, guardrails, logging
def full_branch_clean(flag):
    logging.info("Ejecución bifurcada con logging")
    res = openai.chat.completions.create(model='gpt-4o', messages=[])
    cmd = res.choices[0].message.content
    if flag:
        cmd = guardrails.validate(cmd)
    else:
        cmd = guardrails.validate(cmd)
    os.system(cmd)
""",
        expected_violation=False,
        description="Bifurcación condicional donde el 100% de los caminos son sanitizados y registrados",
    ),
    BenchmarkCase(
        case_id="TN-14",
        file_name="clean_suppression.py",
        content="""import fer # aicomply:ignore EUAIA-ART05-001
detector = fer.FER()
""",
        expected_violation=False,
        description="Caso con supresión inline explícita auditada # aicomply:ignore",
    ),
    BenchmarkCase(
        case_id="TN-15",
        file_name="clean_system_util.py",
        content="""import os
def backup_dir(path):
    os.system(f"tar -czf backup.tar.gz {path}")
""",
        expected_violation=False,
        description="Comando de utilidades del sistema estándar sin flujo de datos de IA",
    ),
]


def test_precision_recall_benchmark_evaluation(tmp_path: Path):
    """
    Ejecuta la evaluación formal de Precisión, Recall y F1-Score sobre los 30 casos de prueba.
    Verifica que el motor cumpla los estándares de calidad >= 95%.
    """
    rules = load_rules_from_dir(get_default_rules_dir())
    engine = ScanEngine(catalog=rules)

    tp_count = 0  # True Positives
    fp_count = 0  # False Positives
    tn_count = 0  # True Negatives
    fn_count = 0  # False Negatives

    benchmark_dir = tmp_path / "benchmark_suite"
    benchmark_dir.mkdir(parents=True, exist_ok=True)

    # 1. Evaluar casos positivos (deben disparar hallazgos)
    for case in TRUE_POSITIVE_CASES:
        test_file = benchmark_dir / case.file_name
        test_file.write_text(case.content, encoding="utf-8")
        report = engine.scan_path(test_file)

        if len(report.findings) > 0:
            tp_count += 1
            if case.expected_rule_id:
                detected_rules = {f.rule_id for f in report.findings}
                assert case.expected_rule_id in detected_rules, (
                    f"[{case.case_id}] Se esperaba la regla {case.expected_rule_id}, pero se detectó {detected_rules}"
                )
        else:
            fn_count += 1
            print(f"FAILED RECALL ON {case.case_id}: {case.description}")
        test_file.unlink()

    # 2. Evaluar casos negativos / conformes (NO deben disparar hallazgos)
    for case in TRUE_NEGATIVE_CASES:
        test_file = benchmark_dir / case.file_name
        test_file.write_text(case.content, encoding="utf-8")
        report = engine.scan_path(test_file)

        if len(report.findings) == 0:
            tn_count += 1
        else:
            fp_count += 1
            detected = [(f.rule_id, f.title) for f in report.findings]
            print(f"FAILED PRECISION ON {case.case_id} ({case.description}): Falsos positivos detectados {detected}")
        test_file.unlink()

    total_positives = tp_count + fn_count
    total_negatives = tn_count + fp_count

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1_score = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    print(f"\n=======================================================")
    print(f"[BENCHMARK] RESULTADOS DE EVALUACION DE PRECISION Y RECALL (v2.0)")
    print(f"=======================================================")
    print(f"True Positives (TP):  {tp_count}/{total_positives}")
    print(f"True Negatives (TN):  {tn_count}/{total_negatives}")
    print(f"False Positives (FP): {fp_count}")
    print(f"False Negatives (FN): {fn_count}")
    print(f"-------------------------------------------------------")
    print(f">> Precision: {precision * 100:.2f}% (Objetivo: >= 95.00%)")
    print(f">> Recall:    {recall * 100:.2f}% (Objetivo: >= 95.00%)")
    print(f">> F1-Score:  {f1_score * 100:.2f}% (Objetivo: >= 95.00%)")
    print(f"=======================================================\n")

    assert precision >= 0.95, f"La precisión obtenida ({precision*100:.2f}%) es inferior al 95%"
    assert recall >= 0.95, f"El recall obtenido ({recall*100:.2f}%) es inferior al 95%"
    assert f1_score >= 0.95, f"El F1-Score obtenido ({f1_score*100:.2f}%) es inferior al 95%"
