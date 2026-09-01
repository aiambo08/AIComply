"""
AIComply - Throughput and Latency Performance Benchmark
Valida que el escaneo completo (AST + Taint + Infra + Regex + Hasher)
mantenga rendimiento submétrico (< 1000ms para miles de líneas de código).
"""

import time
from pathlib import Path
from aicomply.cli import get_default_rules_dir
from aicomply.rules.loader import load_rules_from_dir
from aicomply.scanner.engine import ScanEngine


def test_scan_throughput_and_latency(tmp_path: Path):
    """Genera un proyecto sintético de gran tamaño y mide el tiempo de ejecución."""
    rules = load_rules_from_dir(get_default_rules_dir())
    engine = ScanEngine(catalog=rules)

    project_dir = tmp_path / "large_synth_repo"
    project_dir.mkdir(parents=True, exist_ok=True)

    # 1. Crear múltiples módulos Python (20 archivos de ~100 líneas cada uno)
    for i in range(20):
        module_file = project_dir / f"module_{i}.py"
        code_lines = [
            "import os",
            "import json",
            "import openai",
            "from typing import List, Dict",
            f"def process_batch_{i}(items: List[str]) -> Dict[str, str]:",
            "    results = {}",
            "    for item in items:",
            "        # Simulación de pipeline de inferencia estructurado",
            "        data = {'key': item.strip().lower()}",
            "        results[item] = json.dumps(data)",
            "    return results",
        ]
        # Rellenar con funciones auxiliares
        for j in range(15):
            code_lines.extend([
                f"def helper_func_{i}_{j}(x: int, y: int) -> int:",
                f"    val = x * {j} + y",
                "    return val",
            ])
        module_file.write_text("\n".join(code_lines), encoding="utf-8")

    # 2. Crear archivo Dockerfile
    dockerfile = project_dir / "Dockerfile"
    dockerfile.write_text("""FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN useradd -m appuser
USER appuser
CMD ["python", "module_0.py"]
""", encoding="utf-8")

    # 3. Crear pyproject.toml
    pyproject = project_dir / "pyproject.toml"
    pyproject.write_text("""[project]
name = "benchmark-system"
version = "2.0.0"
dependencies = [
    "fastapi>=0.110.0",
    "pydantic>=2.7.0",
    "uvicorn>=0.29.0",
]
""", encoding="utf-8")

    # 4. Medir tiempo de ejecución del escaneo completo
    start_time = time.perf_counter()
    report = engine.scan_path(project_dir)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    print(f"\n=======================================================")
    print(f"[BENCHMARK] RENDIMIENTO Y LATENCIA DE ESCANEO")
    print(f"=======================================================")
    print(f"Archivos escaneados:   {report.summary.total_files_scanned}")
    print(f"Lineas analizadas:     {report.summary.total_lines_scanned}")
    print(f"Tiempo total medido:   {elapsed_ms:.2f} ms")
    print(f"Velocidad de analisis: {report.summary.total_lines_scanned / (elapsed_ms / 1000):.0f} lineas/segundo")
    print(f"=======================================================\n")

    assert report.summary.total_files_scanned >= 22
    assert report.summary.total_lines_scanned >= 1000
    # El escaneo de más de 1000 líneas debe completarse en menos de 1 segundo (1000ms)
    assert elapsed_ms < 1000.0, f"El tiempo de escaneo ({elapsed_ms:.2f}ms) superó el límite de 1000ms"
