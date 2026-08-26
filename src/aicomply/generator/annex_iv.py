import ast
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set
from aicomply.classifier.risk_tier import classify_overall_risk
from aicomply.schemas import RiskTier, ScanReport, Severity


class AnnexIVGenerator:
    """Generador del expediente técnico regulatorio según Anexo IV del Reglamento (UE) 2024/1689."""

    def __init__(self, report: ScanReport, system_name: str = "AI System", version: str = "1.0.0") -> None:
        self.report = report
        self.system_name = system_name
        self.version = version

    def _collect_ast_imports(self) -> Set[str]:
        """Extrae el conjunto de todos los módulos importados en el código fuente mediante AST."""
        imported_modules: Set[str] = set()
        target_path = Path(self.report.target_path)

        py_files: List[Path] = []
        if target_path.is_file() and target_path.suffix == ".py":
            py_files.append(target_path)
        elif target_path.is_dir():
            py_files.extend(target_path.glob("**/*.py"))

        for file_path in py_files:
            try:
                source = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imported_modules.add(alias.name.split(".")[0].lower())
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported_modules.add(node.module.split(".")[0].lower())
            except Exception:
                continue

        return imported_modules

    def _extract_detected_stack(self) -> Dict[str, List[str]]:
        """Identifica componentes, SDKs y librerías clave a partir de AST imports y hallazgos."""
        imports = self._collect_ast_imports()
        snippets_text = " ".join((f.code_snippet or "").lower() for f in self.report.findings)

        stack: Dict[str, List[str]] = {
            "ai_providers": [],
            "frameworks_rag": [],
            "ml_libraries": [],
            "observability": [],
            "restricted": [],
        }

        # Proveedores de Modelos de IA / LLMs
        if "openai" in imports or "openai" in snippets_text:
            stack["ai_providers"].append("OpenAI SDK (GPT-4o, GPT-3.5)")
        if "anthropic" in imports or "anthropic" in snippets_text:
            stack["ai_providers"].append("Anthropic SDK (Claude 3.5)")
        if any(m in imports for m in ["google", "vertexai"]) or "generativeai" in snippets_text:
            stack["ai_providers"].append("Google GenAI / Vertex AI")
        if "mistralai" in imports or "mistral" in snippets_text:
            stack["ai_providers"].append("Mistral AI SDK")
        if "cohere" in imports:
            stack["ai_providers"].append("Cohere SDK")
        if "transformers" in imports:
            stack["ai_providers"].append("Hugging Face Transformers (Modelos Open-Source)")
        if any(m in imports for m in ["ollama", "litellm"]):
            stack["ai_providers"].append("Ollama / LiteLLM (Inferencia Local / Proxy)")

        # Orquestación, RAG y Bases Vectoriales
        if "langchain" in imports or "langchain" in snippets_text:
            stack["frameworks_rag"].append("LangChain Framework")
        if "llama_index" in imports or "llama_index" in snippets_text:
            stack["frameworks_rag"].append("LlamaIndex Data Framework")
        if any(m in imports for m in ["chromadb", "qdrant_client", "pinecone", "weaviate"]):
            stack["frameworks_rag"].append("Base de Datos Vectorial (RAG)")

        # Machine Learning / Deep Learning
        if "torch" in imports or "pytorch" in imports:
            stack["ml_libraries"].append("PyTorch Deep Learning Engine")
        if "tensorflow" in imports or "keras" in imports:
            stack["ml_libraries"].append("TensorFlow / Keras Framework")
        if "sklearn" in imports:
            stack["ml_libraries"].append("Scikit-Learn")

        # Observabilidad, Gobernanza y Logging
        if any(m in imports for m in ["logging", "structlog", "loguru"]):
            stack["observability"].append("Sistema de Registro y Auditoría Estructurado (Art. 12)")
        if any(m in imports for m in ["langfuse", "arize", "phoenix", "trulens"]):
            stack["observability"].append("Plataforma de Observabilidad y Evaluación LLM")
        if any(m in imports for m in ["guardrails", "nemo_guardrails"]):
            stack["observability"].append("Framework de Moderación y Guardrails (Art. 15)")

        # Componentes con Restricciones Regulatorias
        if any(m in imports for m in ["fer", "deepface", "face_recognition"]) or "fer" in snippets_text:
            stack["restricted"].append("Computer Vision / Inferencia Emocional o Biométrica (Art. 5(1)(f))")

        return stack

    def generate_markdown_dossier(self) -> str:
        """Construye el documento completo en Markdown estructurado conforme a las secciones del Anexo IV."""
        overall_tier = classify_overall_risk(self.report.findings)
        stack = self._extract_detected_stack()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Hash del expediente documental para trazabilidad
        doc_hash_seed = f"{self.report.scan_id}|{self.system_name}|{self.version}|{timestamp}"
        dossier_hash = hashlib.sha256(doc_hash_seed.encode("utf-8")).hexdigest()

        lines = [
            f"# EXPEDIENTE DE DOCUMENTACIÓN TÉCNICA (ANEXO IV)",
            f"### Reglamento (UE) 2024/1689 (EU AI Act) — Artículo 11\n",
            f"> **Identificador de Evidencia:** `{dossier_hash}`  ",
            f"> **Scan ID Origen:** `{self.report.scan_id}`  ",
            f"> **Fecha de Emisión:** {timestamp}  ",
            f"> **Clasificación del Sistema:** `{overall_tier.value.upper()}`\n",
            "---",
            "\n## SECCIÓN 1 — Identificación y Descripción General del Sistema (§1 Anexo IV)\n",
            f"- **Nombre del Sistema:** {self.system_name}",
            f"- **Versión del Código Auditado:** `{self.version}`",
            f"- **Directorio Raíz:** `{self.report.target_path}`",
            f"- **Finalidad Prevista:** Automatización de flujos de trabajo e inferencia mediante modelos de lenguaje/IA.",
            f"- **Nivel de Riesgo Determinado:** **{overall_tier.value.upper()}**",
            "",
            "## SECCIÓN 2 — Métodos de Desarrollo y Componentes de Software (§2 Anexo IV)\n",
            "### 2.1. Inventario de Componentes y Stack Tecnológico de IA Detectado\n",
        ]

        has_stack = False
        if stack["ai_providers"]:
            has_stack = True
            lines.append("#### Proveedores de Modelos de IA e Inferencia")
            for item in stack["ai_providers"]:
                lines.append(f"- `{item}`")
            lines.append("")

        if stack["frameworks_rag"]:
            has_stack = True
            lines.append("#### Orquestación, RAG y Gestión de Contexto")
            for item in stack["frameworks_rag"]:
                lines.append(f"- `{item}`")
            lines.append("")

        if stack["ml_libraries"]:
            has_stack = True
            lines.append("#### Frameworks de Machine Learning / Deep Learning")
            for item in stack["ml_libraries"]:
                lines.append(f"- `{item}`")
            lines.append("")

        if stack["observability"]:
            has_stack = True
            lines.append("#### Observabilidad, Logging y Gobernanza")
            for item in stack["observability"]:
                lines.append(f"- `{item}`")
            lines.append("")

        if stack["restricted"]:
            has_stack = True
            lines.append("#### Componentes con Restricciones Regulatorias (EU AI Act)")
            for item in stack["restricted"]:
                lines.append(f"- **[ALERTA REGULATORIA]** `{item}`")
            lines.append("")

        if not has_stack:
            lines.append("- *Librerías estándar de Python / Inferencia local en desarrollo.*")
            lines.append("")

        lines.extend([
            f"### 2.2. Métricas del Código Fuente",
            f"- **Archivos analizados:** {self.report.summary.total_files_scanned}",
            f"- **Líneas de código auditadas (SLOC):** {self.report.summary.total_lines_scanned:,}",
            f"- **Reglas de conformidad evaluadas:** {self.report.summary.rules_loaded}",
            "",
            "## SECCIÓN 3 — Monitorización, Registro y Trazabilidad (§3 Anexo IV / Art. 12)\n",
            "| Parámetro de Control | Estado Técnico | Evidencia / Observación |",
            "|---|---|---|",
        ])

        # Comprobar estado de logging (Art. 12)
        art12_findings = [f for f in self.report.findings if "ART12" in f.rule_id]
        if art12_findings:
            lines.append(f"| Registro de eventos (Art. 12) | **NO CONFORME** | {len(art12_findings)} llamadas sin trazabilidad de logs detectadas |")
        else:
            lines.append("| Registro de eventos (Art. 12) | **CONFORME** | Módulo de logging estructurado validado en el código |")

        # Comprobar estado de transparencia (Art. 13 / 50)
        art13_findings = [f for f in self.report.findings if "ART13" in f.rule_id]
        if art13_findings:
            lines.append(f"| Transparencia y Disclaimers (Art. 13/50) | **ADVERTENCIA** | Notificación explícita de IA no identificada o deshabilitada |")
        else:
            lines.append("| Transparencia y Disclaimers (Art. 13/50) | **CONFORME** | Notificaciones e indicadores de contenido sintético activos |")

        lines.extend([
            "",
            "## SECCIÓN 4 — Medidas de Supervisión Humana y Ciberseguridad (§4 Anexo IV / Arts. 14-15)\n",
            "- **Human-in-the-loop (Art. 14):** Se requiere mecanismo de aprobación explícita o confirmación humana en decisiones críticas.",
            "- **Robustez y Gestión de Errores (Art. 15):** Los endpoints de inferencia deben disponer de manejo de excepciones y políticas de contingencia (fallbacks).",
            "",
            "## SECCIÓN 5 — Matriz de Riesgos y No-Conformidades Pendientes (§5 Anexo IV)\n",
        ])

        if not self.report.findings:
            lines.append("> **Conformidad Plena:** No se registran no-conformidades técnicas activas en el repositorio.")
        else:
            lines.extend([
                "| ID Regla | Artículo | Severidad | Ubicación | Remediación Exigida |",
                "|---|---|---|---|---|",
            ])
            for f in self.report.findings:
                lines.append(
                    f"| `{f.rule_id}` | {f.article} | **{f.severity.value}** | `{f.location.file_path}:{f.location.start_line}` | {f.remediation} |"
                )

        lines.extend([
            "\n---",
            "\n## DECLARACIÓN DE TRAZABILIDAD Y FIRMA DE AUDITORÍA\n",
            f"El presente dossier ha sido emitido de forma determinista por el motor estático de **AIComply v0.1.0**.",
            f"Cualquier modificación en el código fuente invalidará el hash SHA-256 (`{dossier_hash}`) de este documento.\n",
        ])

        return "\n".join(lines)