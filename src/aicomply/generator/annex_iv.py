"""Nine-part Annex IV working draft using only captured scan evidence."""

from aicomply._version import __version__
from aicomply.reporter.markdown_report import generate_markdown_report, safe_text
from aicomply.schemas import ScanReport


class AnnexIVGenerator:
    def __init__(self, report: ScanReport, system_name: str = "AI System", version: str = "1.0.0") -> None:
        self.report = report
        self.system_name = system_name
        self.version = version

    def generate_markdown_dossier(self) -> str:
        sections = [
            ("Identificación y Descripción General del Sistema",
             "Finalidad prevista; proveedor y contacto; rol; versión y cambios; usuarios y personas afectadas; "
             "interacción con hardware/software; modalidades de comercialización; instrucciones; interfaz."),
            ("Métodos de Desarrollo y Componentes de Software",
             "Diseño, lógica y algoritmos; arquitectura; terceros; decisiones de diseño; datos y procedencia; "
             "selección, etiquetado y limpieza; entrenamiento, validación y prueba; supervisión humana; "
             "cambios predeterminados; ciberseguridad; métricas, grupos evaluados y resultados fechados."),
            ("Monitorización, Registro y Trazabilidad",
             "Capacidades, limitaciones y precisión por grupo; riesgos previsibles; efectos discriminatorios; "
             "supervisión humana; especificaciones de entradas; controles operativos y evidencias de logs."),
            ("Adecuación de las Métricas de Rendimiento",
             "Justificación de métricas para el sistema y finalidad concretos; umbrales; incertidumbre; "
             "evaluación de robustez, exactitud y seguridad en condiciones representativas."),
            ("Sistema de Gestión de Riesgos",
             "Descripción del proceso del Art. 9; peligros, riesgos residuales, controles, responsables, "
             "aceptaciones, pruebas y revisión continua."),
            ("Cambios Durante el Ciclo de Vida",
             "Historial de cambios relevantes, impacto, aprobaciones, revalidación y control de versiones."),
            ("Normas y Especificaciones Aplicadas",
             "Normas armonizadas o especificaciones comunes realmente aplicadas; cobertura y alternativas "
             "técnicas para requisitos no cubiertos. No presumir certificaciones."),
            ("Declaración UE de Conformidad",
             "Copia de la declaración emitida por el responsable y procedimiento de evaluación aplicable. "
             "Este borrador no emite ninguna declaración."),
            ("Vigilancia Poscomercialización",
             "Plan del Art. 72: fuentes, métricas, periodicidad, responsables, incidentes, acciones "
             "correctivas y retroalimentación de usuarios."),
        ]
        lines = [
            "# BORRADOR — DOCUMENTACIÓN TÉCNICA (ANEXO IV)",
            "",
            "> REQUIERE REVISIÓN Y EVIDENCIAS DEL RESPONSABLE. No constituye certificación ni declaración UE de conformidad.",
            "> La aplicabilidad del Art. 11 y el Anexo IV depende de la clasificación y del rol.",
            "",
            "Fuente: https://eur-lex.europa.eu/eli/reg/2024/1689/oj — Anexo IV, puntos 1–9.",
            "Estructura revisada el 2026-09-20; comprobar versión normativa vigente antes de aprobar.",
            "",
            f"- Sistema declarado: {safe_text(self.system_name)}",
            f"- Versión declarada: {safe_text(self.version)}",
            f"- Fecha del escaneo: {safe_text(self.report.timestamp)}",
            f"- Generador: AIComply {__version__}",
            "- Clasificación jurídica: PENDIENTE; no puede inferirse del recuento de hallazgos.",
            "- Responsable / revisor / aprobación / evidencias externas: PENDIENTE.",
            "",
        ]
        for index, (title, required) in enumerate(sections, 1):
            lines.extend([
                f"## SECCIÓN {index} — {title}",
                "",
                "**Estado: PENDIENTE DE COMPLETAR Y VALIDAR.**",
                required,
                "",
            ])
            if index == 2:
                lines.append("### Imports observados en los bytes analizados")
                names = {
                    "openai": "OpenAI SDK", "torch": "PyTorch", "langchain": "LangChain",
                    "transformers": "Hugging Face Transformers",
                    "logging": "Sistema de Registro y Auditoría (import; operación no verificada)",
                }
                for path, modules in sorted(self.report.source_imports.items()):
                    for module in modules:
                        lines.append(f"- {safe_text(path)}: {safe_text(names.get(module, module))}")
                if not self.report.source_imports:
                    lines.append("- Inventario no disponible en este reporte.")
                lines.extend([
                    "",
                    "Un import no prueba uso, modelo, versión, licencia, configuración ni efectividad de controles.",
                    "",
                ])
        lines.extend([
            "## APÉNDICE — Señales técnicas y procedencia",
            "",
            generate_markdown_report(self.report, include_evidence=True),
            "",
            "## Integridad y conservación",
            "",
            "El scan_id identifica el conjunto de hallazgos. El manifiesto identifica los bytes capturados; "
            "no certifica código posterior ni archivos excluidos. Conservar el JSON firmado, fuentes, "
            "configuración y catálogo junto a las evidencias externas. Este Markdown no está firmado.",
        ])
        return "\n".join(lines)
