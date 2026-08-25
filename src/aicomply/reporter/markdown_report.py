"""
AIComply - Markdown Report Generator
Salida en formato tabla y bloques de texto scannable para CLI y GitHub Step Summaries.
"""

from aicomply.classifier.risk_tier import classify_overall_risk
from aicomply.schemas import ScanReport


def generate_markdown_report(report: ScanReport, include_evidence: bool = False) -> str:
    """Genera un reporte legible en Markdown estructurado."""
    overall_tier = classify_overall_risk(report.findings)

    lines = [
        "# AIComply — Reporte de Cumplimiento EU AI Act",
        f"\n**Target:** `{report.target_path}` | **Scan ID:** `{report.scan_id[:12]}` | **Timestamp:** `{report.timestamp}`",
        f"**Clasificación Global:** `{overall_tier.value.upper()}`\n",
        "## Resumen Ejecutivo\n",
        "| Métrica | Valor |",
        "|---|---|",
        f"| Archivos analizados | {report.summary.total_files_scanned} |",
        f"| Líneas de código | {report.summary.total_lines_scanned:,} |",
        f"| Reglas aplicadas | {report.summary.rules_loaded} |",
        f"| Hallazgos totales | {report.summary.total_findings} |",
        f"| Tiempo de ejecución | {report.summary.execution_time_ms} ms |",
        "",
        "### Hallazgos por Nivel de Riesgo\n",
        "| Nivel de Riesgo | Cantidad |",
        "|---|---|",
    ]

    for tier, count in report.summary.findings_by_tier.items():
        lines.append(f"| {tier.value.replace('_', ' ').title()} | {count} |")

    if not report.findings:
        lines.append("\n> **Conformidad validada:** No se detectaron patrones de riesgo con el catálogo de reglas cargado.")
        return "\n".join(lines)

    lines.extend([
        "\n## Detalle de No-Conformidades Detectadas\n",
        "| Severidad | Artículo | Regla | Ubicación | Multa Potencial |",
        "|---|---|---|---|---|",
    ])

    for f in report.findings:
        loc = f"{f.location.file_path}:{f.location.start_line}"
        lines.append(f"| **{f.severity.value}** | {f.article} | {f.title} | `{loc}` | {f.max_fine} |")

    lines.append("\n## Planes de Remediación Técnica\n")

    for idx, f in enumerate(report.findings, start=1):
        lines.extend([
            f"### {idx}. [{f.rule_id}] {f.title}",
            f"- **Artículo:** {f.article} ({f.risk_tier.value})",
            f"- **Ubicación:** `{f.location.file_path}:{f.location.start_line}`",
            f"- **Multa evitada:** {f.max_fine}",
            f"- **Remediación:** {f.remediation}",
        ])
        if f.code_snippet:
            lines.extend([
                "- **Código detectado:**",
                "```python",
                f.code_snippet,
                "```",
            ])
        if include_evidence:
            lines.append(f"- **Hash SHA-256:** `{f.id}`")
        lines.append("")

    return "\n".join(lines)