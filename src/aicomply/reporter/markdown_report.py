"""Plain-text-safe Markdown reports of technical signals."""

from html import escape
import re
import unicodedata

from aicomply.schemas import ScanReport


def display_text(value: str) -> str:
    return "".join(
        f"\\u{ord(char):04x}"
        if unicodedata.category(char).startswith("C") and char not in "\n\t"
        else char for char in value
    )


def safe_text(value: str) -> str:
    value = display_text(value)
    value = re.sub(r"([\\`*_\[\]{}()#+>~])", r"\\\1", escape(value))
    return value.replace("|", "&#124;").replace("\n", " / ").replace("\r", "")


def generate_markdown_report(report: ScanReport, include_evidence: bool = False) -> str:
    lines = [
        "# AIComply — Revisión técnica EU AI Act / RGPD",
        "",
        "> La aplicabilidad normativa y la clasificación jurídica requieren revisión humana.",
        "> Los máximos sancionadores son referencias; no son predicciones ni multas evitadas.",
        "",
        f"**Target:** {safe_text(report.target_path)}",
        f"**Scan ID (hallazgos):** {safe_text(report.scan_id)}",
        f"**Manifiesto de fuentes:** {safe_text(report.source_manifest_hash or 'No disponible')}",
        f"**Catálogo:** {safe_text(report.rules_fingerprint or 'No disponible')}",
        f"**Configuración:** {safe_text(report.config_fingerprint or 'No disponible')}",
        "",
        "## Alcance",
        f"- Archivos analizados: {report.summary.total_files_scanned}",
        f"- Líneas de texto analizadas: {report.summary.total_lines_scanned}",
        f"- Reglas activas: {report.summary.rules_loaded}",
        f"- Rutas excluidas: {len(report.exclusions)} (detalle en JSON)",
        f"- Señales técnicas: {report.summary.total_findings}",
        "",
        "## Limitaciones",
        *[f"- {safe_text(item)}" for item in report.limitations],
        "",
    ]
    if not report.findings:
        lines.append("**Sin hallazgos en el alcance analizado. No acredita conformidad legal.**")
    for index, finding in enumerate(report.findings, 1):
        lines.extend([
            f"## {index}. {safe_text(finding.rule_id)} — {safe_text(finding.title)}",
            f"- Severidad técnica: {finding.severity.value}; confianza del patrón: {finding.confidence.value}",
            f"- Referencia a revisar: {safe_text(finding.article)}",
            f"- Etiqueta del catálogo: {finding.risk_tier.value}",
            f"- Ubicación: {safe_text(finding.location.file_path)}:{finding.location.start_line}",
            f"- Observación: {safe_text(finding.message)}",
            f"- Remediación propuesta: {safe_text(finding.remediation)}",
            f"- Máximo normativo de referencia: {safe_text(finding.max_fine)}",
        ])
        if finding.code_snippet:
            lines.extend(["", "<pre>" + escape(display_text(finding.code_snippet)) + "</pre>"])
        if include_evidence:
            lines.append(f"- Hash de hallazgo: {safe_text(finding.id)}")
        lines.append("")
    return "\n".join(lines)
