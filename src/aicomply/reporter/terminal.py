"""
AIComply - Rich Terminal Reporter
Renderizado visual de auditorías, tablas estructuradas, alertas de severidad
y planes de remediación técnica en consola.
"""

from typing import Optional
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from aicomply.classifier.risk_tier import classify_overall_risk
from aicomply.reporter.markdown_report import display_text
from aicomply.schemas import Finding, RiskTier, ScanReport, Severity
from aicomply._version import __version__

# Mapeo de estilos y etiquetas por Nivel de Riesgo
RISK_TIER_STYLES = {
    RiskTier.PROHIBITED: ("REVISAR ART. 5", "bold white on red"),
    RiskTier.HIGH_RISK: ("REVISAR ALTO RIESGO", "bold red"),
    RiskTier.LIMITED_RISK: ("REVISAR TRANSPARENCIA", "bold yellow"),
    RiskTier.MINIMAL_RISK: ("SIN ETIQUETA ELEVADA", "bold green"),
}

# Mapeo de etiquetas con badges para Severidad Técnica
SEVERITY_BADGES = {
    Severity.CRITICAL: "[bold white on red] CRITICAL [/]",
    Severity.HIGH: "[bold red] HIGH [/]",
    Severity.MEDIUM: "[bold yellow] MEDIUM [/]",
    Severity.LOW: "[bold blue] LOW [/]",
    Severity.INFO: "[bold cyan] INFO [/]",
}

def render_terminal_report(
    report: ScanReport, 
    include_evidence: bool = False,
    console: Optional[Console] = None,
    ) -> None:

    """
    Renderiza el informe completo de auditoría técnica en la consola
    """
    console = console or Console()
    overall_tier = classify_overall_risk(report.findings)
    tier_label, tier_style = RISK_TIER_STYLES.get(overall_tier, (overall_tier.value, "white"))
    if not report.findings:
        tier_label = "CLASIFICACIÓN JURÍDICA NO EVALUADA"

    # 1. Cabecerea principal
    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left", ratio=3)
    header_table.add_column(justify="right", ratio=2)
    header_table.add_row(
        f"[bold cyan]AIComply[/bold cyan] [dim]v{__version__}[/dim] - EU AI Act & GDPR Scanner",
        Text(f"Scan ID: {display_text(report.scan_id[:12])}"),
    )
    header_table.add_row(
        Text(f"Target: {display_text(report.target_path)}"),
        Text(f"UTC: {display_text(report.timestamp[:19].replace('T', ' '))}"),
    )
    header_table.add_row(
        f"[dim]Prioridad técnica:[/dim] [{tier_style}] {tier_label} [/{tier_style}]",
        f"[dim]Tiempo:[/dim] {report.summary.execution_time_ms:.2f} ms",
    )

    console.print()
    console.print(
        Panel(
            header_table,
            title="[bold blue]REVISIÓN TÉCNICA — REQUIERE CONTEXTO REGULATORIO[/bold blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
    )

    # 2. Métricas y Resumen
    summary_tables = Table(
        box=box.SIMPLE_HEAVY,
        header_style="bold magenta",
        expand=True,
        title="[bold]Resumen de Métricas de Código[/bold]",
        title_justify="left",
    )
    summary_tables.add_column("Archivos", justify="center")
    summary_tables.add_column("Líneas de texto", justify="center")
    summary_tables.add_column("Reglas Evaluadas", justify="center")
    summary_tables.add_column("Hallazgos Totales", justify="center")
    summary_tables.add_column("Señales Art. 5", justify="center")
    summary_tables.add_column("Alto Riesgo (P1)", justify="center")

    summary_tables.add_row(
        str(report.summary.total_files_scanned),
        f"{report.summary.total_lines_scanned:,}",
        str(report.summary.rules_loaded),
        f"[bold red]{report.summary.total_findings}[/bold red]"
        if report.summary.total_findings > 0 else
        "[green]0[/green]",
        str(report.summary.findings_by_tier[RiskTier.PROHIBITED]),
        str(report.summary.findings_by_tier[RiskTier.HIGH_RISK]),
    )
    console.print(summary_tables)
    for limitation in report.limitations:
        console.print(Text(display_text(limitation), style="dim"))

    # 3. Estado Limpio (Sin no-conformidades)
    if not report.findings:
        console.print(
            Panel(
                "[bold green]SIN HALLAZGOS EN EL ALCANCE ANALIZADO[/bold green]\n"
                "[dim]No acredita conformidad legal ni garantiza ausencia de multas.[/dim]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return

    # 4. Tabla de No-Conformidades
    findings_table = Table(
        box=box.MINIMAL_DOUBLE_HEAD,
        header_style="bold cyan",
        expand=True,
        title="[bold]Señales Técnicas para Revisión[/bold]",
        title_justify="left",
    )
    findings_table.add_column("Severidad", justify="center", width=12)
    findings_table.add_column("Artículo", justify="left", width=14)
    findings_table.add_column("Regla / Título", justify="left", ratio=3)
    findings_table.add_column("Ubicación", justify="left", ratio=2)
    findings_table.add_column("Máximo normativo", justify="right", width=16)

    for f in report.findings:
        badge = SEVERITY_BADGES.get(f.severity, f.severity.value)
        loc_str = Text(f"{display_text(f.location.file_path)}:{f.location.start_line}")
        fine_str = Text(display_text(f.max_fine))
        
        findings_table.add_row(
            badge,
            Text(display_text(f.article)),
            Text(display_text(f.title)),
            loc_str,
            fine_str,
        )

    console.print(findings_table)
    console.print()

    # 5. Desglose de Remediación Técnica
    console.print("[bold]Instrucciones de Remediación y Evidencia Técnica[/bold]")
    for idx, f in enumerate(report.findings, start=1):
        content_table = Table.grid(padding=(0, 1), expand=True)
        content_table.add_column(style="bold dim", width=16)
        content_table.add_column()

        content_table.add_row("Regla:", Text(display_text(f"{f.rule_id} — {f.title}")))
        content_table.add_row("Artículo:", Text(display_text(f"{f.article} (Etiqueta: {f.risk_tier.value})")))
        content_table.add_row("Ubicación:", Text(display_text(f"{f.location.file_path} (Líneas {f.location.start_line}-{f.location.end_line})")))
        content_table.add_row("Máximo normativo:", Text(display_text(f.max_fine)))
        content_table.add_row("Acción propuesta:", Text(display_text(f.remediation)))

        if include_evidence:
            content_table.add_row("SHA-256:", Text(display_text(f.id), style="dim"))

        # Render de snippet de código si existe
        if f.code_snippet:
            syntax = Syntax(
                display_text(f.code_snippet),
                "python",
                theme="monokai",
                line_numbers=True,
                start_line=f.location.start_line,
                highlight_lines={f.location.start_line},
            )
            panel_renderable = Table.grid(expand=True)
            panel_renderable.add_row(content_table)
            panel_renderable.add_row(Text(""))
            panel_renderable.add_row(syntax)
        else:
            panel_renderable = content_table

        border_color = "red" if f.severity in {Severity.CRITICAL, Severity.HIGH} else "yellow"
        console.print(
            Panel(
                panel_renderable,
                title=Text(display_text(f"Hallazgo #{idx} — {f.rule_id}"), style=f"bold {border_color}"),
                border_style=border_color,
                box=box.ROUNDED,
            )
        )