"""
AIComply - CLI Entrypoint (Typer)
"""

from enum import Enum
from pathlib import Path
from typing import Optional, Set
import typer
from rich.console import Console

from aicomply.reporter.json_report import generate_json_report
from aicomply.reporter.markdown_report import generate_markdown_report
from aicomply.reporter.terminal import render_terminal_report
from aicomply.reporter.sarif_reporter import generate_sarif_report
from aicomply.rules.loader import RuleLoadError, load_rules_from_dir
from aicomply.scanner.engine import ScanEngine

from aicomply.classifier.assess import (
    render_assessment_report,
    run_interactive_assessment,
)

from aicomply.generator.annex_iv import AnnexIVGenerator


app = typer.Typer(
    name="aicomply",
    help="CLI de cumplimiento técnico y análisis determinista del EU AI Act.",
    add_completion=False,
)
console = Console()

@app.callback()
def main() -> None:
    """CLI de cumplimiento técnico y análisis determinista del EU AI Act."""
    pass

class OutputFormat(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"

def get_default_rules_dir() -> Path:
    """
    Obtiene la ruta base del catálogo de reglas
    """
    return Path(__file__).parent / "rules"


@app.command(name="scan")
def scan(
    path: Path = typer.Argument(
        ...,
        help="Ruta al archivo o directorio a auditar.",
        exists=True,
        resolve_path=True,
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.TERMINAL,
        "--format",
        "-f",
        help="Formato de salida del reporte (terminal, markdown, json).",
    ),
    articles: Optional[str] = typer.Option(
        None,
        "--articles",
        "-a",
        help="Filtrar por artículos separados por comas (ej. 5,12,13).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Ruta para guardar el reporte emitido en disco.",
    ),
    evidence: bool = typer.Option(
        False,
        "--evidence",
        help="Incluir identificadores criptográficos SHA-256 por cada hallazgo.",
    ),
    rules_dir: Optional[Path] = typer.Option(
        None,
        "--rules-dir",
        help="Directorio personalizado de reglas YAML.",
    ),
) -> None:
    """Escanea el código fuente en busca de infracciones del EU AI Act."""
    rules_path = rules_dir or get_default_rules_dir()

    try:
        catalog = load_rules_from_dir(rules_path)
    except RuleLoadError as err:
        console.print(f"[bold red]Error al cargar el catálogo de reglas:[/bold red] {err}")
        raise typer.Exit(code=2)

    target_articles: Optional[Set[str]] = None
    if articles:
        target_articles = {art.strip() for art in articles.split(",") if art.strip()}

    engine = ScanEngine(catalog=catalog, target_articles=target_articles)

    try:
        report = engine.scan_path(path)
    except Exception as exc:
        console.print(f"[bold red]Error durante la ejecución del escaneo:[/bold red] {exc}")
        raise typer.Exit(code=2)

    # Gestión de salida según formato
    if output:
        if format == OutputFormat.JSON:
            content = generate_json_report(report)
        elif format == OutputFormat.SARIF:
            content = generate_sarif_report(report)
        else:
            content = generate_markdown_report(report, include_evidence=evidence)
            
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Reporte guardado exitosamente en:[/green] {output}")
    else:
        if format == OutputFormat.JSON:
            typer.echo(generate_json_report(report))
        elif format == OutputFormat.SARIF:
            typer.echo(generate_sarif_report(report))
        elif format == OutputFormat.MARKDOWN:
            typer.echo(generate_markdown_report(report, include_evidence=evidence))
        else:
            render_terminal_report(report, include_evidence=evidence, console=console)

    if report.summary.total_findings > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)

@app.command(name="assess")
def assess() -> None:
    """Asistente interactivo guiado para clasificar el nivel de riesgo de un caso de uso."""
    result = run_interactive_assessment(console=console)
    render_assessment_report(result, console=console)

@app.command(name="docgen")
def docgen(
    path: Path = typer.Argument(
        ...,
        help="Ruta al repositorio del proyecto para auditar y documentar.",
        exists=True,
        resolve_path=True,
    ),
    system_name: str = typer.Option(
        "AI-Production-System",
        "--name",
        "-n",
        help="Nombre formal del sistema de IA para el dossier.",
    ),
    system_version: str = typer.Option(
        "1.0.0",
        "--version",
        "-v",
        help="Versión del sistema de IA.",
    ),
    output: Path = typer.Option(
        Path("ANNEX_IV_TECHNICAL_DOCS.md"),
        "--output",
        "-o",
        help="Ruta del archivo Markdown donde se guardará el expediente.",
    ),
    rules_dir: Optional[Path] = typer.Option(
        None,
        "--rules-dir",
        help="Directorio personalizado de reglas YAML.",
    ),
) -> None:
    """Genera el Dossier de Documentación Técnica formal exigido por el Anexo IV del EU AI Act."""
    rules_path = rules_dir or get_default_rules_dir()

    try:
        catalog = load_rules_from_dir(rules_path)
    except RuleLoadError as err:
        console.print(f"[bold red]Error al cargar catálogo de reglas:[/bold red] {err}")
        raise typer.Exit(code=2)

    engine = ScanEngine(catalog=catalog)

    with console.status("[bold cyan]Analizando arquitectura y generando expediente Anexo IV...[/bold cyan]"):
        report = engine.scan_path(path)
        generator = AnnexIVGenerator(report, system_name=system_name, version=system_version)
        dossier_md = generator.generate_markdown_dossier()
        output.write_text(dossier_md, encoding="utf-8")

    console.print(f"[bold green][OK] Expediente Anexo IV generado con éxito:[/bold green] {output.resolve()}")

if __name__ == "__main__":
    app()