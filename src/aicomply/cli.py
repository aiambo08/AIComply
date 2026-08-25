"""
AIComply - CLI Entrypoint (Typer)
"""

from enum import Enum
from pathlib import Path
from typing import Optional, Set
import sys
import typer
from rich.console import Console

from aicomply.evidence.hasher import compute_scan_hash
from aicomply.reporter.json_report import generate_json_report
from aicomply.reporter.markdown_report import generate_markdown_report
from aicomply.rules.loader import RuleLoadError, load_rules_from_dir
from aicomply.scanner.engine import ScanEngine

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
    MARKDOWN = "markdown"
    JSON = "json"


def get_default_rules_dir() -> Path:
    """Obtiene la ruta interna por defecto del catálogo de reglas."""
    return Path(__file__).parent / "rules" / "eu_ai_act"


@app.command(name="scan")
def scan(
    path: Path = typer.Argument(
        ...,
        help="Ruta al archivo o directorio a auditar.",
        exists=True,
        resolve_path=True,
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.MARKDOWN,
        "--format",
        "-f",
        help="Formato de salida del reporte (markdown, json).",
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
        help="Ruta para guardar el reporte emitido.",
    ),
    evidence: bool = typer.Option(
        False,
        "--evidence",
        help="Incluir identificadores de hash SHA-256 por cada hallazgo.",
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

    if format == OutputFormat.JSON:
        output_content = generate_json_report(report)
    else:
        output_content = generate_markdown_report(report, include_evidence=evidence)

    if output:
        output.write_text(output_content, encoding="utf-8")
        console.print(f"[green]Reporte guardado exitosamente en:[/green] {output}")
    else:
        console.print(output_content)

    # Exit code: 1 si hay hallazgos (para CI/CD gating), 0 si está limpio
    if report.summary.total_findings > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()