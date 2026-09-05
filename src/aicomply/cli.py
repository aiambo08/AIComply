"""
AIComply - CLI Entrypoint (Typer)
"""

from enum import Enum
from pathlib import Path
import sys
from typing import Optional, Set

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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
        help="Formato de salida del reporte (terminal, markdown, json, sarif).",
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
    sign: bool = typer.Option(
        False,
        "--sign",
        help="Firmar asimétricamente el reporte con una clave privada Ed25519.",
    ),
    key: Optional[Path] = typer.Option(
        None,
        "--key",
        "-k",
        help="Ruta a la clave privada Ed25519 (.pem) para firmar.",
    ),
    signer_id: Optional[str] = typer.Option(
        None,
        "--signer-id",
        help="Identidad del firmante (ej. 'secops-ci@company.com').",
    ),
    rules_dir: Optional[Path] = typer.Option(
        None,
        "--rules-dir",
        help="Directorio personalizado de reglas YAML.",
    ),
) -> None:
    """Escanea el código fuente en busca de infracciones del EU AI Act y RGPD."""
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

    # Firma asimétrica Ed25519 si se solicitó
    signed_bundle = None
    if sign:
        if not key or not key.exists():
            console.print("[bold red]Error: Debe especificar una clave privada existente con --key para firmar.[/bold red]")
            raise typer.Exit(code=2)
        from aicomply.evidence.signer import sign_scan_report
        signed_bundle = sign_scan_report(report, key, signer_identity=signer_id)

    # Gestión de salida según formato
    if output:
        if signed_bundle and format == OutputFormat.JSON:
            content = signed_bundle.model_dump_json(indent=2)
        elif format == OutputFormat.JSON:
            content = generate_json_report(report)
        elif format == OutputFormat.SARIF:
            content = generate_sarif_report(report)
        else:
            content = generate_markdown_report(report, include_evidence=evidence)

        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Reporte guardado exitosamente en:[/green] {output}")
    else:
        if signed_bundle and format == OutputFormat.JSON:
            typer.echo(signed_bundle.model_dump_json(indent=2))
        elif format == OutputFormat.JSON:
            typer.echo(generate_json_report(report))
        elif format == OutputFormat.SARIF:
            typer.echo(generate_sarif_report(report))
        elif format == OutputFormat.MARKDOWN:
            typer.echo(generate_markdown_report(report, include_evidence=evidence))
        else:
            render_terminal_report(report, include_evidence=evidence, console=console)
            if signed_bundle:
                console.print(f"[bold green][✓] Reporte firmado con Ed25519 (Huella: {signed_bundle.public_key_fingerprint})[/bold green]")

    if report.summary.total_findings > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="keygen")
def keygen(
    out_dir: Path = typer.Option(
        Path("./pki"),
        "--out-dir",
        "-o",
        help="Directorio donde se generarán las claves.",
    ),
    name: str = typer.Option(
        "aicomply",
        "--name",
        "-n",
        help="Nombre base para los archivos de clave privada (.pem) y pública (.pub).",
    ),
) -> None:
    """Genera un nuevo par de claves asimétricas Ed25519 para firma de evidencias."""
    from aicomply.evidence.signer import generate_keypair
    from rich.panel import Panel
    from rich.table import Table

    try:
        priv_path, pub_path, fingerprint = generate_keypair(out_dir, name)

        table = Table(show_header=False, box=None)
        table.add_row("[bold cyan]Clave Privada (PKCS8 PEM):[/bold cyan]", f"[yellow]{priv_path}[/yellow]")
        table.add_row("[bold cyan]Clave Pública (X.509 PEM):[/bold cyan]", f"[green]{pub_path}[/green]")
        table.add_row("[bold cyan]Huella Digital (SHA-256):[/bold cyan]", f"[magenta]{fingerprint}[/magenta]")

        panel = Panel(
            table,
            title="[bold green]Par de Claves Asimétricas Ed25519 Generado[/bold green]",
            border_style="green",
        )
        console.print(panel)
    except Exception as exc:
        console.print(f"[bold red]Error al generar el par de claves:[/bold red] {exc}")
        raise typer.Exit(code=2)


@app.command(name="verify")
def verify(
    evidence_file: Path = typer.Argument(
        ...,
        help="Ruta al archivo JSON del reporte o paquete de evidencia firmado.",
        exists=True,
        resolve_path=True,
    ),
    public_key: Path = typer.Option(
        ...,
        "--public-key",
        "-k",
        help="Ruta a la clave pública Ed25519 (.pub).",
        exists=True,
        resolve_path=True,
    ),
) -> None:
    """Verifica matemáticamente la autenticidad e integridad de un reporte firmado (Ed25519)."""
    from aicomply.evidence.signer import verify_evidence_bundle
    from rich.panel import Panel
    from rich.table import Table

    is_valid, msg = verify_evidence_bundle(evidence_file, public_key)

    table = Table(show_header=False, box=None)
    table.add_row("[bold cyan]Archivo Verificado:[/bold cyan]", f"{evidence_file}")
    table.add_row("[bold cyan]Clave Pública:[/bold cyan]", f"{public_key}")
    table.add_row("[bold cyan]Resultado:[/bold cyan]", f"{msg}")

    if is_valid:
        panel = Panel(
            table,
            title="[bold green]VERIFICACIÓN EXITOSA — Evidencia Auténtica e Inalterada[/bold green]",
            border_style="green",
        )
        console.print(panel)
        raise typer.Exit(code=0)
    else:
        panel = Panel(
            table,
            title="[bold red]VERIFICACIÓN FALLIDA — Manipulación o Firma Inválida[/bold red]",
            border_style="red",
        )
        console.print(panel)
        raise typer.Exit(code=1)


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

@app.command(name="ui")
def ui(
    path: Path = typer.Argument(
        Path("."),
        help="Ruta al repositorio a inspeccionar en la consola visual.",
        exists=True,
        resolve_path=True,
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="Puerto donde se levantará la consola interactiva.",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Dirección IP de escucha para el servidor web local.",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="No abrir automáticamente el navegador web predeterminado.",
    ),
) -> None:
    """Inicia la consola visual e interactiva local de cumplimiento y trazabilidad (AIComply Cockpit)."""
    from aicomply.ui.server import start_ui_server
    from rich.panel import Panel

    url = f"http://{host}:{port}"
    panel = Panel(
        f"[bold cyan]AIComply Interactive Cockpit[/bold cyan]\n"
        f"Consola activa en: [bold green]{url}[/bold green]\n"
        f"Repositorio objetivo: [yellow]{path}[/yellow]\n"
        f"Presione [bold red]Ctrl+C[/bold red] para detener el servidor.",
        title="[bold green]AIComply UI Server // ONLINE[/bold green]",
        border_style="green",
    )
    console.print(panel)

    server = start_ui_server(
        target_path=path,
        host=host,
        port=port,
        open_browser=not no_browser,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Deteniendo el servidor de la consola AIComply...[/yellow]")
    finally:
        server.server_close()


if __name__ == "__main__":
    app()