"""
AIComply - Interactive Risk Classifier (Decision Tree)
Evalúa casos de uso y arquitecturas de IA mediante preguntas estructuradas
para clasificar el sistema según el EU AI Act y el RGPD.
"""

from dataclasses import dataclass
from typing import List, Optional
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from aicomply.schemas import RiskTier

@dataclass
class AssessmentResult:
    """
    Resultado estructurado de la evaluación guiada.
    """
    system_name: str
    risk_tier: RiskTier
    applicable_articles: List[str]
    obligations: List[str]
    compliance_deadline: str
    rationale: str

def run_interactive_assessment(console: Optional[Console] = None) -> AssessmentResult:
    """
    Ejecuta el cuestionario interactivo en la terminal.
    """
    console= console or Console()

    console.print(
        Panel(
            "[bold cyan]Asistente de Clasificación Regulatoria - EU AI Act & RGPD[/bold cyan]\n"
            "[dim]Responde a las siguientes preguntas técnicas y operativas sobre tu sistema.[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    system_name = Prompt.ask("\n[bold]1. Nombre del sistema o proyecto[/bold]", default="AI-System")

    # PASO 1: Ámbito del EU AI Act
    is_ai = Confirm.ask(
        "\n[bold]2. ¿El sistema infiere salidas (predicciones, contenido, decisiones) a partir de entradas usando modelos autónomos (ej. LLM, ML)?", default=True,
    )
    if not is_ai:
        return AssessmentResult(
            system_name=system_name,
            risk_tier=RiskTier.MINIMAL_RISK,
            applicable_articles=["Fuera de ámbito (Art. 3(1))"],
            obligations=["No sujeto a las obligaciones del EU AI Act."],
            compliance_deadline="N/A",
            rationale="El software no cumple la definición de 'sistema de IA' según el Art. 3(1).",
        )

    # PASO 2: Prácticas Prohibidas (Art. 5) 
    console.print("\n[bold yellow]── Evaluación de Prácticas Prohibidas (Art. 5) ──[/bold yellow]")
    prohibited_checks = [
        ("¿El sistema realiza puntuación social (social scoring) evaluando personas por su conducta?", "Art. 5(1)(c)"),
        ("¿Utiliza técnicas subliminales o manipulativas para alterar el comportamiento causando daño?", "Art. 5(1)(a)"),
        ("¿Infere emociones en lugares de trabajo o instituciones educativas (salvo fines médicos)?", "Art. 5(1)(f)"),
        ("¿Realiza identificación biométrica remota en tiempo real en espacios públicos para fines policiales?", "Art. 5(1)(h)"),
    ]

    for question, ref in prohibited_checks:
        if Confirm.ask(f"• {question}", default=False):
            return AssessmentResult(
                system_name=system_name,
                risk_tier=RiskTier.PROHIBITED,
                applicable_articles=["Art. 5", ref],
                obligations=[
                    "PROHIBICIÓN TOTAL DE DESPLIEGUE Y COMERCIALIZACIÓN.",
                    "Retirada inmediata del mercado o cese de operaciones.",
                    "Sanciones de hasta 35M€ o el 7% de la facturación global anual.",
                ],
                compliance_deadline="Aplicable desde febrero de 2025",
                rationale=f"El sistema incurre en una práctica expresamente prohibida bajo el {ref}.",
            )

    # PASO 3: Sistemas de Alto Riesgo (Anexo I y Anexo III) 
    console.print("\n[bold red]── Evaluación de Sistemas de Alto Riesgo (Art. 6 / Anexo III) ──[/bold red]")
    high_risk_domains = [
        "Biometría: categorización o identificación biométrica remota post-hoc.",
        "Infraestructuras críticas: gestión de tráfico, redes de agua, gas, electricidad.",
        "Educación y formación: admisión de alumnos o evaluación de estudiantes.",
        "Empleo y RRHH: selección de personal, asignación de tareas o monitorización de rendimiento.",
        "Servicios esenciales: evaluación de solvencia/scoring crediticio, acceso a ayudas públicas.",
        "Fuerzas de seguridad, gestión de migración, asilo y control fronterizo.",
        "Administración de justicia y procesos democráticos.",
    ]
    console.print("[dim]Dominios del Anexo III:[/dim]")
    for domain in high_risk_domains:
        console.print(f"  [dim]• {domain}[/dim]")

    in_high_risk = Confirm.ask(
        "\n¿El sistema se utiliza en alguno de estos dominios con impacto directo en derechos o seguridad?",
        default=False,
    )

    if in_high_risk:
        is_narrow_exception = Confirm.ask(
            "¿El sistema realiza únicamente una tarea procedimental estrecha sin influir materialmente en la decisión final (Art. 6(3))?",
            default=False,
        )
        if not is_narrow_exception:
            return AssessmentResult(
                system_name=system_name,
                risk_tier=RiskTier.HIGH_RISK,
                applicable_articles=["Art. 6", "Capítulo III", "Arts. 9-15", "Anexo III"],
                obligations=[
                    "Implantar un sistema continuo de gestión de riesgos (Art. 9).",
                    "Gobernanza y mitigación de sesgos en datos de entrenamiento (Art. 10).",
                    "Elaborar y mantener la documentación técnica (Art. 11 / Anexo IV).",
                    "Habilitar registro automático de eventos (logging) continuo (Art. 12).",
                    "Diseñar interfaces con supervisión humana efectiva y override (Art. 14).",
                    "Asegurar robustez, precisión técnica y ciberseguridad (Art. 15).",
                    "Registro obligatorio en la base de datos de la UE.",
                ],
                compliance_deadline="Agosto 2026 (Transparencia) / Diciembre 2027 (Alto Riesgo)",
                rationale="El sistema opera dentro de los casos de uso críticos enumerados en el Anexo III.",
            )

    # PASO 4: Modelos de Propósito General (GPAI / LLMs) 
    console.print("\n[bold cyan]── Modelos de IA de Propósito General (Capítulo V) ──[/bold cyan]")
    is_gpai = Confirm.ask(
        "¿Desarrollas, entrenas o afinas directamente un modelo base o GPAI (ej. LLM propio)?",
        default=False,
    )
    if is_gpai:
        return AssessmentResult(
            system_name=system_name,
            risk_tier=RiskTier.HIGH_RISK,
            applicable_articles=["Capítulo V", "Arts. 51-55"],
            obligations=[
                "Documentación técnica del modelo y resumen público del entrenamiento.",
                "Cumplimiento de la directiva sobre derechos de autor.",
                "Si supera 10^25 FLOPs: Evaluación de riesgo sistémico y pruebas adversarias.",
            ],
            compliance_deadline="Agosto 2025",
            rationale="Clasificado como Proveedor de Modelos de IA de Propósito General (GPAI).",
        )

    # PASO 5: Riesgo Limitado / Transparencia (Art. 50) 
    console.print("\n[bold yellow]── Obligaciones de Transparencia (Art. 50) ──[/bold yellow]")
    interacts_with_humans = Confirm.ask(
        "¿El sistema interactúa directamente con usuarios (chatbots) o genera contenido sintético/deepfakes?",
        default=True,
    )
    if interacts_with_humans:
        return AssessmentResult(
            system_name=system_name,
            risk_tier=RiskTier.LIMITED_RISK,
            applicable_articles=["Art. 50(1)", "Art. 50(2)", "RGPD Art. 13/14"],
            obligations=[
                "Notificar al usuario de forma clara e inmediata que interactúa con una IA.",
                "Marcar el contenido sintético generado (audio, imagen, vídeo, texto) en formato legible por máquina.",
                "Permitir el ejercicio de derechos RGPD sobre la información tratada.",
            ],
            compliance_deadline="Exigible desde agosto de 2026",
            rationale="Sistemas que interactúan con personas o generan contenido sintético sujeto al Art. 50.",
        )

    # PASO 6: Riesgo Mínimo 
    return AssessmentResult(
        system_name=system_name,
        risk_tier=RiskTier.MINIMAL_RISK,
        applicable_articles=["Art. 95 (Códigos de conducta voluntarios)"],
        obligations=[
            "Sin obligaciones regulatorias vinculantes.",
            "Recomendada adhesión voluntaria a códigos de buenas prácticas éticas.",
        ],
        compliance_deadline="Sin límite vinculante",
        rationale="Sistemas sin riesgo significativo para derechos fundamentales o seguridad física.",
    )


def render_assessment_report(result: AssessmentResult, console: Optional[Console] = None) -> None:
    """Presenta el dictamen de clasificación en la consola."""
    console = console or Console()

    tier_styles = {
        RiskTier.PROHIBITED: ("PROHIBIDO (Art. 5)", "bold white on red"),
        RiskTier.HIGH_RISK: ("ALTO RIESGO", "bold red"),
        RiskTier.LIMITED_RISK: ("RIESGO LIMITADO", "bold yellow"),
        RiskTier.MINIMAL_RISK: ("RIESGO MÍNIMO", "bold green"),
    }
    badge_label, badge_style = tier_styles[result.risk_tier]

    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("Parámetro", style="bold cyan", width=24)
    table.add_column("Detalle")

    table.add_row("Sistema Auditado", f"[bold]{result.system_name}[/bold]")
    table.add_row("Dictamen de Riesgo", f"[{badge_style}] {badge_label} [/{badge_style}]")
    table.add_row("Artículos Clave", ", ".join(result.applicable_articles))
    table.add_row("Entrada en Vigor", f"[bold yellow]{result.compliance_deadline}[/bold yellow]")
    table.add_row("Fundamento Legal", result.rationale)

    console.print()
    console.print(
        Panel(
            table,
            title="[bold blue]DICTAMEN DE CLASIFICACIÓN REGULATORIA (EU AI ACT)[/bold blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
    )

    obs_table = Table(box=box.SIMPLE_HEAVY, expand=True)
    obs_table.add_column("#", width=4, justify="center")
    obs_table.add_column("Obligaciones Técnicas y Operativas Vinculantes")

    for idx, ob in enumerate(result.obligations, start=1):
        obs_table.add_row(str(idx), ob)

    console.print(obs_table)
