"""Contextual triage; technical signals cannot establish legal compliance."""

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from aicomply.schemas import RiskTier

REVIEWED_ON = "2026-09-20"
SOURCES = (
    "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
    "https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-6",
    "https://digital-strategy.ec.europa.eu/en/news/ai-omnibus-enters-force",
    "https://digital-strategy.ec.europa.eu/en/policies/enforcement-ai-act",
    "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
)
TIMELINE_NOTE = (
    "Fechas orientativas según información de la Comisión revisada el "
    f"{REVIEWED_ON}; confirmar texto vigente, rol y régimen transitorio."
)


class SystemContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    system_name: str = Field(default="AI-System", min_length=1, max_length=200)
    intended_purpose: str = Field(default="", max_length=4000)
    role: Literal["provider", "deployer", "importer", "distributor", "unknown"] = "unknown"
    is_ai: bool | None = None
    eu_scope: bool | None = None
    prohibited_practice: bool | None = None
    annex_i_product: bool | None = None
    third_party_conformity: bool | None = None
    annex_iii_use: bool | None = None
    profiling: bool | None = None
    narrow_exception: bool | None = None
    transparency: bool | None = None
    gpai_provider: bool | None = None
    personal_data: bool | None = None
    solely_automated_significant_decision: bool | None = None


@dataclass
class AssessmentResult:
    system_name: str
    risk_tier: RiskTier | None
    applicable_articles: list[str]
    obligations: list[str]
    compliance_deadline: str
    rationale: str
    status: str = "requires_review"
    missing_context: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=lambda: list(SOURCES))
    reviewed_on: str = REVIEWED_ON


def assess_context(context: SystemContext) -> AssessmentResult:
    """Return overlapping review duties without assuming favourable unknowns."""
    articles: list[str] = []
    obligations: list[str] = []
    deadlines: list[str] = []
    missing: list[str] = []
    if not context.intended_purpose.strip():
        missing.append("intended_purpose")
    if context.role == "unknown":
        missing.append("role")
    for name, value in (
        ("is_ai", context.is_ai),
        ("eu_scope", context.eu_scope),
        ("personal_data", context.personal_data),
    ):
        if value is None:
            missing.append(name)

    tier: RiskTier | None = None
    rationale = "Clasificación jurídica pendiente de contexto y revisión."
    in_scope = context.is_ai is True and context.eu_scope is True
    if context.is_ai is False or context.eu_scope is False:
        articles.append("Arts. 2–3: ámbito declarado pendiente de validar")
        rationale = "Posible exclusión del AI Act según respuestas; no excluye RGPD u otras normas."
    else:
        for name, value in (
            ("prohibited_practice", context.prohibited_practice),
            ("annex_i_product", context.annex_i_product),
            ("annex_iii_use", context.annex_iii_use),
            ("transparency", context.transparency),
            ("gpai_provider", context.gpai_provider),
        ):
            if value is None:
                missing.append(name)
        if context.prohibited_practice:
            tier = RiskTier.PROHIBITED
            articles.append("Art. 5")
            obligations.append("Revisión prioritaria de elementos, excepciones y prohibición potencial antes de desplegar.")
            deadlines.append("Art. 5: prácticas originales desde 2025-02-02; nueva prohibición comunicada para 2026-12-02")
        high_risk = False
        if context.annex_i_product:
            if context.third_party_conformity is None:
                missing.append("third_party_conformity")
            elif context.third_party_conformity:
                high_risk = True
                articles.append("Art. 6(1), Anexo I")
                deadlines.append("Anexo I: 2028-08-02 (información de la Comisión)")
        if context.annex_iii_use:
            if context.profiling is None:
                missing.append("profiling")
            if context.narrow_exception is None:
                missing.append("narrow_exception")
            if context.profiling is not False or context.narrow_exception is not True:
                high_risk = True
                articles.append("Art. 6(2), Anexo III")
                deadlines.append("Anexo III: 2027-12-02 (información de la Comisión)")
            else:
                articles.append("Art. 6(3)–(4)")
                obligations.append("Documentar excepción y ausencia de riesgo significativo; el perfilado impide esta excepción.")
        if high_risk:
            if tier != RiskTier.PROHIBITED:
                tier = RiskTier.HIGH_RISK
            if context.role == "deployer":
                articles.extend(["Art. 26", "Art. 27 (si procede)"])
                obligations.append("Validar instrucciones, supervisión humana, registros y necesidad de evaluación de derechos fundamentales.")
            elif context.role == "provider":
                articles.extend(["Arts. 9–15", "Arts. 16–21", "Arts. 43–49"])
                obligations.append("Preparar gestión de riesgos/calidad, datos, Anexo IV, logs, supervisión, evaluaciones y procedimiento de conformidad aplicable.")
            else:
                obligations.append("Determinar obligaciones de la cadena de valor según el rol (Arts. 16–27).")
        if context.transparency:
            if tier is None:
                tier = RiskTier.LIMITED_RISK
            articles.append("Art. 50")
            obligations.append("Revisar información sobre interacción con IA, marcado de contenido sintético y divulgación según tipo de contenido y rol.")
            deadlines.append("Art. 50: 2026-08-02; comprobar transición específica del marcado")
        if in_scope and tier is None and not missing:
            tier = RiskTier.MINIMAL_RISK
            rationale = "No se identifica categoría elevada en las respuestas; revisar exclusiones, otras normas y cambios de finalidad."
    if context.gpai_provider:
        articles.append("Arts. 51–55 (GPAI)")
        obligations.append("Evaluar separadamente ámbito y deberes del proveedor de modelo GPAI, copyright, información a integradores y riesgo sistémico; GPAI no implica por sí mismo alto riesgo del sistema.")
        deadlines.append("GPAI: 2025-08-02; modelos anteriores pueden tener régimen transitorio")
    if context.personal_data:
        articles.extend(["RGPD Arts. 5, 6, 9, 13–14, 25, 32, 35 (según tratamiento)"])
        obligations.append("Documentar base jurídica, minimización, retención, derechos, encargados, transferencias y necesidad de EIPD.")
        if context.solely_automated_significant_decision is None:
            missing.append("solely_automated_significant_decision")
        elif context.solely_automated_significant_decision:
            articles.append("RGPD Art. 22")
            obligations.append("Revisar decisión exclusivamente automatizada con efectos jurídicos o similares significativos, excepciones y garantías.")
    if not in_scope and tier is not None:
        rationale = "Indicios declarados pendientes de confirmar ámbito territorial y definición de IA."
    obligations.append("La evaluación es provisional; no constituye certificación ni garantiza ausencia de multas.")
    return AssessmentResult(
        system_name=context.system_name,
        risk_tier=tier,
        applicable_articles=articles,
        obligations=obligations,
        compliance_deadline="; ".join(deadlines) or "Pendiente de determinar",
        rationale=rationale + " " + TIMELINE_NOTE,
        missing_context=missing,
    )


def _ask(question: str, console: Console) -> bool | None:
    answer = Prompt.ask(question, choices=["s", "n", "?"], default="?", console=console)
    return {"s": True, "n": False, "?": None}[answer]


def run_interactive_assessment(console: Console | None = None) -> AssessmentResult:
    console = console or Console()
    console.print("Evaluación contextual provisional — usa ? cuando falte evidencia.")
    context = SystemContext(
        system_name=Prompt.ask("Nombre del sistema", default="AI-System", console=console),
        intended_purpose=Prompt.ask("Finalidad prevista y personas afectadas", default="", console=console),
    )
    role = Prompt.ask(
        "Rol", choices=["provider", "deployer", "importer", "distributor", "unknown"],
        default="unknown", console=console,
    )
    if role == "provider":
        context.role = "provider"
    elif role == "deployer":
        context.role = "deployer"
    elif role == "importer":
        context.role = "importer"
    elif role == "distributor":
        context.role = "distributor"
    context.is_ai = _ask("¿Cumple la definición de sistema de IA (Art. 3)?", console)
    context.eu_scope = _ask("¿Está dentro del ámbito territorial del Art. 2?", console)
    context.prohibited_practice = _ask("¿Hay indicios de alguna práctica del Art. 5, revisando condiciones y excepciones?", console)
    context.annex_i_product = _ask("¿Es producto o componente de seguridad de un producto del Anexo I?", console)
    if context.annex_i_product:
        context.third_party_conformity = _ask("¿La normativa del producto exige evaluación de conformidad por terceros?", console)
    context.annex_iii_use = _ask("¿Tiene una finalidad incluida en el Anexo III?", console)
    if context.annex_iii_use:
        context.profiling = _ask("¿Realiza perfilado de personas físicas?", console)
        context.narrow_exception = _ask("¿Se ha documentado una excepción del Art. 6(3), sin riesgo significativo ni influencia material?", console)
    context.transparency = _ask("¿Interactúa con personas, genera contenido sintético o usa biometría/emociones sujeto al Art. 50?", console)
    context.gpai_provider = _ask("¿La organización es proveedor de un modelo de propósito general (GPAI)?", console)
    context.personal_data = _ask("¿Se tratan datos personales?", console)
    if context.personal_data:
        context.solely_automated_significant_decision = _ask("¿Adopta decisiones exclusivamente automatizadas con efectos jurídicos o similares significativos?", console)
    return assess_context(context)


def render_assessment_report(result: AssessmentResult, console: Console | None = None) -> None:
    console = console or Console()
    labels = {
        RiskTier.PROHIBITED: "POSIBLE PRÁCTICA PROHIBIDA",
        RiskTier.HIGH_RISK: "POSIBLE ALTO RIESGO",
        RiskTier.LIMITED_RISK: "TRANSPARENCIA",
        RiskTier.MINIMAL_RISK: "SIN CATEGORÍA ELEVADA DECLARADA",
        None: "INDETERMINADO",
    }
    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("Parámetro")
    table.add_column("Detalle")
    for label, value in (
        ("Sistema", result.system_name),
        ("Resultado provisional", labels[result.risk_tier]),
        ("Artículos a revisar", ", ".join(result.applicable_articles)),
        ("Calendario", result.compliance_deadline),
        ("Fundamento", result.rationale),
        ("Contexto pendiente", ", ".join(result.missing_context) or "Revisión humana de respuestas"),
        ("Fuentes", "\n".join(result.sources)),
    ):
        table.add_row(label, Text(value))
    console.print(Panel(table, title="EVALUACIÓN CONTEXTUAL — REQUIERE REVISIÓN"))
    for obligation in result.obligations:
        console.print(Text(f"• {obligation}"))
