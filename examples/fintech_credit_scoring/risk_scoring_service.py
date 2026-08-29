"""
Novabank AI Labs — Automated Credit Risk Scoring & Loan Underwriting Service.
=============================================================================
Este servicio simula un microservicio de producción real en una entidad financiera (Fintech)
que integra modelos LLM y algoritmos de Machine Learning para admisión de préstamos.

El código contiene diversas prácticas de riesgo técnico y regulatorio para evaluar
exhaustivamente la capacidad de detección del motor de AIComply.
"""

import requests
from openai import OpenAI
import fer  # Detección EUAIA-ART05-001: Inferencia emocional en evaluación de perfiles

# 1. Seguridad y Criptografía (GDPR Art. 32 & EU AI Act Art. 15)
OPENAI_API_KEY = "sk-proj-9876543210abcdefghijklmnop12345678"
api_base = "http://inference.novabank-core.internal/v1"

client = OpenAI(api_key=OPENAI_API_KEY, base_url=api_base)

def evaluate_loan_applicant(user_raw_query: str, dni_number: str = "12345678Z", card_pan: str = "4111111111111111"):
    """
    Evalúa la solvencia del solicitante procesando PII sensible, ejecutando scoring social
    e interactuando con un modelo generativo sin logging ni supervisión humana.
    """
    
    # 2. PII y Categorías Especiales (GDPR Art. 5 y Art. 9)
    # Exposición directa de DNI español (12345678Z) y número de tarjeta Visa (4111111111111111)
    applicant_record = f"Solicitante DNI: {dni_number} | Tarjeta Garantía: {card_pan}"
    process_health_records = True  # Violación GDPR Art. 9: Tratamiento de datos de salud sin base reforzada

    # 3. Prácticas Prohibidas por el EU AI Act (Art. 5(1)(c) - Social Scoring)
    # Llamada a función de puntuación por comportamiento social
    social_trust = compute_social_score(applicant_id="USR-9921", trust_index=0.88)

    # 4. Transparencia y Disclaimers (EU AI Act Art. 13 y Art. 50(1))
    ai_disclaimer = False  # Desactivación explícita de la notificación al usuario de que interactúa con IA

    # 5. Robustez y Prompt Injection (EU AI Act Art. 15)
    # Construcción de prompt insegura con f-string interpolando entrada de usuario sin sanitizar
    prompt = f"Analizar riesgo crediticio para solicitud: {user_raw_query} y registro: {applicant_record}"

    # 6. Ausencia de Registro de Eventos (EU AI Act Art. 12)
    # Invocación directa a LLM sin logger estructurado en el scope
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )

    # 7. Ciberseguridad en Transmisión (GDPR Art. 32(1)(a) - Bypass TLS)
    # Envío de métricas internas desactivando la verificación SSL
    requests.post(
        "https://telemetry.novabank-core.internal/audit",
        json={"applicant": dni_number, "status": "processed"},
        verify=False
    )

    # 8. Supervisión Humana y Decisiones Automatizadas (EU AI Act Art. 14 y GDPR Art. 22)
    # Aprobación vinculante automática y ejecución sin intervención humana
    credit_scoring_auto_approve(applicant_id="USR-9921", amount=25000)
    auto_execute_decision(decision="APPROVED", risk_level="LOW")

    # 9. Salida sin Moderación Semántica (EU AI Act Art. 50)
    # Retorno directo del contenido generado por el modelo al usuario final
    return response.choices[0].message.content


def compute_social_score(applicant_id: str, trust_index: float) -> float:
    """Función de scoring social auxiliar."""
    return trust_index * 100.0


def credit_scoring_auto_approve(applicant_id: str, amount: float) -> bool:
    """Función de aprobación automatizada sin operador humano."""
    return True


def auto_execute_decision(decision: str, risk_level: str) -> None:
    """Función de ejecución autónoma de acciones."""
    pass
