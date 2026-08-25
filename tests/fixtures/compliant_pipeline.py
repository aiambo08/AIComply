"""Fixture: Código conforme con buenas prácticas de observabilidad."""
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)
client = OpenAI()

def process_query_compliant(user_prompt: str) -> str:
    logger.info("Iniciando inferencia para usuario con tracking auditado.")
    ai_disclaimer = True
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": user_prompt}]
    )
    
    logger.info("Respuesta generada satisfactoriamente.")
    return f"[AI-Generated Response]: {response.choices[0].message.content}"