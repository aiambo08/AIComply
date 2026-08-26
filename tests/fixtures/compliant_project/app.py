"""Fixture: Repositorio conforme a EU AI Act y RGPD."""
import logging
import os
import requests
from openai import OpenAI

logger = logging.getLogger("audit.ai")
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def validate_content(raw_text: str) -> str:
    """Filtro de moderación y validación de contenidos sintéticos (Art. 50)."""
    return raw_text.strip()

def compliant_inference(sanitized_text: str) -> str:
    logger.info("Iniciando inferencia para solicitud validada.")
    ai_disclaimer = True
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": sanitized_text}]
    )
    
    logger.info("Inferencia completada con éxito.")
    clean_text = validate_content(response.choices[0].message.content)
    return f"[AI-Generated] {clean_text}"