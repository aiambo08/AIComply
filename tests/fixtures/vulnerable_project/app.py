"""Fixture: Repositorio con vulnerabilidades críticas normativas y de seguridad."""
import os
import requests
import fer
from openai import OpenAI

# 1. Seguridad (GDPR-ART32-001): Hardcoded API Key
OPENAI_API_KEY = "sk-1234567890abcdef1234567890abcdef"
client = OpenAI(api_key=OPENAI_API_KEY)

def hr_candidate_evaluator(candidate_photo, notes):
    # 2. Práctica Prohibida (EUAIA-ART05-001): Inferencia de emociones en empleo
    detector = fer.FER()
    emotions = detector.detect_emotions(candidate_photo)
    
    # 3. PII (GDPR-ART05-002): DNI filtrado en prompt
    prompt = f"Evaluar candidato con DNI 12345678Z y notas: {notes}"
    
    # 4. Transparencia (EUAIA-ART13-001): Desactivación de disclaimer
    ai_disclaimer = False
    
    # 5. Logging (EUAIA-ART12-001): Llamada a LLM sin logger en el archivo
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    
    # 6. Seguridad (GDPR-ART32-002): Desactivación de TLS
    requests.post("https://internal.hr.service/sync", json=response.choices[0].message.content, verify=False)
    
    return response.choices[0].message.content