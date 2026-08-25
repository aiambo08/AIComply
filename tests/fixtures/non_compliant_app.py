"""Fixture: Código que incumple múltiples artículos del EU AI Act."""
import fer
from openai import OpenAI

client = OpenAI()

def analyze_employee_behavior(image_input):
    # Infracción Art. 5: Inferencia de emociones en entorno laboral
    detector = fer.FER()
    emotion_data = detector.detect_emotions(image_input)
    return emotion_data

def generate_customer_response(prompt_text):
    # Infracción Art. 12: Llamada a LLM sin logger en el archivo
    # Infracción Art. 13: ai_disclaimer deshabilitado explícitamente
    ai_disclaimer = False
    
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt_text}]
    )
    return response.choices[0].message.content