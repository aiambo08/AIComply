# EXPEDIENTE DE DOCUMENTACIÓN TÉCNICA (ANEXO IV)
### Reglamento (UE) 2024/1689 (EU AI Act) — Artículo 11

> **Identificador de Evidencia:** `be99d739be92d62872e3140e680a4d785ec8eca42338cbd1ed48f22b59ff7634`  
> **Scan ID Origen:** `843a70e5b075710afc51e591cfdfa63e5a068165d77723f502723fd1d142b8aa`  
> **Fecha de Emisión:** 2026-08-30 15:33:43 UTC  
> **Clasificación del Sistema:** `PROHIBITED`

---

## SECCIÓN 1 — Identificación y Descripción General del Sistema (§1 Anexo IV)

- **Nombre del Sistema:** NovaCredit-Underwriting-LLM
- **Versión del Código Auditado:** `1.0.0`
- **Directorio Raíz:** `C:\Users\niaib\OneDrive - Universidad Politécnica de Madrid\106 - PROYECTOS\18. AIComply\aicomply\examples\fintech_credit_scoring`
- **Finalidad Prevista:** Automatización de flujos de trabajo e inferencia mediante modelos de lenguaje/IA.
- **Nivel de Riesgo Determinado:** **PROHIBITED**

## SECCIÓN 2 — Métodos de Desarrollo y Componentes de Software (§2 Anexo IV)

### 2.1. Inventario de Componentes y Stack Tecnológico de IA Detectado

#### Proveedores de Modelos de IA e Inferencia
- `OpenAI SDK (GPT-4o, GPT-3.5)`

#### Componentes con Restricciones Regulatorias (EU AI Act)
- **[ALERTA REGULATORIA]** `Computer Vision / Inferencia Emocional o Biométrica (Art. 5(1)(f))`

### 2.2. Métricas del Código Fuente
- **Archivos analizados:** 2
- **Líneas de código auditadas (SLOC):** 95
- **Reglas de conformidad evaluadas:** 20

## SECCIÓN 3 — Monitorización, Registro y Trazabilidad (§3 Anexo IV / Art. 12)

| Parámetro de Control | Estado Técnico | Evidencia / Observación |
|---|---|---|
| Registro de eventos (Art. 12) | **NO CONFORME** | 1 llamadas sin trazabilidad de logs detectadas |
| Transparencia y Disclaimers (Art. 13/50) | **ADVERTENCIA** | Notificación explícita de IA no identificada o deshabilitada |

## SECCIÓN 4 — Medidas de Supervisión Humana y Ciberseguridad (§4 Anexo IV / Arts. 14-15)

- **Human-in-the-loop (Art. 14):** Se requiere mecanismo de aprobación explícita o confirmación humana en decisiones críticas.
- **Robustez y Gestión de Errores (Art. 15):** Los endpoints de inferencia deben disponer de manejo de excepciones y políticas de contingencia (fallbacks).

## SECCIÓN 5 — Matriz de Riesgos y No-Conformidades Pendientes (§5 Anexo IV)

| ID Regla | Artículo | Severidad | Ubicación | Remediación Exigida |
|---|---|---|---|---|
| `EUAIA-ART12-001` | Art. 12 | **HIGH** | `risk_scoring_service.py:45` | Implementar un módulo de logging estructurado que registre inputs, metadatos y timestamps de cada invocación al modelo de IA. |
| `EUAIA-ART14-001` | Art. 14 | **HIGH** | `risk_scoring_service.py:61` | Introducir un mecanismo explícito de confirmación manual, compuerta de aprobación (human approval gate) o flag de override antes de disparar acciones irreversibles. |
| `EUAIA-ART05-001` | Art. 5(1)(f) | **CRITICAL** | `risk_scoring_service.py:13` | Eliminar el módulo de análisis de emociones o restringir su alcance a entornos no prohibidos expresamente por el Art. 5. |
| `EUAIA-ART05-002` | Art. 5(1)(c) | **CRITICAL** | `risk_scoring_service.py:34` | Eliminar algoritmos de cálculo de fiabilidad o puntuación social generalizada de usuarios. |
| `GDPR-ART22-001` | RGPD Art. 22 | **HIGH** | `risk_scoring_service.py:60` | Configurar el pipeline para requerir confirmación por un operador humano antes de emitir la resolución vinculante al usuario final. |
| `GDPR-ART32-002` | RGPD Art. 32(1)(a) | **HIGH** | `risk_scoring_service.py:52` | Eliminar flags como verify=False o NODE_TLS_REJECT_UNAUTHORIZED='0' en clientes HTTP y SDKs de IA. |
| `EUAIA-ART15-002` | Art. 15 | **CRITICAL** | `risk_scoring_service.py:16` | Externalizar credenciales a variables de entorno (os.environ.get) o almacenes de secretos seguros (AWS Secrets Manager, Vault). |
| `GDPR-ART32-001` | RGPD Art. 32 / EU AI Act Art. 15 | **CRITICAL** | `risk_scoring_service.py:16` | Extraer las credenciales a variables de entorno (.env) o utilizar un gestor de secretos (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). |
| `GDPR-ART32-003` | RGPD Art. 32(1)(a) | **HIGH** | `risk_scoring_service.py:17` | Configurar todos los endpoints base y URLs de inferencia bajo protocolo seguro HTTPS. |
| `GDPR-ART05-002` | RGPD Art. 5(1)(c) / Art. 9 | **HIGH** | `risk_scoring_service.py:21` | Anonimizar o pseudonimizar identificadores nacionales mediante sintetización de datos o módulos de ofuscación (Presidio/Faker). |
| `GDPR-ART05-003` | RGPD Art. 5(1)(f) / Art. 32 | **CRITICAL** | `risk_scoring_service.py:21` | Implementar filtros de enmascaramiento y cumplimiento PCI-DSS antes de enviar secuencias de texto al pipeline de inferencia. |
| `GDPR-ART05-002` | RGPD Art. 5(1)(c) / Art. 9 | **HIGH** | `risk_scoring_service.py:28` | Anonimizar o pseudonimizar identificadores nacionales mediante sintetización de datos o módulos de ofuscación (Presidio/Faker). |
| `GDPR-ART05-003` | RGPD Art. 5(1)(f) / Art. 32 | **CRITICAL** | `risk_scoring_service.py:28` | Implementar filtros de enmascaramiento y cumplimiento PCI-DSS antes de enviar secuencias de texto al pipeline de inferencia. |
| `GDPR-ART09-001` | RGPD Art. 9 | **CRITICAL** | `risk_scoring_service.py:30` | Implementar filtros de desidentificación (presidio, regex de PII) o eliminar campos biométricos no esenciales antes de procesar los lotes de datos. |
| `EUAIA-ART13-001` | Art. 50(1) / Art. 13 | **HIGH** | `risk_scoring_service.py:37` | Incluir disclaimers de transparencia en los endpoints o salidas que entregan contenido directamente a usuarios finales. |
| `EUAIA-ART15-003` | Art. 15 | **HIGH** | `risk_scoring_service.py:41` | Aplicar esquemas de tipado, filtrado de caracteres de inyección y separación formal de roles mediante mensajes estructurados. |
| `GDPR-ART32-002` | RGPD Art. 32(1)(a) | **HIGH** | `risk_scoring_service.py:55` | Eliminar flags como verify=False o NODE_TLS_REJECT_UNAUTHORIZED='0' en clientes HTTP y SDKs de IA. |
| `EUAIA-ART50-002` | Art. 50 | **MEDIUM** | `risk_scoring_service.py:65` | Interponer filtros de toxicidad, validadores de esquema estructurado o moderación semántica previa a la entrega al usuario final. |

---

## DECLARACIÓN DE TRAZABILIDAD Y FIRMA DE AUDITORÍA

El presente dossier ha sido emitido de forma determinista por el motor estático de **AIComply v0.1.0**.
Cualquier modificación en el código fuente invalidará el hash SHA-256 (`be99d739be92d62872e3140e680a4d785ec8eca42338cbd1ed48f22b59ff7634`) de este documento.
