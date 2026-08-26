# AIComply — Motor de Auditoría Estática de Cumplimiento IA (EU AI Act & RGPD)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg" alt="Python Versions" />
  <img src="https://img.shields.io/badge/Compliance-EU%20AI%20Act%20(Reg.%202024%2F1689)-darkgreen.svg" alt="EU AI Act" />
  <img src="https://img.shields.io/badge/Privacy-GDPR%20(Reg.%202016%2F679)-blueviolet.svg" alt="GDPR" />
  <img src="https://img.shields.io/badge/Tests-46%20Passed%20(100%25)-success.svg" alt="Tests" />
  <img src="https://img.shields.io/badge/Format-SARIF%20v2.1.0%20Compatible-orange.svg" alt="SARIF v2.1.0" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" />
</p>

**AIComply** es un analizador estático de código (*Shift-Left Compliance Linter*) determinista, diseñado para auditar repositorios de software, pipelines de datos y aplicaciones basadas en Modelos de Lenguaje (LLMs) e Inteligencia Artificial antes de su despliegue en producción.

Permite a desarrolladores, CTOs y equipos de gobernanza prevenir sanciones regulatorias bajo el **Reglamento de Inteligencia Artificial de la UE (Reglamento UE 2024/1689)** y el **Reglamento General de Protección de Datos (RGPD - Reg. UE 2016/679)**, generando evidencias criptográficas SHA-256 y expedientes técnicos de conformidad (**Anexo IV**).

---

## 🚀 Características Principales

- 🔍 **Análisis Sintáctico AST Puro:** Inspecciona árboles de sintaxis abstracta en memoria sin ejecutar código arbitrario (cero riesgo de ejecución en pipelines de CI/CD).
- 🛡️ **Catálogo de 20 Reglas Oficiales:** Detección de prácticas prohibidas (Art. 5), ausencia de logging (Art. 12), disclaimers de transparencia (Art. 50/13), prompt injection y claves hardcoded (Art. 15), y filtraciones de PII como DNI/NIE o tarjetas de crédito (RGPD Arts. 5 y 32).
- 📊 **Reportes Multi-Formato:** Salida interactiva en terminal (Rich Dashboard), exportación canónica en JSON, reportes de auditoría en Markdown y compatibilidad total con **SARIF v2.1.0** para GitHub Code Scanning / Advanced Security.
- 📑 **Generador de Documentación Técnica (Anexo IV):** Comando `docgen` para autogenerar el borrador formal del expediente técnico exigido por el Artículo 11 del AI Act, incluyendo el inventario de SDKs de IA detectados mediante AST.
- 🌳 **Árbol de Decisión Interactivo (`assess`):** Cuestionario guiado en consola para clasificar sistemas según su nivel de riesgo y determinar plazos y obligaciones legales aplicables.
- 🔒 **Trazabilidad Criptográfica SHA-256:** Identificadores inmutables por hallazgo y consolidado por escaneo con normalización de saltos de línea (CRLF a LF) para auditorías reproducibles.
- ⚙️ **Configuración Declarativa por Repositorio:** Soporte de archivos `.aicomply.yaml` para excluir rutas glob, omitir reglas justificadas y establecer umbrales de fallo en CI/CD.
- 🏷️ **Supresión Granular Inline:** Posibilidad de ignorar alertas justificadas directamente en el código fuente con `# aicomply:ignore <RULE_ID>`.

---

## 📦 Instalación

### Requisitos Previos
- Python 3.11 o superior.

### Instalación en Modo Desarrollo / Local
```bash
# Clonar el repositorio
git clone https://github.com/aiambo08/AIComply.git
cd AIComply/aicomply

# Instalación editable
pip install -e .

# Instalación con dependencias de desarrollo y testing
pip install -e ".[dev]"
```

---

## 🛠️ Guía Rápida de Uso

### 1. Escanear un Repositorio o Archivo (`scan`)
Audita el código fuente y devuelve código de salida `0` si es conforme, `1` si contiene no-conformidades, o `2` en caso de error técnico:

```bash
# Escaneo de terminal con interfaz visual enriquecida (Rich)
aicomply scan ./src

# Escanear filtrando únicamente por artículos específicos (ej. Art. 5 y Art. 12)
aicomply scan . --articles 5,12

# Exportar reporte en formato SARIF v2.1.0 para GitHub Security
aicomply scan . --format sarif --output aicomply-results.sarif

# Exportar reporte en formato JSON con inclusión de hashes de evidencia
aicomply scan . --format json --evidence --output report.json
```

### 2. Generar el Expediente Técnico Formal — Anexo IV (`docgen`)
Construye el dossier regulatorio exigido por el Artículo 11 del EU AI Act a partir del código auditado:

```bash
aicomply docgen . --name "Enterprise-LLM-Copilot" --version "1.2.0" --output docs/ANNEX_IV_TECHNICAL_DOCS.md
```

### 3. Asistente Interactivo de Clasificación de Riesgo (`assess`)
Inicia el cuestionario interactivo para determinar si un caso de uso cae bajo Prácticas Prohibidas, Alto Riesgo (Anexo III), Transparencia (Art. 50) o Riesgo Mínimo:

```bash
aicomply assess
```

---

## 📋 Catálogo de Reglas Oficiales Activas

AIComply incluye **20 reglas predefinidas** validadas contra los textos legales europeos:

| ID de Regla | Regulación | Severidad | Descripción del Patrón Evaluado |
|---|---|---|---|
| **`EUAIA-ART05-001`** | EU AI Act Art. 5(1)(f) | `CRITICAL` | Inferencia de emociones en el entorno laboral o educativo. |
| **`EUAIA-ART05-002`** | EU AI Act Art. 5(1)(c) | `CRITICAL` | Puntuación o clasificación social de personas físicas (*Social Scoring*). |
| **`EUAIA-ART09-001`** | EU AI Act Art. 9 | `LOW` | Omisión del sistema continuo de gestión y mitigación de riesgos. |
| **`EUAIA-ART10-001`** | EU AI Act Art. 10(2) | `MEDIUM` | Ausencia de validación de datos de entrada o control de sesgos. |
| **`EUAIA-ART11-001`** | EU AI Act Art. 11 | `MEDIUM` | Falta de documentación técnica de especificación de modelos. |
| **`EUAIA-ART12-001`** | EU AI Act Art. 12 | `HIGH` | Ausencia de registro continuo de eventos (*logging*) en llamadas a modelos de IA. |
| **`EUAIA-ART13-001`** | EU AI Act Art. 50 / 13 | `HIGH` | Desactivación o falta de notificación explícita de interacción con IA. |
| **`EUAIA-ART14-001`** | EU AI Act Art. 14 | `HIGH` | Ejecución autónoma sin compuerta de supervisión humana (*Human-in-the-loop*). |
| **`EUAIA-ART15-001`** | EU AI Act Art. 15 | `LOW` | Invocación de modelos en producción sin manejo de fallos ni políticas de contingencia (*fallback*). |
| **`EUAIA-ART15-002`** | EU AI Act Art. 15 | `CRITICAL` | Credencial o clave de API de IA codificada en texto plano (*Hardcoded Secret*). |
| **`EUAIA-ART15-003`** | EU AI Act Art. 15 | `HIGH` | Interpolación dinámica de prompts no sanitizados (*Riesgo de Prompt Injection*). |
| **`EUAIA-ART50-002`** | EU AI Act Art. 50 | `MEDIUM` | Entrega directa de salidas de IA sin moderación ni validación de contenidos. |
| **`GDPR-ART05-001`** | RGPD Art. 5(1)(c) | `MEDIUM` | Persistencia de logs de inferencia sin enmascaramiento de datos personales. |
| **`GDPR-ART05-002`** | RGPD Art. 5(1)(c) / 9 | `HIGH` | Presencia de números de identificación nacional (DNI/NIE) en código o prompts estáticos. |
| **`GDPR-ART05-003`** | RGPD Art. 5(1)(f) / 32 | `CRITICAL` | Inserción de números de tarjeta de crédito (PAN) en flujos de datos hacia el LLM. |
| **`GDPR-ART09-001`** | RGPD Art. 9 | `HIGH` | Tratamiento no autorizado de categorías especiales de datos (biométricos/genéticos). |
| **`GDPR-ART22-001`** | RGPD Art. 22 | `HIGH` | Decisión jurídica o de alto impacto basada únicamente en tratamiento automatizado (*Profiling*). |
| **`GDPR-ART32-001`** | RGPD Art. 32 / Art. 15 | `CRITICAL` | Claves de API de proveedores de IA embebidas en texto plano (`sk-...`, `sk-ant-...`). |
| **`GDPR-ART32-002`** | RGPD Art. 32(1)(a) | `HIGH` | Desactivación explícita de verificación TLS/SSL (`verify=False`) en clientes HTTP. |
| **`GDPR-ART32-003`** | RGPD Art. 32(1)(a) | `HIGH` | Invocación de endpoints de inferencia remota sobre protocolo HTTP no cifrado. |

---

## ⚙️ Configuración del Proyecto (`.aicomply.yaml`)

Puedes definir exclusiones globales y parámetros de escaneo creando un archivo `.aicomply.yaml` en la raíz de tu proyecto:

```yaml
# .aicomply.yaml
exclude_paths:
  - "tests/**"
  - "fixtures/**"
  - "legacy/**"

ignore_rules:
  - "EUAIA-ART15-001"  # Desactivada justificadamente por gestión externa en API Gateway

enforce_risk_tier: "high_risk"  # Fallar en CI/CD si el nivel supera este umbral
```

---

## 🏷️ Supresiones Inline en el Código Fuente

Para suprimir alertas justificadas en líneas específicas de código (ej. tests unitarios o mocks sintéticos), utiliza la directiva `# aicomply:ignore`:

```python
# Suprimir una regla específica
client = OpenAI(api_key="sk-test-mock-key-for-unit-testing")  # aicomply:ignore EUAIA-ART15-002

# Suprimir múltiples reglas en una misma línea
resp = requests.get("http://internal-mock-ai/v1", verify=False)  # aicomply:ignore GDPR-ART32-002,GDPR-ART32-003

# Suprimir todas las reglas en una línea
import fer  # aicomply:ignore ALL
```

---

## 🔄 Integración en CI/CD y Pre-commit

### 1. Pipeline de GitHub Actions con Carga SARIF
Crea el archivo `.github/workflows/compliance.yml`:

```yaml
name: EU AI Act & GDPR Compliance Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  compliance-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install Dependencies & AIComply
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run Test Suite
        run: pytest

      - name: Execute Deterministic Compliance Scan (SARIF)
        run: |
          aicomply scan . --format sarif --output aicomply-results.sarif || true

      - name: Upload SARIF report to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aicomply-results.sarif
```

### 2. Hook de Pre-commit
Añade AIComply a tu archivo `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/aiambo08/AIComply
    rev: v0.1.0
    hooks:
      - id: aicomply
```

---

## 🧪 Ejecución de Pruebas Automatizadas

El proyecto cuenta con una suite completa de **46 pruebas unitarias e integración** en `pytest`:

```bash
# Ejecutar todas las pruebas
pytest

# Ejecutar pruebas con reporte detallado
pytest -v --tb=short

# Ejecutar con reporte de cobertura de código
pytest --cov=aicomply --cov-report=term-missing
```

---

## ⚖️ Aviso Legal y Licencia

**Aviso Legal:** AIComply es una herramienta de asistencia técnica y análisis estático de código orientada a facilitar la conformidad técnica (*Compliance-by-Design*). Su uso no sustituye el asesoramiento legal formal ni garantiza por sí mismo la certificación de conformidad con las autoridades reguladoras.

Distribuido bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para más información.
