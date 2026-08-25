"""
AIComply - Core Data Schemas (Pydantic v2)
Define las estructuras de datos para reglas del EU AI Act, patrones de coincidencia,
hallazgos de auditoría (findings) y reportes de conformidad.
"""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskTier(str, Enum):
    """Clasificación de riesgo según el Reglamento (UE) 2024/1689."""
    PROHIBITED = "prohibited"       # Art. 5 (Prácticas prohibidas)
    HIGH_RISK = "high_risk"         # Art. 6, Anexo III, Cap. III (Sistemas de alto riesgo)
    LIMITED_RISK = "limited_risk"   # Art. 50 (Obligaciones de transparencia)
    MINIMAL_RISK = "minimal_risk"   # Riesgo nulo o mínimo (sistemas estándar/sin restricciones)


class Severity(str, Enum):
    """Nivel de severidad técnica del hallazgo."""
    CRITICAL = "CRITICAL"  # P0: Prácticas prohibidas / Multas de hasta 35M€ / 7%
    HIGH = "HIGH"          # P1: Incumplimiento crítico en alto riesgo / Art. 12, 13, 14
    MEDIUM = "MEDIUM"      # P2: Gobernanza de datos / Doc técnica / Art. 10, 11
    LOW = "LOW"            # P3: Gestión de riesgos / Precisión / Art. 9, 15
    INFO = "INFO"          # Recomendaciones de buenas prácticas


class Confidence(str, Enum):
    """Certeza determinista de la regla."""
    HIGH = "HIGH"      # Coincidencia AST exacta (llamada explícita a API/función)
    MEDIUM = "MEDIUM"  # Coincidencia por patrón semántico o heurística AST
    LOW = "LOW"        # Coincidencia por Regex difuso o comentario


class PatternType(str, Enum):
    """Tipo de mecanismo de detección a ejecutar."""
    AST_CALL = "ast_call"                   # Detección de llamadas a funciones/métodos (ej. openai.ChatCompletion)
    AST_IMPORT = "ast_import"               # Detección de módulos importados (ej. langchain, emotion_recognition)
    AST_ASSIGNMENT = "ast_assignment"       # Asignación de variables sensibles
    AST_FUNCTION_DEF = "ast_function_def"   # Firma o nombre de función
    AST_ABSENCE = "ast_absence"             # Detección de ausencia (ej. llamada a LLM sin logger en el mismo scope)
    REGEX = "regex"                         # Fallback para archivos no-Python o comentarios


class RulePattern(BaseModel):
    """Especificación de un patrón de detección dentro de una regla."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    type: PatternType = Field(..., description="Tipo de análisis AST o Regex a aplicar")
    target: str = Field(..., description="Símbolo, import, función o expresión regular a buscar")
    match_args: Optional[Dict[str, Any]] = Field(
        default=None, 
        description="Parámetros obligatorios o prohibidos dentro de una llamada de función"
    )
    negate: bool = Field(
        default=False, 
        description="Si es True, la regla dispara cuando el patrón NO se encuentra (ej. falta de logging)"
    )


class Rule(BaseModel):
    """Estructura de una regla de cumplimiento del EU AI Act."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        ...,
        pattern=r"^[A-Z0-9]{3,8}-(ART\d+|GEN)-\d{3}$",
        description="Identificador único (ej. EUAIA-ART05-001, GDPR-ART09-001)",
    )
    article: str = Field(..., description="Artículo de referencia en el EU AI Act (ej. Art. 5(1)(c))")
    title: str = Field(..., min_length=5, max_length=150)
    severity: Severity
    risk_tier: RiskTier
    description: str = Field(..., min_length=10)
    remediation: str = Field(..., description="Instrucciones directas para corregir el código")
    max_fine: str = Field(..., description="Sanción financiera máxima aplicable (ej. '35M€ o 7%')")
    confidence: Confidence
    patterns: List[RulePattern] = Field(..., min_length=1)

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        return v.strip().upper()


class CodeLocation(BaseModel):
    """Ubicación exacta del hallazgo en el código fuente."""
    model_config = ConfigDict(frozen=True)

    file_path: str = Field(..., description="Ruta relativa del archivo analizado")
    start_line: int = Field(..., ge=1)
    end_line: int = Field(..., ge=1)
    start_col: int = Field(default=0, ge=0)
    end_col: int = Field(default=0, ge=0)


class Finding(BaseModel):
    """Representación inmutable de una no-conformidad detectada."""
    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Hash SHA-256 determinista del hallazgo (para auditoría)")
    rule_id: str
    article: str
    severity: Severity
    risk_tier: RiskTier
    title: str
    message: str
    location: CodeLocation
    code_snippet: Optional[str] = Field(default=None, description="Líneas de código asociadas al hallazgo")
    remediation: str
    max_fine: str
    confidence: Confidence


class ScanSummary(BaseModel):
    """Resumen estadístico y métricas del escaneo."""
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    total_findings: int = 0
    findings_by_tier: Dict[RiskTier, int] = Field(default_factory=lambda: {tier: 0 for tier in RiskTier})
    findings_by_severity: Dict[Severity, int] = Field(default_factory=lambda: {sev: 0 for sev in Severity})
    rules_loaded: int = 0
    execution_time_ms: float = 0.0


class ScanReport(BaseModel):
    """Payload canónico del reporte de conformidad emitido por AIComply."""
    model_config = ConfigDict(frozen=True)

    scan_id: str = Field(..., description="Hash SHA-256 del conjunto total de hallazgos")
    timestamp: str = Field(..., description="Timestamp ISO 8601 UTC de ejecución")
    target_path: str
    summary: ScanSummary
    findings: List[Finding]