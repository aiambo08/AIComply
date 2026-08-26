"""
AIComply - Project Configuration Loader (.aicomply.yaml)
Permite definir exclusiones de reglas, rutas ignoradas y umbrales de fallo en CI/CD.
"""
from pathlib import Path
from typing import List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field
import yaml

class AIComplyConfig(BaseModel):
    """Esquema de configuración de AIComply por repositorio"""
    model_config = ConfigDict(frozen=True, extra="forbid")

    exclude_paths: List[str] = Field(
        default_factory=lambda: ["tests/**", "fixtures/**", "docs/**"],
        description="Rutas o patrones glob a ignorar durante el escaneo."
    )
    ignore_rules: List[str] = Field(
        default_factory=list,
        description="IDs de reglas desactivadas globalmente (ej. ['EUAIA-ART15-001'])."
    )
    enforce_risk_tier: Optional[str] = Field(
        default=None,
        description="Nivel de riesgo máximo tolerado antes de fallar (ej. 'high_risk')."
    )
    custom_rules_dir: Optional[str] = Field(
        default=None,
        description="Ruta relativa a reglas personalizadas adicionales"
    )

def load_project_config(target_dir: Path) -> AIComplyConfig:
    """Busca y carga un archivo .aicomply.yaml o aicomply.yml en el directorio objetivo."""
    candidate_files = [
        target_dir / ".aicomply.yaml",
        target_dir / ".aicomply.yml",
        target_dir / "aicomply.yaml",
    ]

    for config_path in candidate_files:
        if config_path.is_file():
            try:
                with open(config_path, "r", encoding="UTF-8") as f:
                    raw_data = yaml.safe_load(f) or {}
                return AIComplyConfig.model_validate(raw_data)
            except Exception:
                # Si el archivo está corrupto, continuar con la configuración por efecto
                return AIComplyConfig()
    
    return AIComplyConfig()