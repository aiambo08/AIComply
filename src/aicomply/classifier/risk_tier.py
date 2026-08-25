"""
AIComply - Risk Tier Classifier
Calcula la postura global de riesgo del repositorio basándose en la severidad y artículo de los hallazgos.
"""

from typing import List
from aicomply.schemas import Finding, RiskTier


# Jerarquía estricta de riesgo (de mayor a menor)
TIER_HIERARCHY = [
    RiskTier.PROHIBITED,
    RiskTier.HIGH_RISK,
    RiskTier.LIMITED_RISK,
    RiskTier.MINIMAL_RISK,
]


def classify_overall_risk(findings: List[Finding]) -> RiskTier:
    """
    Determina el nivel de riesgo más restrictivo presente en el código escaneado.
    Si no hay hallazgos, el sistema se cataloga como 'minimal_risk'.
    """
    if not findings:
        return RiskTier.MINIMAL_RISK

    present_tiers = {f.risk_tier for f in findings}
    
    for tier in TIER_HIERARCHY:
        if tier in present_tiers:
            return tier

    return RiskTier.MINIMAL_RISK