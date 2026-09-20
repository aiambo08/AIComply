"""
AIComply - Risk Tier Classifier
Agrega etiquetas técnicas del catálogo; no clasifica jurídicamente el sistema.
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
    Agrega la etiqueta más restrictiva entre las reglas que coinciden.
    minimal_risk es el valor vacío de esta jerarquía, no una conclusión jurídica.
    """
    if not findings:
        return RiskTier.MINIMAL_RISK

    present_tiers = {f.risk_tier for f in findings}
    
    for tier in TIER_HIERARCHY:
        if tier in present_tiers:
            return tier

    return RiskTier.MINIMAL_RISK