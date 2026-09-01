"""
AIComply - Data Flow Lattice & Taint States
Formalización del retículo de seguridad y operador de unión pesimista (⊔).
"""

from enum import Enum
from typing import Dict, Set


class TaintState(str, Enum):
    """
    Retículo de estados de taint para variables:
    CLEAN (⊥) ⊏ HUMAN_GATED ≡ SANITIZED ⊏ TAINTED_UNSAFE
    """
    CLEAN = "CLEAN"                    # ⊥: Literales fijos o entradas no-IA
    HUMAN_GATED = "HUMAN_GATED"        # Camino protegido por compuerta condicional humana
    SANITIZED = "SANITIZED"            # Saneado por validador de esquemas / moderación
    TAINTED_UNSAFE = "TAINTED_UNSAFE"  # Dato no validado originado en LLM / IA generativa


def pessimistic_join(s1: TaintState, s2: TaintState) -> TaintState:
    """
    Operador de Unión Pesimista (⊔) en puntos de convergencia del CFG (if/else phi-nodes).
    
    Regla fundamental de solidez (soundness):
    TAINTED_UNSAFE ⊔ SANITIZED = TAINTED_UNSAFE
    TAINTED_UNSAFE ⊔ HUMAN_GATED = TAINTED_UNSAFE
    TAINTED_UNSAFE ⊔ CLEAN = TAINTED_UNSAFE
    SANITIZED ⊔ HUMAN_GATED = SANITIZED
    SANITIZED ⊔ SANITIZED = SANITIZED
    HUMAN_GATED ⊔ HUMAN_GATED = HUMAN_GATED
    CLEAN ⊔ X = X
    """
    if s1 == TaintState.TAINTED_UNSAFE or s2 == TaintState.TAINTED_UNSAFE:
        return TaintState.TAINTED_UNSAFE

    if s1 == TaintState.SANITIZED or s2 == TaintState.SANITIZED:
        return TaintState.SANITIZED

    if s1 == TaintState.HUMAN_GATED or s2 == TaintState.HUMAN_GATED:
        return TaintState.HUMAN_GATED

    return TaintState.CLEAN


class TaintEnvironment:
    """
    Entorno de mapeo de variables a estados de taint en un punto del programa.
    """

    def __init__(self, mapping: Dict[str, TaintState] = None) -> None:
        self._mapping: Dict[str, TaintState] = dict(mapping) if mapping else {}

    def get(self, var_name: str) -> TaintState:
        return self._mapping.get(var_name, TaintState.CLEAN)

    def set(self, var_name: str, state: TaintState) -> None:
        self._mapping[var_name] = state

    def copy(self) -> "TaintEnvironment":
        return TaintEnvironment(dict(self._mapping))

    def join(self, other: "TaintEnvironment") -> "TaintEnvironment":
        """Realiza la unión pesimista de dos entornos de ejecución."""
        all_vars: Set[str] = set(self._mapping.keys()).union(other._mapping.keys())
        merged: Dict[str, TaintState] = {}
        for var in all_vars:
            s1 = self.get(var)
            s2 = other.get(var)
            merged[var] = pessimistic_join(s1, s2)
        return TaintEnvironment(merged)

    def is_tainted(self, var_name: str) -> bool:
        return self.get(var_name) == TaintState.TAINTED_UNSAFE

    def __repr__(self) -> str:
        return f"TaintEnv({self._mapping})"
