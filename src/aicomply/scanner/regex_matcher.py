"""
AIComply - Regex Pattern Matcher
Fallback determinista para escaneo por expresiones regulares en código fuente no-Python o texto plano.
"""

from pathlib import Path
import re
from typing import List, Optional, Set, Tuple

from aicomply.evidence.hasher import compute_finding_hash
from aicomply.schemas import (
    CodeLocation,
    Finding,
    PatternType,
    Rule,
    RulePattern,
)


class RegexScanner:
    """Escanea archivos de texto plano contra patrones REGEX respetando supresiones."""
    def __init__(self, rules: List[Rule]) -> None:
        # Pre-compilar patrones REGEX para evitar recompilación por línea
        self.regex_rules: List[Tuple[Rule, RulePattern, "re.Pattern[str]"]] = []
        for rule in rules:
            for pattern in rule.patterns:
                if pattern.type == PatternType.REGEX:
                    try:
                        compiled = re.compile(pattern.target)
                        self.regex_rules.append((rule, pattern, compiled))
                    except re.error:
                        continue  # Patrón inválido descartado silenciosamente
    
    def _extract_suppressions(self, line: str) -> Set[str]:
        """Extrae directivas de supresión: # aicomply:ignore ID1,ID2 o // aicomply:ignore ID1."""
        if "aicomply:ignore" not in line:
            return set()
        parts = line.split("aicomply:ignore")
        if len(parts) <= 1:
            return set()
        raw_tokens = parts[1].strip().split()
        return {token.strip(",;#/").upper() for token in raw_tokens if token.strip(",;#/")}

    def scan_file(self, file_path: Path, base_path: Optional[Path] = None) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, PermissionError):
            return findings
        
        seen_keys: Set[Tuple[str, str, int]] = set()

        for line_idx, line_content in enumerate(lines, start=1):
            suppressions = self._extract_suppressions(line_content)

            for rule, pattern, compiled in self.regex_rules:
                if rule.id in suppressions or "ALL" in suppressions:
                    continue

                match = compiled.search(line_content)
                if match:
                    dedup_key = (rule.id, rel_path, line_idx)
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    
                    loc = CodeLocation(
                        file_path=rel_path,
                        start_line=line_idx,
                        end_line=line_idx,
                        start_col=match.start(),
                        end_col=match.end(),
                    )
                    snippet = line_content.strip()
                    finding_id = compute_finding_hash(rule.id, loc, pattern.target, snippet)

                    findings.append(
                        Finding(
                            id=finding_id,
                            rule_id=rule.id,
                            article=rule.article,
                            severity=rule.severity,
                            risk_tier=rule.risk_tier,
                            title=rule.title,
                            message=f"Coincidencia de patrón regex '{pattern.target}' con {rule.article}.",
                            location=loc,
                            code_snippet=snippet,
                            remediation=rule.remediation,
                            max_fine=rule.max_fine,
                            confidence=rule.confidence,
                        )
                    )

        return findings