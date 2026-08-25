"""
AIComply - Regex Pattern Matcher
Fallback determinista para escaneo por expresiones regulares en código fuente no-Python o texto plano.
"""

from pathlib import Path
import re
from typing import List, Optional

from aicomply.evidence.hasher import compute_finding_hash
from aicomply.schemas import (
    CodeLocation,
    Finding,
    PatternType,
    Rule,
    RulePattern,
)


class RegexScanner:
    """Escanea archivos de texto plano línea por línea contra reglas tipo REGEX."""

    def __init__(self, rules: List[Rule]) -> None:
        # Filtrar solo reglas que definan patrones REGEX
        self.regex_rules = [
            (rule, pattern)
            for rule in rules
            for pattern in rule.patterns
            if pattern.type == PatternType.REGEX
        ]

    def scan_file(self, file_path: Path, base_path: Optional[Path] = None) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, PermissionError):
            return findings

        for line_idx, line_content in enumerate(lines, start=1):
            for rule, pattern in self.regex_rules:
                match = re.search(pattern.target, line_content)
                if match:
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