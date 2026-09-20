"""
AIComply - Regex Pattern Matcher
Fallback determinista para escaneo por expresiones regulares en código fuente no-Python o texto plano.
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set, Tuple

from aicomply.evidence.hasher import compute_finding_hash
from aicomply.infra.input_reader import read_scan_text
from aicomply.schemas import (
    CodeLocation,
    Finding,
    PatternType,
    Rule,
    RulePattern,
)

REGEX_TIMEOUT_SECONDS = 2
MAX_REGEX_PATTERNS = 256
MAX_REGEX_LENGTH = 4096
_REGEX_WORKER = """
import json
import re
import sys

payload = json.load(sys.stdin)
patterns = [(rule, re.compile(pattern)) for rule, pattern in payload["patterns"]]
matches = []
for line_idx, (line, suppressed) in enumerate(payload["lines"]):
    for pattern_idx, (rule, pattern) in enumerate(patterns):
        if rule in suppressed or "ALL" in suppressed:
            continue
        match = pattern.search(line)
        if match is not None:
            matches.append((line_idx, pattern_idx, match.start(), match.end()))
            if len(matches) > 20000:
                raise ValueError("Regex match budget exceeded")
json.dump(matches, sys.stdout)
"""


class RegexScanner:
    """Escanea archivos de texto plano contra patrones REGEX respetando supresiones."""

    def __init__(self, rules: List[Rule]) -> None:
        # Pre-compilar patrones REGEX para evitar recompilación por línea
        self.regex_rules: List[Tuple[Rule, RulePattern, "re.Pattern[str]"]] = []
        for rule in rules:
            for pattern in rule.patterns:
                if pattern.type == PatternType.REGEX:
                    if not pattern.target or len(pattern.target) > MAX_REGEX_LENGTH:
                        raise ValueError(f"Invalid regex length for rule {rule.id}")
                    if len(self.regex_rules) >= MAX_REGEX_PATTERNS:
                        raise ValueError("Regex pattern budget exceeded")
                    try:
                        compiled = re.compile(pattern.target)
                        self.regex_rules.append((rule, pattern, compiled))
                    except re.error as exc:
                        raise ValueError(f"Invalid regex for rule {rule.id}") from exc

    def _extract_suppressions(self, line: str) -> Set[str]:
        """Extrae directivas de supresión: # aicomply:ignore ID1,ID2 o // aicomply:ignore ID1."""
        if "aicomply:ignore" not in line:
            return set()
        parts = line.split("aicomply:ignore")
        if len(parts) <= 1:
            return set()
        raw_tokens = parts[1].strip().split()
        return {
            token.strip(",;#/").upper() for token in raw_tokens if token.strip(",;#/")
        }

    def scan_file(
        self, file_path: Path, base_path: Optional[Path] = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = (
            str(file_path.relative_to(base_path)) if base_path else str(file_path)
        )

        if not self.regex_rules:
            return findings
        lines = read_scan_text(file_path, base_path).splitlines()
        payload = {
            "patterns": [
                (rule.id, pattern.target) for rule, pattern, _ in self.regex_rules
            ],
            "lines": [
                (line, sorted(self._extract_suppressions(line))) for line in lines
            ],
        }
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", _REGEX_WORKER],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=REGEX_TIMEOUT_SECONDS,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"Regex scan time budget exceeded: {rel_path}") from exc
        except subprocess.CalledProcessError as exc:
            raise ValueError(f"Regex scan failed: {rel_path}") from exc

        seen_keys: Set[Tuple[str, str, int]] = set()

        for line_offset, pattern_index, start, end in json.loads(completed.stdout):
            line_idx = line_offset + 1
            line_content = lines[line_offset]
            rule, pattern, _ = self.regex_rules[pattern_index]
            dedup_key = (rule.id, rel_path, line_idx)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            loc = CodeLocation(
                file_path=rel_path,
                start_line=line_idx,
                end_line=line_idx,
                start_col=start,
                end_col=end,
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
