"""
AIComply - Container Infrastructure Scanner
Inspecciona Dockerfile y docker-compose.yml para detectar ejecución bajo root,
endpoints de inferencia en HTTP plano no cifrado y secretos en variables de entorno.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from aicomply.evidence.hasher import compute_finding_hash
from aicomply.schemas import (
    CodeLocation,
    Finding,
    PatternType,
    Rule,
    RulePattern,
)


class DockerScanner:
    """Escáner estático de contenedores Docker y Docker Compose."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules = [
            r for r in rules
            if any(p.type == PatternType.INFRA_DOCKER for p in r.patterns)
        ]

    def scan_file(self, file_path: Path, base_path: Optional[Path] = None) -> List[Finding]:
        if not self.rules:
            return []

        filename = file_path.name.lower()
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        try:
            content = file_path.read_text(encoding="utf-8-sig")
        except Exception:
            return []

        lines = content.splitlines()
        suppressions = self._extract_suppressions(lines)

        if "dockerfile" in filename or filename.endswith(".dockerfile"):
            return self._scan_dockerfile(content, lines, rel_path, suppressions)
        elif "compose" in filename and (filename.endswith(".yml") or filename.endswith(".yaml")):
            return self._scan_docker_compose(content, lines, rel_path, suppressions)

        return []

    def _extract_suppressions(self, lines: List[str]) -> Dict[int, Set[str]]:
        suppressions: Dict[int, Set[str]] = {}
        for idx, line in enumerate(lines, start=1):
            if "aicomply:ignore" in line:
                parts = line.split("aicomply:ignore")
                if len(parts) > 1:
                    raw_rules = parts[1].strip().split()
                    rules = {r.strip(",;").upper() for r in raw_rules if r.strip(",;")}
                    suppressions[idx] = rules
        return suppressions

    def _scan_dockerfile(
        self,
        content: str,
        lines: List[str],
        rel_path: str,
        suppressions: Dict[int, Set[str]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        has_non_root_user = False
        user_line = 1

        for line_idx, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            # 1. Comprobar directiva USER
            if line_stripped.upper().startswith("USER"):
                parts = line_stripped.split()
                if len(parts) > 1:
                    user_val = parts[1].strip().lower()
                    if user_val not in {"root", "0", "0:0"}:
                        has_non_root_user = True
                        user_line = line_idx

            # 2. Comprobar secretos hardcodeados en ENV o ARG
            if line_stripped.upper().startswith(("ENV ", "ARG ")):
                for secret_kw in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "AWS_SECRET_ACCESS_KEY"]:
                    if secret_kw in line_stripped and "=" in line_stripped:
                        val_part = line_stripped.split("=", 1)[1].strip()
                        if val_part and not val_part.startswith(("$", "{")) and len(val_part) > 6:
                            for rule in self.rules:
                                for pattern in rule.patterns:
                                    if pattern.type == PatternType.INFRA_DOCKER and pattern.match_args:
                                        if pattern.match_args.get("secrets_in_env"):
                                            line_sups = suppressions.get(line_idx, set())
                                            if rule.id in line_sups or "ALL" in line_sups:
                                                continue
                                            findings.append(self._create_finding(
                                                rule=rule,
                                                target=f"ENV {secret_kw}",
                                                rel_path=rel_path,
                                                start_line=line_idx,
                                                end_line=line_idx,
                                                snippet=line_stripped,
                                            ))

            # 3. Comprobar endpoints HTTP de inferencia sin cifrado (EXPOSE 8000/5000 sin TLS)
            if line_stripped.upper().startswith("EXPOSE"):
                for port in ["80", "8000", "5000", "8080"]:
                    if re.search(rf"\b{port}\b", line_stripped):
                        for rule in self.rules:
                            for pattern in rule.patterns:
                                if pattern.type == PatternType.INFRA_DOCKER and pattern.match_args:
                                    if pattern.match_args.get("insecure_http_endpoint"):
                                        line_sups = suppressions.get(line_idx, set())
                                        if rule.id in line_sups or "ALL" in line_sups:
                                            continue
                                        findings.append(self._create_finding(
                                            rule=rule,
                                            target=f"EXPOSE {port}",
                                            rel_path=rel_path,
                                            start_line=line_idx,
                                            end_line=line_idx,
                                            snippet=line_stripped,
                                        ))

        # Evaluar regla de usuario root si no se definió USER no-root
        if not has_non_root_user:
            for rule in self.rules:
                for pattern in rule.patterns:
                    if pattern.type == PatternType.INFRA_DOCKER and pattern.match_args:
                        if pattern.match_args.get("missing_directive") == "USER":
                            line_sups = suppressions.get(1, set())
                            if rule.id in line_sups or "ALL" in line_sups:
                                continue
                            snippet = lines[0].strip() if lines else "Dockerfile"
                            findings.append(self._create_finding(
                                rule=rule,
                                target="missing_USER_directive",
                                rel_path=rel_path,
                                start_line=1,
                                end_line=1,
                                snippet=snippet,
                            ))

        return findings

    def _scan_docker_compose(
        self,
        content: str,
        lines: List[str],
        rel_path: str,
        suppressions: Dict[int, Set[str]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            parsed = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(parsed, dict) or "services" not in parsed:
            return findings

        services = parsed.get("services", {})
        if not isinstance(services, dict):
            return findings

        for svc_name, svc_conf in services.items():
            if not isinstance(svc_conf, dict):
                continue

            # 1. Privileged mode o User Root
            is_privileged = svc_conf.get("privileged") is True
            user_val = str(svc_conf.get("user", "")).lower()
            is_root = user_val in {"root", "0", "0:0"}

            if is_privileged or is_root:
                for rule in self.rules:
                    for pattern in rule.patterns:
                        if pattern.type == PatternType.INFRA_DOCKER and pattern.match_args:
                            if pattern.match_args.get("privileged_mode"):
                                line_num = self._find_service_line(lines, svc_name)
                                line_sups = suppressions.get(line_num, set())
                                if rule.id in line_sups or "ALL" in line_sups:
                                    continue
                                findings.append(self._create_finding(
                                    rule=rule,
                                    target=f"service '{svc_name}' (privileged/root)",
                                    rel_path=rel_path,
                                    start_line=line_num,
                                    end_line=line_num,
                                    snippet=lines[line_num - 1].strip() if line_num <= len(lines) else svc_name,
                                ))

            # 2. Puertos directos de inferencia sin cifrado (ej. 8000:8000)
            ports = svc_conf.get("ports", [])
            if isinstance(ports, list):
                for p in ports:
                    p_str = str(p)
                    for insecure_p in ["80:80", "8000:8000", "5000:5000", "8080:8080"]:
                        if insecure_p in p_str:
                            for rule in self.rules:
                                for pattern in rule.patterns:
                                    if pattern.type == PatternType.INFRA_DOCKER and pattern.match_args:
                                        if pattern.match_args.get("insecure_http_endpoint"):
                                            line_num = self._find_port_line(lines, p_str)
                                            line_sups = suppressions.get(line_num, set())
                                            if rule.id in line_sups or "ALL" in line_sups:
                                                continue
                                            findings.append(self._create_finding(
                                                rule=rule,
                                                target=f"ports: {p_str}",
                                                rel_path=rel_path,
                                                start_line=line_num,
                                                end_line=line_num,
                                                snippet=lines[line_num - 1].strip() if line_num <= len(lines) else p_str,
                                            ))

        return findings

    def _find_service_line(self, lines: List[str], svc_name: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if f"{svc_name}:" in line:
                return idx
        return 1

    def _find_port_line(self, lines: List[str], port_str: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if port_str in line:
                return idx
        return 1

    def _create_finding(
        self,
        rule: Rule,
        target: str,
        rel_path: str,
        start_line: int,
        end_line: int,
        snippet: str,
    ) -> Finding:
        loc = CodeLocation(
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            start_col=0,
            end_col=len(snippet),
        )
        finding_id = compute_finding_hash(rule.id, loc, target, snippet)
        return Finding(
            id=finding_id,
            rule_id=rule.id,
            article=rule.article,
            severity=rule.severity,
            risk_tier=rule.risk_tier,
            title=rule.title,
            message=f"Riesgo de infraestructura detectado en '{target}' ({rule.article}).",
            location=loc,
            code_snippet=snippet,
            remediation=rule.remediation,
            max_fine=rule.max_fine,
            confidence=rule.confidence,
        )
