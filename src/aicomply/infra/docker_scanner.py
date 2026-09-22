"""
AIComply - Container Infrastructure Scanner
Inspecciona Dockerfile y docker-compose.yml para detectar ejecución bajo root,
endpoints de inferencia en HTTP plano no cifrado y secretos en variables de entorno.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

from aicomply.config import StrictSafeLoader
from aicomply.evidence.hasher import compute_finding_hash
from aicomply.infra.input_reader import read_scan_text
from aicomply.schemas import (
    CodeLocation,
    Finding,
    PatternType,
    Rule,
)


COMPOSE_MAX_DEPTH = 64
COMPOSE_MAX_EVENTS = 20000
COMPOSE_MAX_ALIASES = 256


ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)")
BUILD_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _literal_assignments(line: str) -> List[tuple[str, str]]:
    """ARG APP_USER=app / ENV A=1 B="two": only literal values, nested references stay unresolved."""
    return [
        (name, value.strip("\"'"))
        for name, value in ASSIGNMENT.findall(line.partition(" ")[2])
        if "$" not in value
    ]


def _expand_build_vars(value: str, build_vars: Dict[str, str]) -> str:
    def replace(match: "re.Match[str]") -> str:
        name = match.group(1) or match.group(3)
        if name in build_vars:
            return build_vars[name]
        if match.group(2) is not None:
            return match.group(2)
        return match.group(0)

    return BUILD_VAR.sub(replace, value)


def load_compose_yaml(text: str) -> object:
    """Compose input may use anchors/merge keys; parsing stays bounded by depth, events and aliases."""
    depth = 0
    alias_count = 0
    for index, event in enumerate(yaml.parse(text)):
        if isinstance(event, yaml.events.AliasEvent):
            alias_count += 1
        elif isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            depth += 1
        elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
            depth -= 1
        if depth > COMPOSE_MAX_DEPTH or index >= COMPOSE_MAX_EVENTS or alias_count > COMPOSE_MAX_ALIASES:
            raise ValueError("Compose YAML complexity budget exceeded")
    return yaml.load(text, Loader=StrictSafeLoader)


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
        if not (
            "dockerfile" in filename
            or "compose" in filename and filename.endswith((".yml", ".yaml"))
        ):
            return []
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        content = read_scan_text(file_path, base_path)

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
        build_vars: Dict[str, str] = {}

        for line_idx, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            # 1. Comprobar directiva USER
            parts = line_stripped.split()
            instruction = parts[0].upper()
            if instruction == "FROM":
                has_non_root_user = False
                user_line = line_idx
            if instruction in {"ARG", "ENV"}:
                for name, value in _literal_assignments(line_stripped):
                    build_vars[name] = value
            if instruction == "USER":
                if len(parts) > 1:
                    user_val = _expand_build_vars(parts[1], build_vars).split(":", 1)[0].strip().lower()
                    has_non_root_user = (
                        bool(user_val)
                        and user_val not in {"root", "0"}
                        and not user_val.startswith(("$", "{"))
                    )
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
                            line_sups = suppressions.get(user_line, set())
                            if rule.id in line_sups or "ALL" in line_sups:
                                continue
                            snippet = lines[user_line - 1].strip() if lines else "Dockerfile"
                            findings.append(self._create_finding(
                                rule=rule,
                                target="missing_USER_directive",
                                rel_path=rel_path,
                                start_line=user_line,
                                end_line=user_line,
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
        parsed = load_compose_yaml(content)

        if not isinstance(parsed, dict):
            raise ValueError("Compose document must be a mapping")

        services = parsed.get("services", {})
        if not isinstance(services, dict):
            raise ValueError("Compose services must be a mapping")

        for svc_name, svc_conf in services.items():
            if not isinstance(svc_conf, dict):
                raise ValueError("Compose service must be a mapping")

            # 1. Privileged mode o User Root
            is_privileged = svc_conf.get("privileged") is True
            user_val = str(svc_conf.get("user", "")).lower()
            is_root = user_val.split(":", 1)[0] in {"root", "0"}

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
