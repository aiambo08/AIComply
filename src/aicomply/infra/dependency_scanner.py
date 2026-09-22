"""
AIComply - Dependency & Manifest Infrastructure Scanner
Inspecciona de forma determinista y offline archivos pyproject.toml, requirements.txt,
uv.lock y Pipfile para detectar dependencias de IA prohibidas y versiones vulnerables.
"""

import json
import re
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Set

from aicomply.evidence.hasher import compute_finding_hash
from aicomply.infra.input_reader import read_scan_text
from aicomply.schemas import (
    CodeLocation,
    Finding,
    PatternType,
    Rule,
)


def _package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _table(parent: dict, name: str) -> dict:
    value = parent.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"Manifest field '{name}' must be a table")
    return value


class DependencyScanner:
    """Escáner estático de dependencias y manifiestos de paquetes."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules = [
            r for r in rules 
            if any(p.type == PatternType.INFRA_DEPENDENCY for p in r.patterns)
        ]

    def scan_file(self, file_path: Path, base_path: Optional[Path] = None) -> List[Finding]:
        if not self.rules:
            return []

        filename = file_path.name.lower()
        if not (
            filename in {"pyproject.toml", "uv.lock", "pipfile", "pipfile.lock"}
            or filename.startswith("requirements") and filename.endswith(".txt")
        ):
            return []
        rel_path = str(file_path.relative_to(base_path)) if base_path else str(file_path)

        content = read_scan_text(file_path, base_path)

        lines = content.splitlines()
        suppressions = self._extract_suppressions(lines)

        # Determinar el tipo de manifiesto
        if filename == "requirements.txt" or filename.startswith("requirements") and filename.endswith(".txt"):
            return self._scan_requirements_txt(content, lines, rel_path, suppressions)
        elif filename == "pyproject.toml":
            return self._scan_pyproject_toml(content, lines, rel_path, suppressions)
        elif filename == "uv.lock":
            return self._scan_uv_lock(content, lines, rel_path, suppressions)
        elif filename in {"pipfile", "pipfile.lock"}:
            return self._scan_pipfile(content, lines, rel_path, suppressions)

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

    def _scan_requirements_txt(
        self,
        content: str,
        lines: List[str],
        rel_path: str,
        suppressions: Dict[int, Set[str]],
    ) -> List[Finding]:
        findings: List[Finding] = []

        for line_idx, line in enumerate(lines, start=1):
            line_clean = re.sub(r"(?:^|\s)#.*$", "", line).strip()
            if not line_clean:
                continue

            # Parsear nombre de paquete (ej. "torch>=2.0.0", "deepface==0.0.79", "face-recognition",
            # "git+https://host/repo.git#egg=deepface", "-e git+...#egg=deepface")
            egg_match = re.search(r"#egg=([a-zA-Z0-9_\-\.]+)", line_clean)
            pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", line_clean)
            if egg_match:
                pkg_name = _package_name(egg_match.group(1))
            elif pkg_match and not re.match(r"^\S*://", line_clean):
                pkg_name = _package_name(pkg_match.group(1))
            else:
                continue

            for rule in self.rules:
                for pattern in rule.patterns:
                    if pattern.type == PatternType.INFRA_DEPENDENCY and pattern.target:
                        target_norm = _package_name(pattern.target)
                        if target_norm == pkg_name:
                            # Comprobar supresiones
                            line_sups = suppressions.get(line_idx, set())
                            if rule.id in line_sups or "ALL" in line_sups:
                                continue

                            finding = self._create_finding(
                                rule=rule,
                                target=pattern.target,
                                rel_path=rel_path,
                                start_line=line_idx,
                                end_line=line_idx,
                                snippet=line.strip(),
                            )
                            findings.append(finding)

        return findings

    def _scan_pyproject_toml(
        self,
        content: str,
        lines: List[str],
        rel_path: str,
        suppressions: Dict[int, Set[str]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = tomllib.loads(content)

        # Extraer dependencias de [project.dependencies] y [project.optional-dependencies]
        declared_pkgs: Set[str] = set()
        project = _table(parsed, "project")
        project_deps = project.get("dependencies", [])
        if not isinstance(project_deps, list) or not all(isinstance(dep, str) for dep in project_deps):
            raise ValueError("Project dependencies must be a list of strings")
        if isinstance(project_deps, list):
            for dep in project_deps:
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)", str(dep).strip())
                if m:
                    declared_pkgs.add(_package_name(m.group(1)))

        opt_deps = _table(project, "optional-dependencies")
        if isinstance(opt_deps, dict):
            for group, deps in opt_deps.items():
                if not isinstance(deps, list) or not all(isinstance(dep, str) for dep in deps):
                    raise ValueError("Optional dependencies must be lists of strings")
                if isinstance(deps, list):
                    for dep in deps:
                        m = re.match(r"^([a-zA-Z0-9_\-\.]+)", str(dep).strip())
                        if m:
                            declared_pkgs.add(_package_name(m.group(1)))

        # Poetry dependencies
        poetry_deps = _table(_table(_table(parsed, "tool"), "poetry"), "dependencies")
        if isinstance(poetry_deps, dict):
            for k in poetry_deps.keys():
                declared_pkgs.add(_package_name(str(k)))

        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern.type == PatternType.INFRA_DEPENDENCY and pattern.target:
                    target_norm = _package_name(pattern.target)
                    if target_norm in declared_pkgs:
                        # Buscar número de línea en el archivo
                        match_line = 1
                        for idx, line in enumerate(lines, start=1):
                            if target_norm in line.lower().replace("_", "-"):
                                match_line = idx
                                break

                        line_sups = suppressions.get(match_line, set())
                        if rule.id in line_sups or "ALL" in line_sups:
                            continue

                        finding = self._create_finding(
                            rule=rule,
                            target=pattern.target,
                            rel_path=rel_path,
                            start_line=match_line,
                            end_line=match_line,
                            snippet=lines[match_line - 1].strip() if match_line <= len(lines) else pattern.target,
                        )
                        findings.append(finding)

        return findings

    def _scan_uv_lock(
        self,
        content: str,
        lines: List[str],
        rel_path: str,
        suppressions: Dict[int, Set[str]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = tomllib.loads(content)

        # En uv.lock, los paquetes están en [[package]] name = "..."
        packages = parsed.get("package", [])
        if not isinstance(packages, list):
            raise ValueError("Lockfile packages must be a list of tables")

        for pkg in packages:
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                raise ValueError("Lockfile package requires a string name")
            if isinstance(pkg, dict) and "name" in pkg:
                pkg_name = _package_name(pkg["name"])
                for rule in self.rules:
                    for pattern in rule.patterns:
                        if pattern.type == PatternType.INFRA_DEPENDENCY and pattern.target:
                            target_norm = _package_name(pattern.target)
                            if target_norm == pkg_name:
                                # Buscar la línea de este paquete en uv.lock
                                match_line = 1
                                for idx, line in enumerate(lines, start=1):
                                    if f'name = "{pkg["name"]}"' in line or f"name = '{pkg['name']}'" in line:
                                        match_line = idx
                                        break

                                line_sups = suppressions.get(match_line, set())
                                if rule.id in line_sups or "ALL" in line_sups:
                                    continue

                                finding = self._create_finding(
                                    rule=rule,
                                    target=pattern.target,
                                    rel_path=rel_path,
                                    start_line=match_line,
                                    end_line=match_line,
                                    snippet=lines[match_line - 1].strip() if match_line <= len(lines) else f"name = '{pkg['name']}'",
                                )
                                findings.append(finding)

        return findings

    def _scan_pipfile(
        self,
        content: str,
        lines: List[str],
        rel_path: str,
        suppressions: Dict[int, Set[str]],
    ) -> List[Finding]:
        findings: List[Finding] = []
        if rel_path.lower().endswith(".lock"):
            parsed = json.loads(content)
            if not isinstance(parsed, dict):
                raise ValueError("Pipfile.lock must contain an object")
            sections = ("default", "develop")
        else:
            parsed = tomllib.loads(content)
            sections = ("packages", "dev-packages")
        packages = {
            _package_name(name)
            for section in sections for name in _table(parsed, section)
        }
        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern.type != PatternType.INFRA_DEPENDENCY or not pattern.target:
                    continue
                target_norm = _package_name(pattern.target)
                if target_norm not in packages:
                    continue
                line_idx = next(
                    (idx for idx, line in enumerate(lines, start=1)
                     if not line.lstrip().startswith("#") and target_norm in _package_name(line)),
                    1,
                )
                line_sups = suppressions.get(line_idx, set())
                if rule.id in line_sups or "ALL" in line_sups:
                    continue
                findings.append(self._create_finding(
                    rule=rule,
                    target=pattern.target,
                    rel_path=rel_path,
                    start_line=line_idx,
                    end_line=line_idx,
                    snippet=lines[line_idx - 1].strip(),
                ))
        return findings

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
            message=f"Dependencia detectada '{target}' sujeta a restricciones bajo {rule.article}.",
            location=loc,
            code_snippet=snippet,
            remediation=rule.remediation,
            max_fine=rule.max_fine,
            confidence=rule.confidence,
        )
