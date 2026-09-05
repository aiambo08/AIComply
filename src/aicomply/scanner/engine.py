"""
AIComply - Scan Engine Orchestrator
Coordina la configuración del proyecto (.aicomply.yaml), el análisis AST/Regex,
el filtrado por exclusiones y la agregación determinista del reporte.
"""

from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
import time
from typing import List, Optional, Set, Tuple

from aicomply.classifier.risk_tier import classify_overall_risk
from aicomply.config import AIComplyConfig, load_project_config
from aicomply.evidence.hasher import compute_scan_hash
from aicomply.infra.dependency_scanner import DependencyScanner
from aicomply.infra.docker_scanner import DockerScanner
from aicomply.rules.loader import RuleCatalog
from aicomply.scanner.ast_parser import PythonASTScanner
from aicomply.scanner.regex_matcher import RegexScanner
from aicomply.schemas import Finding, RiskTier, Rule, ScanReport, ScanSummary, Severity
IGNORED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".eggs",
}

PYTHON_EXTENSIONS = {".py", ".pyw"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env", ".toml", ".txt", ".lock"}
INFRA_FILENAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml", "requirements.txt",
    "uv.lock", "pyproject.toml", "pipfile", "pipfile.lock"
}


def is_scannable_file(path: Path) -> bool:
    """Determina si un archivo debe ser incluido en el escaneo estático o de infraestructura."""
    name_lower = path.name.lower()
    # Ignorar artefactos de auditoría autogenerados por el propio escáner
    if name_lower.endswith(".evidence.json") or name_lower.endswith(".sarif") or name_lower.endswith(".sarif.json"):
        return False
    suffix_lower = path.suffix.lower()
    if suffix_lower in TEXT_EXTENSIONS:
        return True
    if name_lower in INFRA_FILENAMES or "dockerfile" in name_lower or "compose" in name_lower:
        return True
    return False


class ScanEngine:
    """Motor central de escaneo determinista con soporte de configuración."""

    def __init__(self, catalog: RuleCatalog, target_articles: Optional[Set[str]] = None, config: Optional[AIComplyConfig] = None) -> None:
        self.catalog = catalog
        self.config = config or AIComplyConfig()
        self.target_articles = target_articles
        self.rules: List[Rule] = self._prepare_active_rules()
        self.ast_scanner = PythonASTScanner(self.rules)
        self.regex_scanner = RegexScanner(self.rules)
        self.dependency_scanner = DependencyScanner(self.rules)
        self.docker_scanner = DockerScanner(self.rules)
    
    def _prepare_active_rules(self) -> List[Rule]:
        """Aplica filtros de artículos CLI y exclusiones de reglas declaradas en la configuración."""
        candidate_rules = (
            self.catalog.filter_by_articles(self.target_articles)
            if self.target_articles
            else self.catalog.rules
        )
        ignored_set = {r.strip().upper() for r in self.config.ignore_rules}
        return [rule for rule in candidate_rules if rule.id.upper() not in ignored_set]

    def _is_path_excluded(self, rel_path: str) -> bool:
        """Verifica si una ruta relativa coincide con los patrones exclude_paths de .aicomply.yaml."""
        norm_path = rel_path.replace("\\", "/")
        for pattern in self.config.exclude_paths:
            norm_pattern = pattern.replace("\\", "/")
            if fnmatch(norm_path, norm_pattern) or fnmatch(norm_path, f"*/{norm_pattern}"):
                return True
        return False

    def scan_path(self, target_path: Path) -> ScanReport:
        start_time = time.perf_counter()
        target_path = target_path.resolve()

        if not target_path.exists():
            raise FileNotFoundError(f"La ruta objetivo no existe: {target_path}")

        # Si no se pasó configuración explícita, buscar .aicomply.yaml en la raíz objetivo
        base_dir = target_path if target_path.is_dir() else target_path.parent
        if self.config == AIComplyConfig():
            loaded_cfg = load_project_config(base_dir)
            if loaded_cfg != self.config:
                self.config = loaded_cfg
                self.rules = self._prepare_active_rules()
                self.ast_scanner = PythonASTScanner(self.rules)
                self.regex_scanner = RegexScanner(self.rules)
                self.dependency_scanner = DependencyScanner(self.rules)
                self.docker_scanner = DockerScanner(self.rules)

        files_to_scan: List[Path] = []
        if target_path.is_file():
            rel_file = str(target_path.relative_to(base_dir)).replace("\\", "/")
            if not self._is_path_excluded(rel_file):
                files_to_scan.append(target_path)
        else:
            for path in target_path.rglob("*"):
                if path.is_file():
                    if any(ignored in path.parts for ignored in IGNORED_DIRS):
                        continue
                    if not is_scannable_file(path):
                        continue

                    rel_path_str = str(path.relative_to(base_dir)).replace("\\", "/")
                    if self._is_path_excluded(rel_path_str):
                        continue

                    files_to_scan.append(path)

        findings: List[Finding] = []
        total_lines = 0
        # Deduplicación cross-engine: (rule_id, file_path, start_line)
        seen_dedup_keys: Set[Tuple[str, str, int]] = set()

        for file_path in sorted(files_to_scan):
            try:
                line_count = sum(1 for _ in file_path.open("rb"))
                total_lines += line_count
            except Exception:
                line_count = 0

            file_findings: List[Finding] = []
            filename_lower = file_path.name.lower()

            # 1. Análisis AST en archivos Python (prioridad sobre Regex)
            if file_path.suffix.lower() in PYTHON_EXTENSIONS:
                ast_findings = self.ast_scanner.scan_file(file_path, base_path=base_dir)
                file_findings.extend(ast_findings)

            # 2. Análisis de Manifiestos y Dependencias (pyproject.toml, requirements.txt, uv.lock, Pipfile)
            dep_findings = self.dependency_scanner.scan_file(file_path, base_path=base_dir)
            file_findings.extend(dep_findings)

            # 3. Análisis de Contenedores Docker y Docker Compose
            docker_findings = self.docker_scanner.scan_file(file_path, base_path=base_dir)
            file_findings.extend(docker_findings)

            # 4. Análisis Regex complementario (Secretos, PII, patrones textuales)
            regex_findings = self.regex_scanner.scan_file(file_path, base_path=base_dir)
            file_findings.extend(regex_findings)

            # 5. Deduplicación: primera detección prevalece sobre duplicados en misma línea
            for f in file_findings:
                dedup_key = (f.rule_id, f.location.file_path, f.location.start_line)
                if dedup_key not in seen_dedup_keys:
                    seen_dedup_keys.add(dedup_key)
                    findings.append(f)

        execution_time = (time.perf_counter() - start_time) * 1000  # ms

        # Generar métricas del resumen
        summary = self._build_summary(
            files_count=len(files_to_scan),
            lines_count=total_lines,
            findings=findings,
            rules_count=len(self.rules),
            exec_time_ms=execution_time,
        )

        scan_hash = compute_scan_hash(findings)

        return ScanReport(
            scan_id=scan_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_path=str(target_path),
            summary=summary,
            findings=findings,
        )

    def _build_summary(
        self,
        files_count: int,
        lines_count: int,
        findings: List[Finding],
        rules_count: int,
        exec_time_ms: float,
    ) -> ScanSummary:
        findings_by_tier = {tier: 0 for tier in RiskTier}
        findings_by_severity = {sev: 0 for sev in Severity}

        for finding in findings:
            findings_by_tier[finding.risk_tier] += 1
            findings_by_severity[finding.severity] += 1

        return ScanSummary(
            total_files_scanned=files_count,
            total_lines_scanned=lines_count,
            total_findings=len(findings),
            findings_by_tier=findings_by_tier,
            findings_by_severity=findings_by_severity,
            rules_loaded=rules_count,
            execution_time_ms=round(exec_time_ms, 2),
        )