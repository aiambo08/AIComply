"""
AIComply - Scan Engine Orchestrator
Coordina la lectura del código fuente, el paso por AST/Regex y la agregación determinista.
"""

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import List, Optional, Set

from aicomply.classifier.risk_tier import classify_overall_risk
from aicomply.evidence.hasher import compute_scan_hash
from aicomply.rules.loader import RuleCatalog
from aicomply.scanner.ast_parser import PythonASTScanner
from aicomply.scanner.regex_matcher import RegexScanner
from aicomply.schemas import Finding, RiskTier, ScanReport, ScanSummary, Severity

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
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env"}


class ScanEngine:
    """Motor central de escaneo determinista."""

    def __init__(self, catalog: RuleCatalog, target_articles: Optional[Set[str]] = None) -> None:
        self.catalog = catalog
        self.rules = (
            self.catalog.filter_by_articles(target_articles)
            if target_articles
            else self.catalog.rules
        )
        self.ast_scanner = PythonASTScanner(self.rules)
        self.regex_scanner = RegexScanner(self.rules)

    def scan_path(self, target_path: Path) -> ScanReport:
        start_time = time.perf_counter()
        target_path = target_path.resolve()

        if not target_path.exists():
            raise FileNotFoundError(f"La ruta objetivo no existe: {target_path}")

        files_to_scan: List[Path] = []
        if target_path.is_file():
            files_to_scan.append(target_path)
            base_dir = target_path.parent
        else:
            base_dir = target_path
            for path in target_path.rglob("*"):
                if path.is_file():
                    # Comprobar si pertenece a una carpeta ignorada
                    if any(ignored in path.parts for ignored in IGNORED_DIRS):
                        continue
                    if path.suffix.lower() in TEXT_EXTENSIONS:
                        files_to_scan.append(path)

        findings: List[Finding] = []
        total_lines = 0

        for file_path in sorted(files_to_scan):
            try:
                line_count = sum(1 for _ in file_path.open("rb"))
                total_lines += line_count
            except Exception:
                line_count = 0

            # 1. Análisis AST en archivos Python
            if file_path.suffix.lower() in PYTHON_EXTENSIONS:
                ast_findings = self.ast_scanner.scan_file(file_path, base_path=base_dir)
                findings.extend(ast_findings)

            # 2. Análisis Regex complementario
            regex_findings = self.regex_scanner.scan_file(file_path, base_path=base_dir)
            findings.extend(regex_findings)

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