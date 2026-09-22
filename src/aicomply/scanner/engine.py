"""
AIComply - Scan Engine Orchestrator
Coordina la configuración del proyecto (.aicomply.yaml), el análisis AST/Regex,
el filtrado por exclusiones y la agregación determinista del reporte.
"""

import ast
import hashlib
import io
import json
import os
import re
import stat
import time
import tokenize
import tomllib
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Optional, Set, Tuple

import yaml

from aicomply.config import (
    AIComplyConfig, checked_path, error_summary, load_project_config, read_regular_file,
)
from aicomply.evidence.hasher import compute_scan_hash
from aicomply.infra.dependency_scanner import DependencyScanner
from aicomply.infra.docker_scanner import DockerScanner, load_compose_yaml
from aicomply.infra.input_reader import MAX_INPUT_BYTES
from aicomply.rules.loader import RuleCatalog, load_rules_from_dir
from aicomply.scanner.ast_parser import PythonASTScanner
from aicomply.scanner.regex_matcher import RegexScanner
from aicomply.schemas import (
    Finding, RiskTier, Rule, ScanReport, ScanSummary, Severity, SourceManifestEntry,
)

MAX_SOURCE_BYTES = MAX_INPUT_BYTES
MAX_SCAN_BYTES = 100 * 1024 * 1024
MAX_SCAN_ENTRIES = 10000
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
TEXT_EXTENSIONS = {".py", ".pyw", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env", ".toml", ".txt", ".lock"}
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
    if suffix_lower in TEXT_EXTENSIONS or name_lower == ".env" or name_lower.startswith(".env."):
        return True
    if name_lower in INFRA_FILENAMES or "dockerfile" in name_lower or "compose" in name_lower:
        return True
    return False


def _fingerprint(payload: object) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _mapping(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Expected a manifest mapping")
    return value


def _dependency_list(value: object) -> None:
    if not isinstance(value, list):
        raise ValueError("Expected a list of dependency strings")
    for dependency in value:
        if not isinstance(dependency, str):
            raise ValueError("Expected a dependency string")
        _validate_requirement(dependency)


REQUIREMENT_COMMENT = re.compile(r"(?:^|\s)#.*$")
URL_REQUIREMENT = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*\+)?(?:https?|ssh|git|file)://\S+")
HASH_OPTION = re.compile(r"--hash=(?:sha256|sha384|sha512):[0-9a-fA-F]+")
FILE_OPTIONS = {"-r", "--requirement", "-c", "--constraint"}
EDITABLE_OPTIONS = {"-e", "--editable"}
VALUE_OPTIONS = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host",
    "--no-binary", "--only-binary", "--use-feature",
}
FLAG_OPTIONS = {"--no-index", "--pre", "--prefer-binary", "--require-hashes"}


def _local_reference(reference: str, requirements_path: Path) -> Path:
    """pip file references must stay inside the scanned project and point to real entries."""
    candidate = Path(reference)
    if candidate.is_absolute() or ".." in candidate.parts or not reference.strip():
        raise ValueError(f"Requirements reference escapes the project: {reference}")
    resolved = requirements_path.parent / candidate
    try:
        mode = resolved.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"Requirements reference not found: {reference}") from exc
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise ValueError(f"Requirements reference is not a regular entry: {reference}")
    return resolved


def _split_option(line: str) -> Tuple[str, str]:
    head, _, rest = line.partition(" ")
    if head.startswith("--") and "=" in head:
        option, _, inline_value = head.partition("=")
        return option, f"{inline_value} {rest}".strip()
    return head, rest.strip()


def _validate_requirements_line(line: str, requirements_path: Path) -> None:
    """pip option lines (-r, -e, --index-url, --hash), direct URLs and PEP 508 requirements."""
    if line.startswith("-"):
        option, value = _split_option(line)
        if option in FILE_OPTIONS:
            if not stat.S_ISREG(_local_reference(value, requirements_path).lstat().st_mode):
                raise ValueError(f"Requirements reference is not a file: {value}")
        elif option in EDITABLE_OPTIONS:
            if not URL_REQUIREMENT.fullmatch(value):
                _local_reference(value.split("[", 1)[0], requirements_path)
        elif option in VALUE_OPTIONS:
            if not value or any(character.isspace() for character in value):
                raise ValueError(f"Malformed pip option: {option}")
        elif option in FLAG_OPTIONS:
            if value:
                raise ValueError(f"Unexpected value for pip option: {option}")
        else:
            raise ValueError(f"Unsupported pip option: {option}")
        return
    requirement, *hashes = line.split(" --hash=")
    for digest in hashes:
        if HASH_OPTION.fullmatch(f"--hash={digest.strip()}") is None:
            raise ValueError("Malformed --hash option")
    if URL_REQUIREMENT.fullmatch(requirement.strip()):
        return
    _validate_requirement(requirement)


def _validate_requirement(requirement: str) -> None:
    requirement, separator, marker = requirement.strip().partition(";")
    if separator:
        expression = ast.parse(marker.strip(), mode="eval")
        marker_names = {
            "python_version", "python_full_version", "os_name", "sys_platform",
            "platform_release", "platform_system", "platform_version", "platform_machine",
            "platform_python_implementation", "implementation_name", "implementation_version",
            "extra", "extras", "dependency_groups",
        }
        for node in ast.walk(expression):
            if not isinstance(node, (
                ast.Expression, ast.Compare, ast.BoolOp, ast.And, ast.Or, ast.Eq, ast.NotEq,
                ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Name, ast.Load, ast.Constant,
            )):
                raise ValueError("Unsupported requirement marker")
            if isinstance(node, ast.Name) and node.id not in marker_names:
                raise ValueError("Unknown requirement marker")
            if isinstance(node, ast.Constant) and not isinstance(node.value, str):
                raise ValueError("Expected a requirement marker string")
            if isinstance(node, ast.BoolOp) and any(
                not isinstance(value, (ast.Compare, ast.BoolOp)) for value in node.values
            ):
                raise ValueError("Expected requirement marker comparisons")
            if isinstance(node, ast.Compare) and (
                len(node.ops) != 1
                or not all(isinstance(value, (ast.Name, ast.Constant))
                           for value in [node.left, *node.comparators])
            ):
                raise ValueError("Unsupported requirement marker comparison")
        if not isinstance(expression.body, (ast.Compare, ast.BoolOp)):
            raise ValueError("Expected a requirement marker comparison")
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_, .-]+\])?", requirement)
    if match is None:
        raise ValueError("Unsupported or malformed requirement")
    specifiers = requirement[match.end():].strip()
    if not specifiers:
        return
    if specifiers.startswith("@"):
        if not specifiers[1:].strip() or len(specifiers[1:].split()) != 1:
            raise ValueError("Malformed direct requirement")
        return
    if specifiers.startswith("(") and specifiers.endswith(")"):
        specifiers = specifiers[1:-1]
    for specifier in specifiers.split(","):
        if not re.fullmatch(
            r"(?:===|~=|==|!=|<=|>=|<|>)\s*[A-Za-z0-9*_.+!-]+", specifier.strip()
        ):
            raise ValueError("Unsupported or malformed requirement version")


def _unique_json_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _decode_source(path: Path, data: bytes) -> str:
    """UTF-8 (with BOM) for every input; Python sources may also declare a PEP 263 encoding."""
    if path.suffix.lower() in PYTHON_EXTENSIONS:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding)
    return data.decode("utf-8-sig")


def _validate_source(path: Path, data: bytes) -> str:
    try:
        text = _decode_source(path, data)
        if "\x00" in text:
            raise ValueError("NUL bytes in source")
        name = path.name.lower()
        if path.suffix.lower() in PYTHON_EXTENSIONS:
            ast.parse(text, filename=path.name)
        elif name in {"pyproject.toml", "uv.lock", "pipfile"}:
            document = tomllib.loads(text)
            if name == "pyproject.toml":
                project = _mapping(document.get("project", {}))
                _dependency_list(project.get("dependencies", []))
                for deps in _mapping(project.get("optional-dependencies", {})).values():
                    _dependency_list(deps)
                tool = _mapping(document.get("tool", {}))
                poetry = _mapping(tool.get("poetry", {}))
                _mapping(poetry.get("dependencies", {}))
            elif name == "uv.lock":
                packages = document.get("package", [])
                if not isinstance(packages, list):
                    raise ValueError("Expected a package list")
                for package in packages:
                    package_name = _mapping(package).get("name")
                    if not isinstance(package_name, str) or not package_name.strip():
                        raise ValueError("Missing package name")
            else:
                for section in ("packages", "dev-packages"):
                    _mapping(document.get(section, {}))
        elif name == "pipfile.lock":
            document = _mapping(json.loads(text, object_pairs_hook=_unique_json_mapping))
            for section in ("default", "develop"):
                _mapping(document.get(section, {}))
        elif "compose" in name and path.suffix.lower() in {".yaml", ".yml"}:
            document = _mapping(load_compose_yaml(text))
            services = _mapping(document.get("services"))
            for service in services.values():
                service = _mapping(service)
                if "ports" in service and not isinstance(service["ports"], list):
                    raise ValueError("Expected a ports list")
                if "privileged" in service and not isinstance(service["privileged"], bool):
                    raise ValueError("Expected a privileged boolean")
        elif name.startswith("requirements") and name.endswith(".txt"):
            for line in text.splitlines():
                line = REQUIREMENT_COMMENT.sub("", line).rstrip("\\").strip()
                if line:
                    _validate_requirements_line(line, path)
        return text
    except (ValueError, SyntaxError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError(
            f"Unable to fully parse scan input: {path} ({error_summary(exc)})"
        ) from exc


class ScanEngine:
    """Motor central de escaneo determinista con soporte de configuración."""

    def __init__(self, catalog: RuleCatalog, target_articles: Optional[Set[str]] = None, config: Optional[AIComplyConfig] = None) -> None:
        self.catalog = catalog
        self._explicit_config = config
        self.config = config or AIComplyConfig()
        self.target_articles = target_articles
        self.rules: List[Rule] = self._prepare_active_rules()
        self.ast_scanner = PythonASTScanner(self.rules)
        self.regex_scanner = RegexScanner(self.rules)
        self.dependency_scanner = DependencyScanner(self.rules)
        self.docker_scanner = DockerScanner(self.rules)
    
    def _prepare_active_rules(self, catalog: Optional[RuleCatalog] = None) -> List[Rule]:
        """Aplica filtros de artículos CLI y exclusiones de reglas declaradas en la configuración."""
        catalog = catalog or self.catalog
        candidate_rules = (
            catalog.filter_by_articles(self.target_articles)
            if self.target_articles
            else catalog.rules
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
        target_path = checked_path(target_path)
        mode = target_path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"Scan target must be a regular file or directory: {target_path}")
        base_dir = target_path if target_path.is_dir() else target_path.parent
        self.config = (
            AIComplyConfig.model_validate(self._explicit_config.model_dump())
            if self._explicit_config is not None else load_project_config(base_dir)
        )
        catalog = self.catalog
        if self.config.custom_rules_dir:
            custom_path = base_dir / self.config.custom_rules_dir.replace("\\", "/")
            checked_path(custom_path).relative_to(base_dir)
            custom = load_rules_from_dir(custom_path)
            catalog = RuleCatalog([*catalog.rules, *custom.rules])
        if set(self.config.ignore_rules) - {rule.id for rule in catalog.rules}:
            raise ValueError("Configuration ignores an unknown rule ID")
        self.rules = self._prepare_active_rules(catalog)
        self.ast_scanner = PythonASTScanner(self.rules)
        self.regex_scanner = RegexScanner(self.rules)
        self.dependency_scanner = DependencyScanner(self.rules)
        self.docker_scanner = DockerScanner(self.rules)
        files_to_scan, exclusions = self._discover_files(target_path, base_dir)

        findings: List[Finding] = []
        total_lines = 0
        total_bytes = 0
        manifest: List[SourceManifestEntry] = []
        source_imports: dict[str, list[str]] = {}
        # Deduplicación cross-engine: (rule_id, file_path, start_line)
        seen_dedup_keys: Set[Tuple[str, str, int]] = set()

        with TemporaryDirectory(prefix="aicomply-scan-") as snapshot_dir:
            snapshot_root = Path(snapshot_dir)
            for original in sorted(files_to_scan):
                data = read_regular_file(original, MAX_SOURCE_BYTES)
                total_bytes += len(data)
                if total_bytes > MAX_SCAN_BYTES:
                    raise ValueError(f"Scan exceeds {MAX_SCAN_BYTES} bytes")
                text = _validate_source(original, data)
                total_lines += len(text.splitlines())
                relative = original.relative_to(base_dir)
                if original.suffix.lower() in PYTHON_EXTENSIONS:
                    imported: set[str] = set()
                    for node in ast.walk(ast.parse(text)):
                        if isinstance(node, ast.Import):
                            imported.update(alias.name.split(".")[0] for alias in node.names)
                        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                            imported.add(node.module.split(".")[0])
                    source_imports[relative.as_posix()] = sorted(imported)
                manifest.append(SourceManifestEntry(
                    path=relative.as_posix(), sha256=hashlib.sha256(data).hexdigest(),
                    size_bytes=len(data),
                ))
                file_path = snapshot_root / relative
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(text.encode("utf-8"))

                file_findings: List[Finding] = []
                if file_path.suffix.lower() in PYTHON_EXTENSIONS:
                    file_findings.extend(self.ast_scanner.scan_file(file_path, base_path=snapshot_root))
                file_findings.extend(self.dependency_scanner.scan_file(file_path, base_path=snapshot_root))
                file_findings.extend(self.docker_scanner.scan_file(file_path, base_path=snapshot_root))
                file_findings.extend(self.regex_scanner.scan_file(file_path, base_path=snapshot_root))
                file_path.unlink()
                for finding in file_findings:
                    dedup_key = (finding.rule_id, finding.location.file_path, finding.location.start_line)
                    if dedup_key not in seen_dedup_keys:
                        seen_dedup_keys.add(dedup_key)
                        findings.append(finding)

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
        effective_config = {
            **self.config.model_dump(mode="json"),
            "target_articles": sorted(self.target_articles or []),
            "ignored_directories": sorted(IGNORED_DIRS),
            "text_extensions": sorted(TEXT_EXTENSIONS),
            "infra_filenames": sorted(INFRA_FILENAMES),
            "max_source_bytes": MAX_SOURCE_BYTES,
            "max_scan_bytes": MAX_SCAN_BYTES,
            "max_scan_entries": MAX_SCAN_ENTRIES,
        }

        return ScanReport(
            scan_id=scan_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_path=str(target_path),
            summary=summary,
            findings=findings,
            source_imports=source_imports,
            source_manifest=manifest,
            source_manifest_hash=_fingerprint([entry.model_dump() for entry in manifest]),
            active_rule_ids=sorted(rule.id for rule in self.rules),
            rules_fingerprint=_fingerprint([
                rule.model_dump(mode="json") for rule in sorted(self.rules, key=lambda rule: rule.id)
            ]),
            config_fingerprint=_fingerprint(effective_config),
            effective_config=effective_config,
            exclusions=exclusions,
        )

    def _discover_files(self, target: Path, base: Path) -> Tuple[List[Path], dict[str, str]]:
        files: List[Path] = []
        exclusions: dict[str, str] = {}
        pending = [target]
        entries = 0
        while pending:
            path = pending.pop()
            entries += 1
            if entries > MAX_SCAN_ENTRIES:
                raise ValueError(f"Scan exceeds {MAX_SCAN_ENTRIES} entries")
            relative = path.relative_to(base).as_posix()
            if path != target and path.name in IGNORED_DIRS:
                exclusions[relative] = "ignored_directory"
                continue
            if self._is_path_excluded(relative) or self._is_path_excluded(relative + "/"):
                exclusions[relative] = "exclude_paths"
                continue
            checked_path(path).relative_to(base)
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                with os.scandir(path) as children:
                    for child in children:
                        pending.append(Path(child.path))
                        if len(pending) + entries > MAX_SCAN_ENTRIES:
                            raise ValueError(f"Scan exceeds {MAX_SCAN_ENTRIES} entries")
            elif not stat.S_ISREG(mode):
                raise ValueError(f"Not a regular scan input: {path}")
            elif is_scannable_file(path):
                files.append(path)
            elif path == target:
                raise ValueError(f"Unsupported scan target: {path}")
            else:
                exclusions[relative] = "unsupported_or_generated_file"
        return sorted(files), dict(sorted(exclusions.items()))

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