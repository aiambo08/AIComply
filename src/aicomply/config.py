"""
AIComply - Project Configuration Loader (.aicomply.yaml)
Permite definir exclusiones de reglas, rutas ignoradas y umbrales de fallo en CI/CD.
"""
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from yaml.nodes import MappingNode
from yaml.tokens import AliasToken

MAX_POLICY_BYTES = 1024 * 1024


def error_summary(exc: BaseException, limit: int = 200) -> str:
    """One-line, bounded root cause suitable for CLI messages."""
    if isinstance(exc, ValidationError):
        text = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        )
    elif isinstance(exc, SyntaxError):
        text = f"{exc.msg} at line {exc.lineno}" if exc.lineno else str(exc.msg)
    elif isinstance(exc, UnicodeDecodeError):
        text = f"invalid {exc.encoding} at byte {exc.start}"
    elif isinstance(exc, RecursionError):
        text = "nesting too deep"
    else:
        text = " ".join(str(exc).split())
    text = text or type(exc).__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."


def checked_path(path: Path) -> Path:
    """Return an absolute path without traversing symbolic links."""
    path = path.absolute()
    for component in [*reversed(path.parents), path]:
        if stat.S_ISLNK(component.lstat().st_mode):
            raise ValueError(f"Symbolic links are not supported: {component}")
    return Path(os.path.abspath(path))


def read_regular_file(path: Path, max_bytes: int) -> bytes:
    """Read bounded regular input; POSIX opens each component with O_NOFOLLOW."""
    path = checked_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"Not a regular file: {path}")
    if before.st_size > max_bytes:
        raise ValueError(f"File exceeds {max_bytes} bytes: {path}")
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd
                )
                os.close(parent_fd)
                parent_fd = next_fd
            fd = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd
            )
        finally:
            os.close(parent_fd)
        input_stream = os.fdopen(fd, "rb")
    else:
        input_stream = path.open("rb")
    with input_stream as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError(f"File changed while opening: {path}")
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    if len(data) > max_bytes:
        raise ValueError(f"File exceeds {max_bytes} bytes: {path}")
    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ) or len(data) != after.st_size:
        raise ValueError(f"File changed while reading: {path}")
    return data


class StrictSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict:
        keys = set()
        for key_node, _ in node.value:
            key = (
                "<<" if key_node.tag == "tag:yaml.org,2002:merge"
                else self.construct_object(key_node, deep=deep)
            )
            if not isinstance(key, str) or key in keys:
                raise ValueError("YAML keys must be unique strings")
            keys.add(key)
        self.flatten_mapping(node)
        return super().construct_mapping(node, deep=deep)


def load_policy_yaml(text: str) -> object:
    """Policy documents cannot use aliases or duplicate mapping keys."""
    if any(isinstance(token, AliasToken) for token in yaml.scan(text)):
        raise ValueError("YAML aliases are not supported in policy files")
    return yaml.load(text, Loader=StrictSafeLoader)


class AIComplyConfig(BaseModel):
    """Esquema de configuración de AIComply por repositorio"""
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    exclude_paths: List[str] = Field(
        default_factory=lambda: ["tests/**", "fixtures/**", "docs/**"],
        description="Rutas o patrones glob a ignorar durante el escaneo."
    )
    ignore_rules: List[str] = Field(
        default_factory=list,
        description="IDs de reglas desactivadas globalmente (ej. ['EUAIA-ART15-001'])."
    )
    enforce_risk_tier: Optional[Literal["prohibited", "high_risk", "limited_risk", "minimal_risk"]] = Field(
        default=None,
        description="Nivel de riesgo máximo tolerado antes de fallar (ej. 'high_risk')."
    )
    custom_rules_dir: Optional[str] = Field(
        default=None,
        description="Ruta relativa a reglas personalizadas adicionales"
    )

    @field_validator("exclude_paths")
    @classmethod
    def validate_exclusions(cls, paths: List[str]) -> List[str]:
        for path in paths:
            cls.validate_relative_path(path)
        return paths

    @field_validator("custom_rules_dir")
    @classmethod
    def validate_custom_dir(cls, path: Optional[str]) -> Optional[str]:
        if path is not None:
            cls.validate_relative_path(path)
        return path

    @staticmethod
    def validate_relative_path(path: str) -> None:
        normalized = path.replace("\\", "/")
        if (
            not normalized.strip()
            or "\x00" in normalized
            or Path(normalized).is_absolute()
            or PureWindowsPath(path).drive
            or ".." in normalized.split("/")
        ):
            raise ValueError("Expected a nonempty relative path within the project")

    @field_validator("ignore_rules")
    @classmethod
    def validate_ignored_rules(cls, rules: List[str]) -> List[str]:
        normalized = [rule.strip().upper() for rule in rules]
        if any(not re.fullmatch(r"[A-Z0-9]{3,8}-(ART\d+|GEN)-\d{3}", rule) for rule in normalized):
            raise ValueError("Invalid ignored rule ID")
        return normalized


def load_project_config(target_dir: Path) -> AIComplyConfig:
    """Busca y carga un archivo .aicomply.yaml o aicomply.yml en el directorio objetivo."""
    candidate_files = [
        target_dir / ".aicomply.yaml",
        target_dir / ".aicomply.yml",
        target_dir / "aicomply.yaml",
    ]

    existing = []
    for config_path in candidate_files:
        try:
            config_path.lstat()
        except FileNotFoundError:
            continue
        existing.append(config_path)
    if len(existing) > 1:
        raise ValueError("Multiple project configuration files found")
    if not existing:
        return AIComplyConfig()
    config_path = existing[0]
    try:
        text = read_regular_file(config_path, MAX_POLICY_BYTES).decode("utf-8-sig")
        return AIComplyConfig.model_validate(load_policy_yaml(text))
    except (ValueError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError(
            f"Invalid project configuration: {config_path} ({error_summary(exc)})"
        ) from exc