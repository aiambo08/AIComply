"""Run with `uv sync --locked --extra dev && uv run --frozen python scripts/check_quality.py`."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, cwd: Path = ROOT) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def resource_files(root: Path) -> list[Path]:
    package = root / "src" / "aicomply"
    rules = sorted(path for path in (package / "rules").rglob("*") if path.suffix in (".yaml", ".yml"))
    static = sorted(path for path in (package / "ui" / "static").rglob("*") if path.is_file())
    if not rules or not static:
        raise ValueError("Rules and UI resources must both be present")
    return rules + static


def verify_archives(root: Path, wheel: Path, sdist: Path) -> None:
    with zipfile.ZipFile(wheel) as wheel_archive, tarfile.open(sdist) as source_archive:
        prefix = sdist.name.removesuffix(".tar.gz")
        for path in resource_files(root):
            expected = path.read_bytes()
            wheel_name = path.relative_to(root / "src").as_posix()
            source_name = f"{prefix}/{path.relative_to(root).as_posix()}"
            source_file = source_archive.extractfile(source_name)
            if source_file is None or source_file.read() != expected:
                raise ValueError(f"Missing or altered sdist resource: {source_name}")
            if wheel_archive.read(wheel_name) != expected:
                raise ValueError(f"Missing or altered wheel resource: {wheel_name}")


def verify_install(artifact: Path, directory: Path, *, locked: bool = True) -> None:
    directory.mkdir()
    dependencies = directory / "requirements.txt"
    environment = directory / "installed"
    run("uv", "venv", "--seed", "--python", sys.executable, str(environment))
    python = str(environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    if locked:
        run("uv", "export", "--locked", "--no-dev", "--no-emit-project",
            "--format", "requirements-txt", "--output-file", str(dependencies))
        run("uv", "pip", "install", "--python", python, "--require-hashes", "-r", str(dependencies))
        run(python, "-I", "-m", "pip", "install", "--no-deps", str(artifact), cwd=directory)
    else:
        run(python, "-I", "-m", "pip", "install", "--no-cache-dir",
            "--index-url", "https://pypi.org/simple", str(artifact), cwd=directory)
    run(python, "-I", "-m", "pip", "check", cwd=directory)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    run(python, "-I", str(ROOT / "scripts" / "smoke_distribution.py"),
        "--expected-version", version, cwd=directory)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    run("uv", "lock", "--check")
    run(sys.executable, "-m", "ruff", "check", ".")
    run(sys.executable, "-m", "mypy")
    run(sys.executable, "-m", "pytest", "-q")
    with tempfile.TemporaryDirectory(prefix="aicomply-quality-", dir=ROOT.parent) as scratch:
        directory = Path(scratch)
        artifacts = directory / "dist"
        run(sys.executable, "-m", "build", "--no-isolation", "--outdir", str(artifacts))
        wheel, = artifacts.glob("*.whl")
        sdist, = artifacts.glob("*.tar.gz")
        run(sys.executable, "-m", "twine", "check", "--strict", str(wheel), str(sdist))
        verify_archives(ROOT, wheel, sdist)
        verify_install(wheel, directory / "locked-wheel")
        verify_install(sdist, directory / "resolved-sdist", locked=False)
        args.dist_dir.mkdir(parents=True, exist_ok=True)
        for artifact in (wheel, sdist):
            destination = args.dist_dir / artifact.name
            shutil.copyfile(artifact, destination)
            print(f"{hashlib.sha256(destination.read_bytes()).hexdigest()}  {destination.name}")
    print("Quality checks and installed-artifact smoke test passed.")


if __name__ == "__main__":
    main()
