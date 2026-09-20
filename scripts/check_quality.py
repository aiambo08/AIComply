"""Run with `uv sync --locked --extra dev && uv run --frozen python scripts/check_quality.py`."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
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


def verify_install(wheel: Path, directory: Path) -> None:
    dependencies = directory / "requirements.txt"
    environment = directory / "installed"
    run("uv", "export", "--locked", "--no-dev", "--no-emit-project",
        "--format", "requirements-txt", "--output-file", str(dependencies))
    run("uv", "venv", "--python", sys.executable, str(environment))
    python = str(environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    run("uv", "pip", "install", "--python", python, "--require-hashes", "-r", str(dependencies))
    run("uv", "pip", "install", "--python", python, "--no-deps", str(wheel))
    run("uv", "pip", "check", "--python", python)
    run(python, "-I", "-c", """
from importlib.metadata import distribution
from importlib.resources import files
from pathlib import Path
import sys
import aicomply
from aicomply.rules.loader import load_builtin_rules
assert Path(aicomply.__file__).resolve().is_relative_to(Path(sys.prefix))
assert load_builtin_rules().rules
assert files("aicomply").joinpath("ui/static/app.html").read_text(encoding="utf-8")
entry_points = {entry.name for entry in distribution("aicomply-cli").entry_points}
assert {"aicomply", "aicomply-cli"} <= entry_points
""", cwd=directory)
    for entry in ("aicomply", "aicomply-cli"):
        executable = environment / ("Scripts" if os.name == "nt" else "bin") / (
            f"{entry}.exe" if os.name == "nt" else entry
        )
        run(str(executable), "--help", cwd=directory)
    fixture = directory / "fixture"
    fixture.mkdir()
    (fixture / "clean.py").write_text("answer = 42\n", encoding="utf-8")
    report = directory / "smoke.sarif"
    run(python, "-I", "-m", "aicomply.cli", "scan", "--format", "sarif",
        "--output", str(report), "--", str(fixture), cwd=directory)
    payload = json.loads(report.read_text(encoding="utf-8"))
    if payload["version"] != "2.1.0" or payload["runs"][0]["results"]:
        raise ValueError("Installed artifact smoke scan failed")


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
        verify_archives(ROOT, wheel, sdist)
        verify_install(wheel, directory)
        args.dist_dir.mkdir(parents=True, exist_ok=True)
        for artifact in (wheel, sdist):
            destination = args.dist_dir / artifact.name
            shutil.copyfile(artifact, destination)
            print(f"{hashlib.sha256(destination.read_bytes()).hexdigest()}  {destination.name}")
    print("Quality checks and installed-artifact smoke test passed.")


if __name__ == "__main__":
    main()
