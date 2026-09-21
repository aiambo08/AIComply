import hashlib
import json
from pathlib import Path

import pytest
import yaml

from scripts.verify_pypi import compare_files


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("damage", [None, "missing", "digest", "yanked"])
def test_published_files_must_match_tested_artifacts(tmp_path: Path, damage: str | None) -> None:
    artifact = tmp_path / "aicomply_cli-2.0.0a0-py3-none-any.whl"
    artifact.write_bytes(b"tested-distribution")
    published = {
        "filename": artifact.name,
        "digests": {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
        "yanked": False,
    }
    if damage == "digest":
        published["digests"] = {"sha256": "0" * 64}
    if damage == "yanked":
        published["yanked"] = True
    payload = json.dumps({"urls": [] if damage == "missing" else [published]}).encode()
    if damage:
        with pytest.raises(LookupError if damage == "missing" else ValueError):
            compare_files([artifact], payload)
    else:
        compare_files([artifact], payload)


def test_pypi_verification_has_no_publishing_permission() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    assert "github.event_name == 'push'" in workflow["jobs"]["publish"]["if"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    verify = workflow["jobs"]["verify-pypi"]
    assert verify["needs"] == "publish"
    assert verify["permissions"] == {"contents": "read"}
    commands = "\n".join(step.get("run", "") for step in verify["steps"])
    assert "scripts/verify_pypi.py" in commands
    assert "scripts/smoke_distribution.py" in commands
    assert "--no-cache-dir" in commands
    assert "https://pypi.org/simple" in commands
    assert "|| true" not in commands
