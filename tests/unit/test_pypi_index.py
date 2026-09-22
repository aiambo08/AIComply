import hashlib
import io
import json
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
import zipfile

import pytest

from scripts.verify_pypi import verify


@pytest.fixture
def distributions(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    wheel = tmp_path / "aicomply_cli-2.0.0a0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "aicomply_cli-2.0.0a0.dist-info/METADATA",
            "Name: aicomply-cli\nVersion: 2.0.0a0\n",
        )
    sdist = tmp_path / "aicomply_cli-2.0.0a0.tar.gz"
    sdist.write_bytes(b"verified source distribution")
    hashes = {
        artifact.name: hashlib.sha256(artifact.read_bytes()).hexdigest()
        for artifact in (wheel, sdist)
    }
    release = json.dumps({"urls": [
        {"filename": name, "digests": {"sha256": digest}, "yanked": False}
        for name, digest in hashes.items()
    ]}).encode()
    index = json.dumps({"files": [
        {"filename": name, "hashes": {"sha256": digest}, "yanked": False}
        for name, digest in hashes.items()
    ]}).encode()
    return tmp_path, release, index


@pytest.mark.parametrize("visible_files", [0, 1])
def test_waits_for_both_artifacts_in_simple_index(
    distributions: tuple[Path, bytes, bytes], visible_files: int,
) -> None:
    directory, release, index = distributions
    stale_index = json.loads(index)
    stale_index["files"] = stale_index["files"][:visible_files]
    responses = [
        io.BytesIO(release), io.BytesIO(json.dumps(stale_index).encode()),
        io.BytesIO(release), io.BytesIO(index),
    ]
    with patch("scripts.verify_pypi.urlopen", side_effect=responses) as fetch, \
            patch("scripts.verify_pypi.time.sleep") as sleep:
        verify(directory)
    assert fetch.call_count == 4
    sleep.assert_called_once_with(10)
    request = fetch.call_args_list[1].args[0]
    assert request.full_url == "https://pypi.org/simple/aicomply-cli/"
    assert request.get_header("Accept") == "application/vnd.pypi.simple.v1+json"


@pytest.mark.parametrize("damage", ["digest", "yanked", "reason", "empty_reason"])
def test_rejects_inconsistent_or_yanked_simple_index(
    distributions: tuple[Path, bytes, bytes], damage: str,
) -> None:
    directory, release, index = distributions
    broken = json.loads(index)
    if damage == "digest":
        broken["files"][0]["hashes"]["sha256"] = "0" * 64
    else:
        broken["files"][0]["yanked"] = {
            "yanked": True, "reason": "withdrawn", "empty_reason": "",
        }[damage]
    with patch("scripts.verify_pypi.urlopen", side_effect=[
        io.BytesIO(release), io.BytesIO(json.dumps(broken).encode()),
    ]), patch("scripts.verify_pypi.time.sleep") as sleep:
        with pytest.raises(ValueError, match="digest differs|yanked"):
            verify(directory)
    sleep.assert_not_called()


def test_simple_index_propagation_has_a_retry_limit(
    distributions: tuple[Path, bytes, bytes],
) -> None:
    directory, release, _ = distributions
    responses = [
        response
        for _ in range(6)
        for response in (io.BytesIO(release), io.BytesIO(b'{"files": []}'))
    ]
    with patch("scripts.verify_pypi.urlopen", side_effect=responses) as fetch, \
            patch("scripts.verify_pypi.time.sleep") as sleep:
        with pytest.raises(RuntimeError, match="Could not verify published artifacts"):
            verify(directory)
    assert fetch.call_count == 12
    assert sleep.call_count == 5


@pytest.mark.parametrize("status", [404, 429, 503])
def test_retries_transient_index_http_errors(
    distributions: tuple[Path, bytes, bytes], status: int,
) -> None:
    directory, release, index = distributions
    with patch("scripts.verify_pypi.urlopen", side_effect=[
        io.BytesIO(release),
        HTTPError("https://pypi.org/simple/aicomply-cli/", status, "temporary", None, None),
        io.BytesIO(release), io.BytesIO(index),
    ]), patch("scripts.verify_pypi.time.sleep") as sleep:
        verify(directory)
    sleep.assert_called_once_with(10)


def test_does_not_retry_index_permission_errors(
    distributions: tuple[Path, bytes, bytes],
) -> None:
    directory, release, _ = distributions
    with patch("scripts.verify_pypi.urlopen", side_effect=[
        io.BytesIO(release),
        HTTPError("https://pypi.org/simple/aicomply-cli/", 403, "forbidden", None, None),
    ]), patch("scripts.verify_pypi.time.sleep") as sleep:
        with pytest.raises(HTTPError):
            verify(directory)
    sleep.assert_not_called()
