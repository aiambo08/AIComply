"""Verify that PyPI serves the exact wheel and sdist approved by quality CI."""

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile


def compare_files(artifacts: list[Path], payload: bytes, *, simple: bool = False) -> None:
    collection = "files" if simple else "urls"
    hash_key = "hashes" if simple else "digests"
    releases = {item["filename"]: item for item in json.loads(payload)[collection]}
    for artifact in artifacts:
        if artifact.name not in releases:
            raise LookupError(f"Not yet visible on PyPI: {artifact.name}")
        published = releases[artifact.name]
        if published.get("yanked", False) is not False:
            raise ValueError(f"Release is yanked: {artifact.name}")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if published[hash_key]["sha256"] != digest:
            raise ValueError(f"Published digest differs: {artifact.name}")


def verify(dist_dir: Path) -> None:
    wheel, = dist_dir.glob("*.whl")
    sdist, = dist_dir.glob("*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        metadata_name, = (name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
    if metadata["Name"] != "aicomply-cli" or not metadata["Version"]:
        raise ValueError("Expected an aicomply-cli distribution with a version")
    url = f"https://pypi.org/pypi/aicomply-cli/{quote(metadata['Version'], safe='')}/json"
    sources = [
        (Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"}), False),
        (Request("https://pypi.org/simple/aicomply-cli/", headers={
            "Accept": "application/vnd.pypi.simple.v1+json", "Cache-Control": "no-cache",
        }), True),
    ]
    for attempt in range(6):
        try:
            for request, simple in sources:
                with urlopen(request, timeout=15) as response:
                    payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise ValueError("Oversize PyPI metadata")
                compare_files([wheel, sdist], payload, simple=simple)
            print(
                f"PyPI release metadata and Simple index match both verified artifacts "
                f"for {metadata['Version']}."
            )
            return
        except HTTPError as exc:
            if exc.code not in {404, 429, 500, 502, 503, 504}:
                raise
            failure = str(exc)
        except (URLError, TimeoutError, LookupError) as exc:
            failure = str(exc)
        if attempt == 5:
            raise RuntimeError(f"Could not verify published artifacts: {failure}")
        print(f"Waiting for PyPI metadata ({attempt + 1}/6): {failure}", flush=True)
        time.sleep(10)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, required=True)
    args = parser.parse_args()
    verify(args.dist_dir)


if __name__ == "__main__":
    main()
