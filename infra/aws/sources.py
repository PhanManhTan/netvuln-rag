"""Fetch official release archives and freeze their observed SHA-256 digests.

An observed digest pins subsequent downloads; it is not a claim that a vendor
signature was verified. An existing lock is never silently refreshed.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
from urllib.request import Request, urlopen

from infra.aws.catalog import LOCK, MANIFEST, load_lock, load_manifest


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def archive_name(source_id: str) -> str:
    return source_id + ".tar"


def validate_archive(path: Path, root: str) -> None:
    with tarfile.open(path) as archive:
        names = [member.name.removeprefix("./").split("/")[0] for member in archive.getmembers()]
    if not names or set(names) != {root}:
        raise ValueError(f"Unexpected source root for {path.name}: {set(names)}")


def fetch_source(source: dict, directory: Path, pinned: dict | None) -> dict:
    destination = directory / archive_name(source["source_id"])
    if destination.exists():
        if pinned and (sha256(destination) != pinned["sha256"] or destination.stat().st_size != pinned["size_bytes"]):
            raise ValueError(f"Cached source failed integrity verification: {destination.name}")
        validate_archive(destination, source["archive_root"])
        if pinned:
            return pinned
        resolved = source["url"]
    else:
        request = Request(source["url"], headers={"User-Agent": "netvuln-reproducible-build/1"})
        descriptor, temporary = tempfile.mkstemp(dir=directory, prefix="download-")
        try:
            with os.fdopen(descriptor, "wb") as output, urlopen(request, timeout=120) as response:
                resolved = response.url
                for block in iter(lambda: response.read(1024 * 1024), b""):
                    output.write(block)
            candidate = Path(temporary)
            validate_archive(candidate, source["archive_root"])
            if pinned and (sha256(candidate) != pinned["sha256"] or candidate.stat().st_size != pinned["size_bytes"]):
                raise ValueError(f"Downloaded source differs from lock: {source['source_id']}")
            candidate.replace(destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return pinned or {
        "url": source["url"], "resolved_url": resolved,
        "sha256": sha256(destination), "size_bytes": destination.stat().st_size,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "verification": "sha256_observed_over_https_not_vendor_signature",
    }


def fetch_all(manifest: dict, directory: Path, lock_path: Path) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    existing = load_lock(manifest, lock_path) if lock_path.exists() else None
    def fetch(source: dict) -> tuple[str, dict]:
        identity = source["source_id"]
        result = fetch_source(source, directory, existing["sources"][identity] if existing else None)
        print(f"Verified archive: {identity} ({result['size_bytes']} bytes)", flush=True)
        return identity, result
    with ThreadPoolExecutor(max_workers=4) as executor:
        entries = dict(executor.map(fetch, manifest["sources"]))
    result = existing or {"schema_version": 1, "sources": entries}
    if not existing:
        # Do not overwrite another process's newly created lock.
        with lock_path.open("x", encoding="utf-8") as output:
            json.dump(result, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write("\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--cache", type=Path, default=Path("artifacts/aws/sources"))
    args = parser.parse_args()
    fetch_all(load_manifest(args.manifest), args.cache, args.lock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
