"""Assemble a deterministic, credential-free deployment bundle; no AWS calls."""

from __future__ import annotations

import argparse
import gzip
import io
import json
from pathlib import Path
import shutil
import tarfile

from infra.aws.catalog import ROOT, load_lock, load_manifest
from infra.aws.render import render_all
from infra.aws.sources import archive_name, sha256, validate_archive


def deployment_files(repo: Path) -> list[tuple[Path, str]]:
    files = []
    data_files = {"infra/aws/experiment.json", "infra/aws/sources.lock.json", "infra/aws/control-requirements.txt"}
    for package in ("infra", "collector"):
        for source in sorted((repo / package).rglob("*")):
            relative = source.relative_to(repo)
            if not source.is_file() or any(part in {"__pycache__", "audit", "validation"} for part in relative.parts):
                continue
            name = relative.as_posix()
            if (source.suffix == ".py" or name in data_files
                    or relative.parent == Path("infra/aws/templates") and source.suffix == ".json"
                    or relative.parent == Path("infra/ansible") and source.suffix in {".yml", ".yaml", ".cfg", ".j2"}):
                files.append((source, name))
    return files


def build_bundle(output: Path, repo: Path | None = None) -> dict:
    repo = repo or ROOT.parents[1]
    manifest = load_manifest(repo / "infra/aws/experiment.json")
    lock = load_lock(manifest, repo / "infra/aws/sources.lock.json")
    render_all(repo / "infra/aws/templates", manifest)
    # Explicit allowlist: .env, AWS credentials, artifacts, logs and gold labels cannot enter this bundle.
    files = deployment_files(repo)
    for source in manifest["sources"]:
        path = repo / "artifacts/aws/sources" / archive_name(source["source_id"])
        pin = lock["sources"][source["source_id"]]
        if sha256(path) != pin["sha256"] or path.stat().st_size != pin["size_bytes"]:
            raise ValueError(f"Source archive differs from lock: {source['source_id']}")
        validate_archive(path, source["archive_root"])
        files.append((path, path.relative_to(repo).as_posix()))
    output.mkdir(parents=True, exist_ok=True)
    bundle = output / "bundle.tar.gz"
    with bundle.open("wb") as raw, gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w|") as archive:
        for source, name in sorted(files, key=lambda row: row[1]):
            data = source.read_bytes()
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime, item.uid, item.gid = len(data), 0o644, 0, 0, 0
            archive.addfile(item, io.BytesIO(data))
    destination = output / "templates"
    destination.mkdir(exist_ok=True)
    for path in (repo / "infra/aws/templates").glob("*.template.json"):
        shutil.copyfile(path, destination / path.name)
    record = {"schema_version": 1, "experiment_id": manifest["experiment_id"], "expected_targets": 16,
              "bundle_sha256": sha256(bundle), "bundle_size_bytes": bundle.stat().st_size,
              "files": {name: sha256(path) for path, name in sorted(files, key=lambda row: row[1])},
              "templates": {path.name: sha256(path) for path in sorted(destination.glob("*.template.json"))},
              "scope": "sixteen_native_versions_ansible_facts_service_and_network_isolation_readiness",
              "pending": ["AWS deployment validation", "Greenbone scanner stack", "reviewed CVE gold", "RAG inventory integration", "complete model benchmark runner"]}
    (output / "package.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/aws/package"))
    args = parser.parse_args()
    record = build_bundle(args.output)
    print(json.dumps({"directory": str(args.output), "expected_targets": record["expected_targets"], "bundle_sha256": record["bundle_sha256"], "size_bytes": record["bundle_size_bytes"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
