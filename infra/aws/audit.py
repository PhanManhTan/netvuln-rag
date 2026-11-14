"""Export build evidence without confusing compilation with live AWS validation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from infra.aws.catalog import ROOT, load_lock, load_manifest
from infra.aws.sources import sha256


def summarize_builds(directory: Path) -> dict:
    manifest, lock = load_manifest(), load_lock(load_manifest())
    newest = {}
    for path in directory.rglob("*.json"):
        if path.name == "summary.json":
            continue
        value = json.loads(path.read_text())
        if "status" not in value or "completed_at" not in value or "device_id" not in value:
            continue
        identity = value["device_id"]
        if identity not in newest or value["completed_at"] > newest[identity]["completed_at"]:
            newest[identity] = {**value, "record": path.relative_to(directory).as_posix()}
    results = []
    for target in manifest["targets"]:
        row = newest.get(target["device_id"], {"device_id": target["device_id"], "status": "pending"})
        row = dict(row)
        expected_hash = lock["sources"][f"{target['product_id']}-{target['version']}"]["sha256"]
        if row["status"] == "passed" and (row.get("build", {}).get("version") != target["version"] or row["build"].get("source_sha256") != expected_hash or not row["build"].get("binary_sha256")):
            row.update(status="failed", audit_error="Build evidence differs from the locked target")
        results.append(row)
    return {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
            "scope": "source_compilation_and_binary_version_only", "manifest_sha256": sha256(ROOT / "experiment.json"),
            "sources_lock_sha256": sha256(ROOT / "sources.lock.json"), "expected_targets": 16,
            "passed_targets": sum(row["status"] == "passed" for row in results),
            "full_matrix_passed": all(row["status"] == "passed" for row in results),
            "aws_deployment": "pending", "cve_benchmark": "pending", "results": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-results", type=Path, default=Path("artifacts/aws/build-validation"))
    parser.add_argument("--output", type=Path, default=ROOT / "audit/build-results.json")
    args = parser.parse_args()
    result = summarize_builds(args.build_results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"Build/version checks: {result['passed_targets']}/16; AWS deployment and CVE evaluation pending")
    return 0 if result["full_matrix_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
