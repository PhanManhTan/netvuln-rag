"""Build pinned releases in isolated containers and retain auditable logs/results."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from infra.aws.catalog import load_lock, load_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices", nargs="+", help="Defaults to the entire sixteen-target matrix")
    parser.add_argument("--image", default="netvuln-build:ubuntu22")
    parser.add_argument("--workers", type=int, choices=(1, 2), default=2)
    parser.add_argument("--output", type=Path, default=Path("artifacts/aws/build-validation"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manifest = load_manifest()
    load_lock(manifest)
    requested = set(args.devices or [row["device_id"] for row in manifest["targets"]])
    if requested - {row["device_id"] for row in manifest["targets"]}:
        parser.error("Unknown target identity")
    output = args.output.resolve() / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    image_id = subprocess.check_output(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"], text=True).strip()

    def build(identity: str) -> dict:
        products = output / f"{identity}.products"
        products.mkdir()
        command = ["docker", "run", "--rm", "--network", "none", "--mount", f"type=bind,src={root},dst=/workspace,readonly",
                   "--mount", f"type=bind,src={products},dst=/opt/netvuln/products",
                   args.image, "python3", "-m", "infra.aws.build", "--device", identity,
                   "--cache", "/workspace/artifacts/aws/sources"]
        log_path = output / f"{identity}.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=7200)
        rows = [line.removeprefix("NETVULN_BUILD_RESULT=") for line in log_path.read_text().splitlines() if line.startswith("NETVULN_BUILD_RESULT=")]
        result = {"device_id": identity, "status": "passed" if process.returncode == 0 and len(rows) == 1 else "failed",
                  "exit_code": process.returncode, "image_id": image_id, "log": log_path.name,
                  "completed_at": datetime.now(timezone.utc).isoformat()}
        if len(rows) == 1:
            result["build"] = json.loads(rows[0])
        (output / f"{identity}.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"{identity}: {result['status']} ({log_path})", flush=True)
        return result

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(build, identity) for identity in sorted(requested)]
        for future in as_completed(futures):
            results.append(future.result())
    summary = {"schema_version": 1, "scope": "source_compilation_and_binary_version_only",
               "expected_targets": 16, "attempted_targets": len(results),
               "full_matrix_passed": len(results) == 16 and all(row["status"] == "passed" for row in results),
               "results": sorted(results, key=lambda row: row["device_id"])}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if all(row["status"] == "passed" for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
