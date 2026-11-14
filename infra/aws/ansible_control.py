"""Control-node orchestration: SSH install, collect, validate and save the run."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

from collector.models import DeviceSnapshot
from collector.store import SnapshotStore
from infra.aws.build import BUILD_PACKAGES
from infra.aws.catalog import ROOT, load_manifest
from infra.aws.network_policy import forwarding_delta


def inventory(manifest: dict, private_key: str, known_hosts: str, run_dir: str) -> dict:
    return {"all": {"children": {"netvuln_targets": {
        "hosts": {row["device_id"]: {"ansible_host": row["ip"], "netvuln_target": row} for row in manifest["targets"]},
        "vars": {"ansible_user": "netvulnadmin", "ansible_ssh_private_key_file": private_key,
                 "ansible_python_interpreter": "/usr/bin/python3",
                 "ansible_ssh_common_args": f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts} -o IdentitiesOnly=yes",
                 "netvuln_build_packages": list(BUILD_PACKAGES), "netvuln_run_dir": run_dir},
    }}}}


def run_fleet(config: dict, directory: Path) -> dict:
    manifest = load_manifest()
    directory.mkdir(parents=True, exist_ok=False)
    inventory_path = directory / "inventory.json"
    inventory_path.write_text(json.dumps(inventory(manifest, "/etc/netvuln/pki/ansible_key", "/etc/netvuln/pki/known_hosts", str(directory)), indent=2) + "\n")
    command = ["/opt/netvuln/venv/bin/ansible-playbook", "-i", str(inventory_path), str(ROOT.parent / "ansible/site.yml")]
    env = {**os.environ, "ANSIBLE_HOME": str(directory / ".ansible"), "ANSIBLE_CONFIG": str(ROOT.parent / "ansible/ansible.cfg"), "ANSIBLE_LOG_PATH": str(directory / "ansible.log")}
    try:
        # Leave time for audit upload before the outer SSM command's four-hour limit.
        result = subprocess.run(command, env=env, timeout=12600)
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124
    registry = {row["device_id"]: row for row in manifest["targets"]}
    store = SnapshotStore(directory / "snapshots", registry)
    probes, routing, errors = [], [], []
    for target in manifest["targets"]:
        identity = target["device_id"]
        path = directory / f"{identity}.facts.json"
        if path.exists():
            try:
                snapshot = DeviceSnapshot.model_validate_json(path.read_text())
                if snapshot.device_id != identity:
                    raise ValueError("Ansible result identity differs from registered host")
                store.save(snapshot)
            except ValueError as exc:
                errors.append({"device_id": identity, "error": str(exc)})
        probe_path = directory / f"{identity}.probe.json"
        probes.append(json.loads(probe_path.read_text()) if probe_path.exists() else {"device_id": identity, "status": "missing"})
        if target["product_id"] == "frr":
            route_path = directory / f"{identity}.routing.json"
            before_path = directory / f"{identity}.routing-before.json"
            before = json.loads(before_path.read_text()) if before_path.exists() else {}
            after = json.loads(route_path.read_text()) if route_path.exists() else {}
            routing.append(forwarding_delta(identity, before, after))
    frozen = store.freeze(max_age_seconds=600)
    report = {"schema_version": 1, "transport": "ansible_ssh_agentless", "ansible_exit_code": exit_code,
              "scope": "installation_facts_and_functional_readiness_not_cve_evaluation", "collector_snapshot": frozen,
              "probes": probes, "routing": routing, "errors": errors,
              "complete": exit_code == 0 and not errors and frozen["complete"] and all(row.get("status") == "passed" for row in probes + routing)}
    (directory / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    import boto3
    s3 = boto3.client("s3", region_name=config["region"])
    for path in directory.rglob("*"):
        if path.is_file():
            key = f"{config['artifacts_prefix']}/runs/ansible/{directory.name}/{path.relative_to(directory).as_posix()}"
            s3.upload_file(str(path), config["artifacts_bucket"], key, ExtraArgs={"ServerSideEncryption": "AES256"})
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/netvuln/bootstrap.json"))
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    report = run_fleet(config, Path("/var/lib/netvuln/ansible") / stamp)
    print(json.dumps({"complete": report["complete"], "transport": report["transport"], "run_id": stamp}))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
