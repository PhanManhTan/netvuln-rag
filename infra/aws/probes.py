"""Functional checks run automatically by CloudFormation through Systems Manager."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time
from urllib.request import Request, urlopen
import ssl

from infra.aws.build import probe_binary
from infra.aws.catalog import load_manifest, target_by_id
from infra.aws.network_policy import probe_isolation


def command(arguments: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Probe command failed ({Path(arguments[0]).name}): {(result.stdout + result.stderr)[-1500:]}")
    return result.stdout.strip()


def local_probe(config: dict, manifest: dict) -> dict:
    target = target_by_id(manifest, config["device_id"])
    prefix = Path("/opt/netvuln/products") / target["product_id"] / target["version"]
    result = {"device_id": target["device_id"], "checks": {}, "status": "failed"}
    try:
        result["binary"] = probe_binary(target["product_id"], target["version"], prefix)
        command(["systemctl", "is-active", "--quiet", "netvuln-target.service"])
        result["checks"]["service_active"] = True
        product = target["product_id"]
        if product in {"nginx", "apache", "haproxy"}:
            expected = target["device_id"] if product == "apache" else "APACHE-" + target["device_id"][-1]
            body = command(["curl", "--fail", "--silent", "--show-error", "--max-time", "10", "http://127.0.0.1/index.html"])
            if body != expected:
                raise ValueError("HTTP request did not reach the expected application backend")
            result["checks"]["http_backend"] = expected
        elif product in {"bind", "dnsmasq"}:
            expected = target_by_id(manifest, "APACHE-" + target["device_id"][-1])["ip"]
            answer = command(["dig", "+short", "+time=3", "+tries=1", "@127.0.0.1", "web.netvuln.test", "A"])
            if answer != expected:
                raise ValueError("DNS response did not match the configured zone")
            result["checks"]["dns_answer"] = answer
        elif product == "openssh":
            peer = target_by_id(manifest, target["peer"])
            common = [str(prefix / "bin/ssh"), "-i", "/etc/netvuln/pki/probe_key", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UserKnownHostsFile=/etc/netvuln/known_hosts"]
            response = command([*common, f"netvulnprobe@{peer['ip']}", "printf netvuln-ssh-ok"])
            if response != "netvuln-ssh-ok":
                raise ValueError("SSH client did not reach the registered server")
            # Exercise the tested Portable sshd as well as the client binary.
            response = command([*common, "-p", "2222", f"netvulnprobe@{target['ip']}", "printf netvuln-ssh-ok"])
            if response != "netvuln-ssh-ok":
                raise ValueError("Portable sshd functional check failed")
            frontend = target_by_id(manifest, "HAPROXY-" + target["device_id"][-1])
            backend = command(["curl", "--fail", "--silent", "--show-error", "--max-time", "10", f"http://{frontend['ip']}/index.html"])
            if backend != peer["device_id"]:
                raise ValueError("Routed client-to-service HTTP request failed")
            result["checks"].update(ssh_client=True, portable_sshd=True, routed_http_backend=backend)
            resolver = target_by_id(manifest, "DNSMASQ-" + target["device_id"][-1])
            for protocol in ("+notcp", "+tcp"):
                answer = command(["dig", "+short", "+time=3", "+tries=1", protocol, "@" + resolver["ip"], "web.netvuln.test", "A"])
                if answer != peer["ip"]:
                    raise ValueError("Client DNS request did not traverse its branch resolver")
            result["checks"]["routed_dns_udp_and_tcp"] = True
        elif product == "openvpn":
            interfaces = json.loads(command(["ip", "-j", "address", "show", "dev", "tun0"]))
            if not interfaces or not interfaces[0].get("addr_info"):
                raise ValueError("VPN tunnel has no address")
            if target["role"] == "vpn_client":
                command(["ping", "-n", "-c", "2", "-W", "3", "10.54.0.1"])
            result["checks"].update(tunnel_address=True, vpn_role=target["role"])
            if target["role"] == "vpn_client":
                result["checks"]["tunnel_traffic"] = True
        elif product == "frr":
            if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
                raise ValueError("Router is not forwarding IPv4 traffic")
            text = command([str(prefix / "bin/vtysh"), "-c", "show bgp ipv4 unicast summary json"])
            summary = json.loads(text)
            def established(value) -> bool:
                if isinstance(value, dict):
                    peers = value.get("peers", {})
                    if isinstance(peers, dict) and peers.get(target_by_id(manifest, target["peer"])["ip"], {}).get("state") == "Established":
                        return True
                    return any(established(item) for item in value.values())
                return False
            if not established(summary):
                raise ValueError("FRR BGP session is not established")
            result["checks"].update(ipv4_forwarding=True, bgp_established=True)
        result["isolation"] = probe_isolation(target, manifest)
        if any(not row["passed"] for row in result["isolation"]):
            raise ValueError("A forbidden flow connected or filtering could not be established")
        result["status"] = "passed"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
    return result


def fetch_snapshot(config: dict, manifest: dict) -> dict:
    import boto3
    reader = boto3.client("secretsmanager", region_name=config["region"]).get_secret_value(SecretId=config["read_secret_arn"])["SecretString"]
    address = f"https://{manifest['network']['collector_ip']}:{manifest['network']['collector_port']}/v1/snapshot"
    request = Request(address, headers={"Authorization": "Bearer " + reader})
    with urlopen(request, context=ssl.create_default_context(cafile="/etc/netvuln/pki/collector.crt"), timeout=30) as response:
        return json.load(response)


def fleet_probe(config: dict, manifest: dict) -> dict:
    import boto3
    ec2, ssm = (boto3.client(service, region_name=config["region"]) for service in ("ec2", "ssm"))
    expected = {row["device_id"] for row in manifest["targets"]}
    observed = {}
    for page in ec2.get_paginator("describe_instances").paginate(Filters=[
        {"Name": "tag:NetVulnFleet", "Values": [config["fleet_id"]]},
        {"Name": "tag:NetVulnRole", "Values": ["target"]}, {"Name": "instance-state-name", "Values": ["running"]},
    ]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
                identity = tags.get("NetVulnDevice")
                if identity in observed or identity not in expected:
                    raise ValueError("Unexpected or duplicate target EC2 identity")
                if instance["PrivateIpAddress"] != target_by_id(manifest, identity)["ip"]:
                    raise ValueError("EC2 target IP differs from experiment manifest")
                observed[identity] = instance["InstanceId"]
    if set(observed) != expected:
        raise ValueError(f"Fleet is missing registered targets: {sorted(expected - set(observed))}")
    deadline = time.monotonic() + 600
    snapshot = fetch_snapshot(config, manifest)
    while not snapshot["complete"] and time.monotonic() < deadline:
        time.sleep(10)
        snapshot = fetch_snapshot(config, manifest)
    if not snapshot["complete"] or snapshot["expected_devices"] != 16:
        raise ValueError("Collector coverage is incomplete or stale")
    invocation = ssm.send_command(InstanceIds=list(observed.values()), DocumentName="AWS-RunShellScript", TimeoutSeconds=600,
                                  Parameters={"commands": ["cd /opt/netvuln/repo && python3 -m infra.aws.probes --local --config /etc/netvuln/bootstrap.json"], "executionTimeout": ["600"]})
    command_id = invocation["Command"]["CommandId"]
    rows = []
    deadline = time.monotonic() + 1200
    remaining = dict(observed)
    while remaining and time.monotonic() < deadline:
        for identity, instance_id in list(remaining.items()):
            try:
                response = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            except ssm.exceptions.InvocationDoesNotExist:
                continue
            if response["Status"] in {"Pending", "InProgress", "Delayed", "Cancelling"}:
                continue
            row = {"device_id": identity, "instance_id": instance_id, "status": "failed", "ssm_status": response["Status"]}
            try:
                row["probe"] = json.loads(response.get("StandardOutputContent", ""))
                if response["ResponseCode"] == 0 and row["probe"]["status"] == "passed":
                    row["status"] = "passed"
            except (ValueError, KeyError):
                row["error"] = "Probe did not return a valid result"
            if response.get("StandardErrorContent"):
                row["stderr"] = response["StandardErrorContent"][-4000:]
            rows.append(row)
            del remaining[identity]
        if remaining:
            time.sleep(5)
    rows += [{"device_id": identity, "instance_id": instance_id, "status": "failed", "error": "SSM probe timed out"} for identity, instance_id in remaining.items()]
    return {"schema_version": 1, "scope": "aws_installation_collector_and_service_functionality_not_cve_accuracy",
            "captured_at": datetime.now(timezone.utc).isoformat(), "ssm_command_id": command_id,
            "collector_snapshot": snapshot, "targets": sorted(rows, key=lambda row: row["device_id"]),
            "complete": len(rows) == 16 and all(row["status"] == "passed" for row in rows)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true")
    mode.add_argument("--fleet", action="store_true")
    parser.add_argument("--config", type=Path, default=Path("/etc/netvuln/bootstrap.json"))
    args = parser.parse_args()
    config, manifest = json.loads(args.config.read_text()), load_manifest()
    if args.local:
        deadline = time.monotonic() + 120
        result = local_probe(config, manifest)
        while result["status"] != "passed" and time.monotonic() < deadline:
            time.sleep(5)
            result = local_probe(config, manifest)
        print(json.dumps(result))
        return 0 if result["status"] == "passed" else 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    try:
        result = fleet_probe(config, manifest)
    except Exception as exc:
        result = {"schema_version": 1, "complete": False, "error": str(exc), "captured_at": stamp}
    directory = Path("/var/lib/netvuln/readiness")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{stamp}.json"
    destination.write_text(json.dumps(result, indent=2) + "\n")
    import boto3
    boto3.client("s3", region_name=config["region"]).upload_file(str(destination), config["artifacts_bucket"], f"{config['artifacts_prefix']}/runs/readiness/{stamp}.json", ExtraArgs={"ServerSideEncryption": "AES256"})
    print(json.dumps({"complete": result["complete"], "artifact": str(destination)}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
