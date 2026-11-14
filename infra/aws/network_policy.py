"""Declared service flows, router forwarding rules and live isolation probes.

Management SSH is a separate permission. Sharing a VPC never grants general
workload access. This module does not change the Codespace host's firewall.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess

from infra.aws.catalog import load_manifest, target_by_id


def service_flows(manifest: dict) -> list[dict]:
    flows = []
    def add(identity, source, destination, protocol, port, router=None):
        flows.append({"id": identity, "source": source, "destination": destination,
                      "source_ip": target_by_id(manifest, source)["ip"],
                      "destination_ip": target_by_id(manifest, destination)["ip"],
                      "protocol": protocol, "port": port, "router": router})
    for branch in ("A", "B"):
        router = f"FRR-{branch}"
        add(f"client-{branch}-web", f"OPENSSH-{branch}", f"HAPROXY-{branch}", "tcp", 80, router)
        add(f"client-{branch}-ssh", f"OPENSSH-{branch}", f"APACHE-{branch}", "tcp", 22, router)
        for protocol in ("tcp", "udp"):
            add(f"client-{branch}-dns-{protocol}", f"OPENSSH-{branch}", f"DNSMASQ-{branch}", protocol, 53, router)
            add(f"forwarder-{branch}-dns-{protocol}", f"DNSMASQ-{branch}", f"BIND-{branch}", protocol, 53)
        add(f"frontend-{branch}", f"HAPROXY-{branch}", f"NGINX-{branch}", "tcp", 80)
        add(f"backend-{branch}", f"NGINX-{branch}", f"APACHE-{branch}", "tcp", 80)
        add(f"bgp-{branch}", router, f"FRR-{'B' if branch == 'A' else 'A'}", "tcp", 179)
    add("vpn-underlay", "OPENVPN-B", "OPENVPN-A", "udp", 1194, "FRR-A")
    return flows


def ingress_rules(target: dict, manifest: dict) -> list[dict]:
    rules = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
              "CidrIp": manifest["network"]["collector_ip"] + "/32", "Description": "Ansible management SSH only"}]
    for flow in service_flows(manifest):
        if flow["destination"] == target["device_id"] or flow["router"] == target["device_id"]:
            rules.append({"IpProtocol": flow["protocol"], "FromPort": flow["port"], "ToPort": flow["port"],
                          "CidrIp": flow["source_ip"] + "/32", "Description": flow["id"]})
        if flow["router"] == target["device_id"]:
            rules.append({"IpProtocol": flow["protocol"], "FromPort": 1024, "ToPort": 65535,
                          "CidrIp": flow["destination_ip"] + "/32", "Description": flow["id"] + " return traffic"})
    # CIDRs are deliberate: SG references do not preserve source identity through a middlebox.
    return rules


def router_rules(target: dict, manifest: dict) -> str:
    if target["product_id"] != "frr":
        raise ValueError("Forwarding policy is only installed on registered routers")
    lines = ["table inet netvuln {", " chain forward {", "  type filter hook forward priority 0; policy drop;",
             "  ct state established,related counter accept"]
    for flow in service_flows(manifest):
        if flow["router"] == target["device_id"]:
            lines.append(f'  ip saddr {flow["source_ip"]} ip daddr {flow["destination_ip"]} {flow["protocol"]} dport {flow["port"]} counter accept comment "{flow["id"]}"')
    lines += ['  counter drop comment "default-deny"', " }", "}"]
    return "\n".join(lines) + "\n"


def apply_router(target: dict, manifest: dict, path: Path = Path("/etc/netvuln/router.nft")) -> bool:
    desired = router_rules(target, manifest)
    exists = subprocess.run(["nft", "list", "table", "inet", "netvuln"], capture_output=True).returncode == 0
    if exists and path.exists() and path.read_text() == desired:
        return False
    path.write_text(desired)
    path.chmod(0o600)
    # Replace only our own table, atomically; never flush another firewall's rules.
    script = ("delete table inet netvuln\n" if exists else "") + desired
    subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True)
    return True


def isolation_cases(target: dict, manifest: dict) -> list[dict]:
    branch = target["device_id"][-1]
    other = "B" if branch == "A" else "A"
    cases = []
    def deny(name, destination, port):
        cases.append({"id": name, "destination": destination, "ip": target_by_id(manifest, destination)["ip"], "port": port})
    if target["product_id"] == "openssh":
        deny("backend-http-hidden", f"APACHE-{branch}", 80)
        deny("other-branch-web", f"HAPROXY-{other}", 80)
        deny("other-branch-admin", f"APACHE-{other}", 22)
        cases.append({"id": "workload-to-management", "destination": "MGMT", "ip": manifest["network"]["collector_ip"], "port": 22})
    elif target["product_id"] == "haproxy":
        deny("frontend-cannot-skip-proxy", f"APACHE-{branch}", 80)
    elif target["product_id"] == "apache":
        deny("backend-cannot-open-reverse-proxy", f"NGINX-{branch}", 80)
        deny("server-cannot-admin-client", f"OPENSSH-{branch}", 22)
    elif target["product_id"] == "dnsmasq":
        deny("other-branch-dns", f"BIND-{other}", 53)
    return cases


def probe_isolation(target: dict, manifest: dict) -> list[dict]:
    results = []
    for case in isolation_cases(target, manifest):
        row = {**case, "expected": "filtered", "passed": False}
        try:
            with socket.create_connection((case["ip"], case["port"]), timeout=3):
                row["observed"] = "connected"
        except TimeoutError:
            row.update(observed="filtered_timeout", passed=True)
        except OSError as exc:
            # Refused/unreachable is not proof that a healthy listening service was filtered.
            row.update(observed="connection_error", error=str(exc))
        results.append(row)
    return results


def router_evidence(target: dict, manifest: dict) -> dict:
    command = subprocess.run(["nft", "-j", "list", "table", "inet", "netvuln"], capture_output=True, text=True, check=True)
    raw = json.loads(command.stdout)
    counters = {}
    for item in raw["nftables"]:
        rule = item.get("rule", {})
        if rule.get("comment"):
            counters[rule["comment"]] = next((expr["counter"]["packets"] for expr in rule.get("expr", []) if "counter" in expr), 0)
    required = f"client-{target['device_id'][-1]}-web"
    return {"device_id": target["device_id"], "status": "passed" if counters.get(required, 0) > 0 else "failed",
            "scope": "observed_forwarding_counter_not_just_endpoint_reachability", "required_flow": required,
            "counters": counters, "ruleset": raw}


def forwarding_delta(identity: str, before: dict, after: dict) -> dict:
    flow = f"client-{identity[-1]}-web"
    initial, final = before.get("counters", {}).get(flow), after.get("counters", {}).get(flow)
    valid = before.get("device_id") == after.get("device_id") == identity and type(initial) is int and type(final) is int
    delta = final - initial if valid else None
    return {**after, "device_id": identity, "required_flow": flow,
            "packets_before": initial, "packets_after": final, "new_packets": delta,
            "status": "passed" if valid and delta > 0 else "failed"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--verify-counters", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest()
    target = target_by_id(manifest, args.device)
    if args.apply:
        print(json.dumps({"device_id": args.device, "changed": apply_router(target, manifest)}))
        return 0
    result = router_evidence(target, manifest)
    print(json.dumps(result))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
