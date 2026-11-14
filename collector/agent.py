"""Observe local binaries and effective configuration; send facts, never CVE labels."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import ssl
import socket
import platform
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from infra.aws.build import binary_spec
from infra.aws.sources import sha256
import re


def capture(command: list[str], timeout: int = 30) -> tuple[int, str]:
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    return result.returncode, (result.stdout + result.stderr).strip()


def os_facts() -> dict[str, str]:
    result = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value.strip('"')
    return result


def packages() -> list[dict[str, str]]:
    code, text = capture(["dpkg-query", "-W", "-f=${db:Status-Status}\t${binary:Package}\t${Version}\n"])
    if code:
        raise RuntimeError("Package inventory command failed")
    return [{"name": fields[1], "version": fields[2]} for line in text.splitlines()
            if len(fields := line.split("\t")) == 3 and fields[0] == "installed"]


def configuration(product: str, prefix: Path, config_path: Path = Path("/etc/netvuln/service.conf")) -> dict:
    commands = {
        "nginx": [str(prefix / "sbin/nginx"), "-T", "-c", str(config_path)],
        "apache": [str(prefix / "bin/httpd"), "-t", "-D", "DUMP_RUN_CFG", "-f", str(config_path)],
        "bind": [str(prefix / "bin/named-checkconf"), "-p", str(config_path)],
        "openssh": [str(prefix / "sbin/sshd"), "-T", "-f", str(config_path)],
        "frr": [str(prefix / "bin/vtysh"), "-c", "show running-config"],
    }
    result = {"configuration_sha256": sha256(config_path) if config_path.exists() else None}
    if product in commands:
        code, effective = capture(commands[product])
        if code:
            raise RuntimeError(f"Effective configuration probe failed for {product}")
        result["effective"] = effective[:65536]
        if product == "openssh":
            selected = {"logingracetime", "port", "listenaddress", "usepam", "passwordauthentication", "permitrootlogin"}
            result.update({key: value for line in effective.splitlines() for key, _, value in [line.partition(" ")] if key in selected})
    elif config_path.exists():
        # Generated files contain key/cert paths, never inline private keys or passwords.
        result["effective"] = config_path.read_text()[:65536]
    return result


def collect(config: dict) -> dict:
    target = config["target"]
    product, prefix = target["product_id"], Path(config["prefix"])
    binary, args, pattern = binary_spec(product, prefix)
    software = {"product_id": product, "component": binary.name, "evidence": {"scope": "experiment_target"}, "configuration": {}}
    errors = []
    try:
        code, output = capture([str(binary), *args])
        match = re.search(pattern, output)
        if code or not match:
            raise RuntimeError("Could not observe target binary version")
        software.update(version=match.group(1), binary=str(binary), binary_sha256=sha256(binary))
        software["evidence"]["version_output"] = output[:16384]
        build_path = prefix / "build.json"
        if build_path.exists():
            build = json.loads(build_path.read_text())
            software["evidence"]["source_sha256"] = build["source_sha256"]
        if config.get("pid_file"):
            pid = int(Path(config["pid_file"]).read_text().strip())
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
            software["running"] = executable == binary.resolve()
            process_status = Path(f"/proc/{pid}/status").read_text()
            uid = next(int(line.split()[1]) for line in process_status.splitlines() if line.startswith("Uid:"))
            software["evidence"].update(pid=pid, process_uid=uid)
        else:
            active, _ = capture(["systemctl", "is-active", "--quiet", "netvuln-target.service"])
            software["running"] = active == 0
        software["configuration"] = configuration(product, prefix, Path(config.get("configuration_file", "/etc/netvuln/service.conf")))
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        software["error"] = str(exc)
        errors.append(str(exc))
    installed = []
    try:
        installed = packages()
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        errors.append(str(exc))
    network = {}
    for name, command in (("addresses", ["ip", "-j", "address"]), ("routes", ["ip", "-j", "route"])):
        try:
            code, output = capture(command)
            if code:
                raise ValueError(f"Network probe failed: {name}")
            network[name] = json.loads(output)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    forwarding = Path("/proc/sys/net/ipv4/ip_forward")
    network["ipv4_forwarding"] = forwarding.read_text().strip() == "1"
    code, libc = capture(["getconf", "GNU_LIBC_VERSION"])
    if code == 0:
        network["libc"] = libc
    network["architecture"] = platform.machine()
    addresses = [entry["local"] for interface in network.get("addresses", [])
                 for entry in interface.get("addr_info", [])
                 if entry.get("family") == "inet" and (config.get("network_scope") == "loopback_pilot" or not entry["local"].startswith("127."))]
    actual_ip = next((address for address in addresses if address == config["management_ip"]), addresses[0] if addresses else "unknown")
    if actual_ip != config["management_ip"]:
        errors.append("Registered management IP was not observed on a local interface")
    if config.get("network_scope") == "loopback_pilot":
        port = int(config["listener_port"])
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            network["ssh_banner"] = connection.recv(1024).decode().strip()
        network["listener"] = f"127.0.0.1:{port}"
    return {
        "schema_version": 1, "device_id": target["device_id"],
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "management_ip": actual_ip, "collection_status": "partial" if errors else "collected",
        "os": os_facts(), "software": [software], "packages": installed, "network": network,
        "errors": errors, "limitations": [
            "Package versions may include distribution backports; upstream version alone does not establish applicability.",
            "Only configured target components have binary and effective configuration probes; package inventory includes other installed software.",
            "Running state and network reachability are separate from whether a CVE applies.",
        ],
    }


def push(config: dict, snapshot: dict) -> dict:
    url = config["collector_url"].rstrip("/") + f"/v1/devices/{snapshot['device_id']}/snapshots"
    if not url.startswith("https://"):
        raise ValueError("Agent transport requires HTTPS")
    context = ssl.create_default_context(cafile=config["ca_file"])
    request = Request(url, data=json.dumps(snapshot).encode(), method="POST", headers={
        "Authorization": "Bearer " + config["token"], "Content-Type": "application/json",
    })
    with urlopen(request, context=context, timeout=30) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/netvuln/agent.json"))
    parser.add_argument("--print-only", action="store_true", help="Observe locally without making a network request")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    snapshot = collect(config)
    if args.print_only:
        print(json.dumps(snapshot, ensure_ascii=False))
    else:
        try:
            print(json.dumps(push(config, snapshot)))
        except HTTPError as exc:
            print(f"Collector rejected snapshot: HTTP {exc.code}", file=sys.stderr)
            return 1
        except URLError:
            print("Collector connection or TLS validation failed", file=sys.stderr)
            return 1
    return 0 if snapshot["collection_status"] == "collected" else 1


if __name__ == "__main__":
    raise SystemExit(main())
