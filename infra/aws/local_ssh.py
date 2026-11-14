"""Start the locally installed OpenSSH pilot on loopback and capture real facts.

Run with sudo for normal sshd privilege separation. This does not edit or replace
the system's sshd, authorized_keys, service units, network or port 22.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import time

from collector.agent import os_facts, packages
from infra.aws.build import probe_binary
from infra.aws.catalog import load_lock, load_manifest
from infra.aws.sources import sha256


def start(prefix: Path, state: Path, port: int) -> dict:
    if os.geteuid() != 0:
        raise PermissionError("Run this isolated sshd pilot with sudo")
    if not prefix.resolve().is_relative_to(Path("/tmp")) or not state.resolve().is_relative_to(Path("/tmp")):
        raise ValueError("Local pilot paths must be under /tmp")
    if not 1024 < port <= 65535:
        raise ValueError("The pilot must use its own high port")
    observed = probe_binary("openssh", "9.6p1", prefix)
    build = json.loads((prefix / "build.json").read_text())
    pin = load_lock(load_manifest())["sources"]["openssh-9.6p1"]["sha256"]
    if build["source_sha256"] != pin or build["binary_sha256"] != observed["binary_sha256"]:
        raise ValueError("Installed binary/build evidence differs from locked source")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))
    state.mkdir(parents=True, exist_ok=True, mode=0o755)
    state.chmod(0o755)
    empty = prefix / "empty"
    empty.mkdir(exist_ok=True)
    os.chown(empty, 0, 0)
    empty.chmod(0o755)
    key = state / "ssh_host_ed25519_key"
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    key.chmod(0o600)
    config = state / "sshd_config"
    config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {key}\nPidFile {state}/sshd.pid\nPasswordAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\nUsePAM yes\nLoginGraceTime 120\nAllowUsers codespace\n")
    config.chmod(0o644)
    binary = observed["binary"]
    subprocess.run([binary, "-t", "-f", str(config)], check=True)
    effective = subprocess.check_output([binary, "-T", "-f", str(config)], text=True)
    allowed = {"port", "listenaddress", "logingracetime", "usepam", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "maxauthtries"}
    fields = {key: value for line in effective.splitlines() for key, _, value in [line.partition(" ")] if key in allowed}
    with (state / "sshd.log").open("a") as log:
        process = subprocess.Popen([binary, "-D", "-e", "-f", str(config)], stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
    banner = None
    for _ in range(40):
        if process.poll() is not None:
            raise RuntimeError(f"Pilot sshd exited; inspect {state / 'sshd.log'}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                banner = client.recv(1024).decode().strip()
            break
        except OSError:
            time.sleep(0.25)
    if not banner or not banner.startswith("SSH-2.0-OpenSSH_9.6"):
        process.terminate()
        raise RuntimeError("Pilot sshd did not report the expected live SSH banner")
    snapshot = {
        "schema_version": 1, "device_id": "OPENSSH-A", "collected_at": datetime.now(timezone.utc).isoformat(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "management_ip": "127.0.0.1", "collection_status": "collected", "os": os_facts(),
        "software": [{"product_id": "openssh", "component": "sshd", "version": observed["version"],
                      "binary": binary, "binary_sha256": observed["binary_sha256"], "running": True,
                      "configuration": {**fields, "configuration_sha256": sha256(config)},
                      "evidence": {"scope": "experiment_target", "source_sha256": pin, "version_output": observed["version_output"],
                                   "process_uid": 0, "pid": process.pid}}],
        "packages": packages(), "network": {"ssh_banner": banner, "listener": f"127.0.0.1:{port}",
                   "libc": subprocess.check_output(["getconf", "GNU_LIBC_VERSION"], text=True).strip(), "architecture": platform.machine()},
        "errors": [], "limitations": ["Single Codespace process; not the AWS network.", "No exploit was attempted; this captures software/configuration facts only."],
    }
    destination = state / "snapshot.json"
    destination.write_text(json.dumps(snapshot, indent=2) + "\n")
    destination.chmod(0o644)
    print(json.dumps({"pid": process.pid, "listener": snapshot["network"]["listener"], "version": observed["version"], "snapshot": str(destination)}))
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path("/tmp/netvuln-openssh-pilot/products/openssh/9.6p1"))
    parser.add_argument("--state", type=Path, default=Path("/tmp/netvuln-openssh-pilot/service"))
    parser.add_argument("--port", type=int, default=22222)
    args = parser.parse_args()
    start(args.prefix, args.state, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
