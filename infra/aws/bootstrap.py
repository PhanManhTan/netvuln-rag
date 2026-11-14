"""CloudFormation SSH bootstrap and Ansible-managed native application installation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

from infra.aws.build import BUILD_PACKAGES, build_target, check_platform, probe_binary, run
from infra.aws.catalog import ROOT, load_lock, load_manifest, target_by_id
from infra.aws.network_policy import apply_router


REPO = ROOT.parents[1]
CONFIG = Path("/etc/netvuln")
STATE = Path("/var/lib/netvuln")


def write(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(mode)


def output(command: list[str]) -> str:
    # Never print Secrets Manager response bodies or private keys.
    return subprocess.check_output(command, text=True, timeout=120).strip()


def s3(config: dict, action: str, key: str, path: Path) -> None:
    location = f"s3://{config['artifacts_bucket']}/{config['artifacts_prefix']}/{key}"
    command = ["aws", "s3", "cp", str(path), location] if action == "upload" else ["aws", "s3", "cp", location, str(path)]
    subprocess.run([*command, "--only-show-errors"], check=True, timeout=120)


def make_ssh_key(path: Path) -> None:
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)])
    path.chmod(0o600)


def management_pki(config: dict, manifest: dict) -> None:
    pki = CONFIG / "pki"
    pki.mkdir(parents=True, exist_ok=True)
    run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365", "-subj", "/CN=netvuln-vpn-ca", "-keyout", str(pki / "ca.key"), "-out", str(pki / "ca.crt")])
    (pki / "ca.key").chmod(0o600)
    make_ssh_key(pki / "probe_key")
    make_ssh_key(pki / "ansible_key")
    known_hosts = []
    for target in manifest["targets"]:
        directory = pki / target["device_id"]
        directory.mkdir(mode=0o700)
        hostkey = directory / "ssh_host_ed25519_key"
        make_ssh_key(hostkey)
        public = hostkey.with_suffix(".pub").read_text().split()
        known_hosts.append(f"{target['ip']},[{target['ip']}]:2222 {public[0]} {public[1]}")
        shutil.copyfile(pki / "probe_key.pub", directory / "authorized_key.pub")
        shutil.copyfile(pki / "ansible_key.pub", directory / "control_authorized_key.pub")
        if target["product_id"] == "openssh":
            shutil.copyfile(pki / "probe_key", directory / "probe_key")
        if target["product_id"] == "openvpn":
            role = "serverAuth" if target["role"] == "vpn_server" else "clientAuth"
            run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-subj", f"/CN={target['device_id']}", "-keyout", str(directory / "vpn.key"), "-out", str(directory / "vpn.csr")])
            write(directory / "vpn.ext", f"extendedKeyUsage={role}\nkeyUsage=digitalSignature,keyEncipherment\n")
            run(["openssl", "x509", "-req", "-in", str(directory / "vpn.csr"), "-CA", str(pki / "ca.crt"), "-CAkey", str(pki / "ca.key"), "-CAcreateserial", "-days", "365", "-extfile", str(directory / "vpn.ext"), "-out", str(directory / "vpn.crt")])
            shutil.copyfile(pki / "ca.crt", directory / "ca.crt")
        archive_path = pki / f"{target['device_id']}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            for path in sorted(directory.iterdir()):
                archive.add(path, arcname=path.name)
        archive_path.chmod(0o600)
        s3(config, "upload", f"pki/{target['device_id']}.tar.gz", archive_path)
    known_path = pki / "known_hosts"
    write(known_path, "\n".join(known_hosts) + "\n", 0o644)
    s3(config, "upload", "ssh-known-hosts", known_path)


def unit(name: str, command: list[str], *, user: str = "root", extra_unit: str = "", extra_service: str = "", service_type: str = "simple") -> None:
    if any("\n" in part or '"' in part for part in command):
        raise ValueError("Invalid service argument")
    executable = " ".join('"' + part + '"' for part in command)
    write(Path("/etc/systemd/system") / name, f"""[Unit]
Description=NetVuln experiment {name}
After=network-online.target
Wants=network-online.target
{extra_unit}
[Service]
Type={service_type}
User={user}
WorkingDirectory={REPO}
ExecStart={executable}
Restart=on-failure
RestartSec=5
{extra_service}
[Install]
WantedBy=multi-user.target
""", 0o644)


def start_unit(name: str) -> None:
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", name])
    time.sleep(2)
    run(["systemctl", "is-active", "--quiet", name])


def bootstrap_management(config: dict, manifest: dict) -> None:
    run(["apt-get", "install", "-y", "--no-install-recommends", "openssl", "openssh-client", "python3-venv"])
    run(["python3", "-m", "venv", "/opt/netvuln/venv"])
    run(["/opt/netvuln/venv/bin/pip", "install", "-r", str(ROOT / "control-requirements.txt")])
    CONFIG.chmod(0o700)
    STATE.mkdir(parents=True, exist_ok=True)
    management_pki(config, manifest)
    (CONFIG / "pki").chmod(0o700)
    run(["/opt/netvuln/venv/bin/ansible-playbook", "--version"])


def target_pki(config: dict, target: dict) -> None:
    directory = CONFIG / "pki"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    archive_path = CONFIG / "pki.tar.gz"
    s3(config, "download", f"pki/{target['device_id']}.tar.gz", archive_path)
    with tarfile.open(archive_path) as archive:
        if any(not member.isfile() or Path(member.name).name != member.name for member in archive.getmembers()):
            raise ValueError("Invalid node credential bundle")
        archive.extractall(directory)
    for path in directory.iterdir():
        path.chmod(0o600)
    s3(config, "download", "ssh-known-hosts", CONFIG / "known_hosts")
    if subprocess.run(["id", "netvulnprobe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(["useradd", "--create-home", "--shell", "/bin/bash", "netvulnprobe"])
        # The account is usable for public-key auth; no password is distributed or accepted.
        password_hash = output(["openssl", "passwd", "-6", output(["openssl", "rand", "-hex", "32"])])
        subprocess.run(["usermod", "--password", password_hash, "netvulnprobe"], check=True)
    home = Path("/home/netvulnprobe/.ssh")
    write(home / "authorized_keys", (directory / "authorized_key.pub").read_text())
    home.chmod(0o700)
    run(["chown", "-R", "netvulnprobe:netvulnprobe", str(home)])
    if subprocess.run(["id", "netvulnadmin"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(["useradd", "--create-home", "--shell", "/bin/bash", "netvulnadmin"])
        password_hash = output(["openssl", "passwd", "-6", output(["openssl", "rand", "-hex", "32"])])
        subprocess.run(["usermod", "--password", password_hash, "netvulnadmin"], check=True)
    admin_home = Path("/home/netvulnadmin/.ssh")
    write(admin_home / "authorized_keys", (directory / "control_authorized_key.pub").read_text())
    admin_home.chmod(0o700)
    run(["chown", "-R", "netvulnadmin:netvulnadmin", str(admin_home)])
    write(Path("/etc/sudoers.d/netvulnadmin"), "netvulnadmin ALL=(ALL) NOPASSWD:ALL\n", 0o440)
    run(["visudo", "-cf", "/etc/sudoers.d/netvulnadmin"])
    write(Path("/etc/ssh/sshd_config.d/99-netvuln.conf"), f"PasswordAuthentication no\nPermitRootLogin no\nHostKey {directory}/ssh_host_ed25519_key\n", 0o644)
    run(["systemctl", "restart", "ssh.service"])


def configure_service(target: dict, manifest: dict, prefix: Path) -> None:
    product = target["product_id"]
    peer = target_by_id(manifest, target["peer"]) if target.get("peer") else None
    conf = CONFIG / "service.conf"
    command: list[str]
    if product == "apache":
        web = STATE / "www"
        write(web / "index.html", target["device_id"] + "\n", 0o644)
        text = f"""ServerRoot "{prefix}"
Listen 80
ServerName {target['device_id']}.netvuln.test
PidFile /run/netvuln-apache.pid
<IfModule !mpm_event_module>
LoadModule mpm_event_module modules/mod_mpm_event.so
</IfModule>
<IfModule !authz_core_module>
LoadModule authz_core_module modules/mod_authz_core.so
</IfModule>
<IfModule !unixd_module>
LoadModule unixd_module modules/mod_unixd.so
</IfModule>
<IfModule !dir_module>
LoadModule dir_module modules/mod_dir.so
</IfModule>
DirectoryIndex index.html
User www-data
Group www-data
ErrorLog /dev/stderr
DocumentRoot "{web}"
<Directory />
    Require all denied
</Directory>
<Directory "{web}">
    Require all granted
</Directory>
"""
        command = [str(prefix / "bin/httpd"), "-DFOREGROUND", "-f", str(conf)]
    elif product == "nginx":
        text = f"""daemon off;
pid /run/netvuln-nginx.pid;
error_log /dev/stderr;
events {{ worker_connections 128; }}
http {{ access_log off; server {{ listen 80; location / {{ proxy_pass http://{peer['ip']}:80; }} }} }}
"""
        command = [str(prefix / "sbin/nginx"), "-c", str(conf)]
    elif product == "haproxy":
        text = f"""global
    maxconn 128
defaults
    mode http
    timeout connect 5s
    timeout client 15s
    timeout server 15s
frontend http
    bind :80
    default_backend upstream
backend upstream
    server upstream1 {peer['ip']}:80 check
"""
        command = [str(prefix / "sbin/haproxy"), "-db", "-f", str(conf)]
    elif product == "bind":
        apache = target_by_id(manifest, "APACHE-" + target["device_id"][-1])
        zone = CONFIG / "netvuln.test.zone"
        write(zone, f"$TTL 60\n@ IN SOA ns.netvuln.test. hostmaster.netvuln.test. (1 60 60 3600 60)\n@ IN NS ns.netvuln.test.\nns IN A {target['ip']}\nweb IN A {apache['ip']}\n", 0o644)
        text = f'options {{ directory "{STATE}"; listen-on {{ {target["ip"]}; 127.0.0.1; }}; listen-on-v6 {{ none; }}; recursion no; dnssec-validation no; }};\nzone "netvuln.test" {{ type primary; file "{zone}"; }};\n'
        command = [str(prefix / "sbin/named"), "-g", "-c", str(conf)]
    elif product == "dnsmasq":
        text = f"port=53\nbind-interfaces\nlisten-address={target['ip']},127.0.0.1\nno-resolv\nserver=/netvuln.test/{peer['ip']}\nno-hosts\nuser=nobody\n"
        command = [str(prefix / "sbin/dnsmasq"), "--keep-in-foreground", f"--conf-file={conf}"]
    elif product == "openssh":
        Path("/run/sshd").mkdir(exist_ok=True)
        text = f"Port 2222\nListenAddress 0.0.0.0\nHostKey {CONFIG}/pki/ssh_host_ed25519_key\nPidFile /run/netvuln-sshd.pid\nPasswordAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\nUsePAM yes\nAllowUsers netvulnprobe\nAuthorizedKeysFile .ssh/authorized_keys\n"
        command = [str(prefix / "sbin/sshd"), "-D", "-e", "-f", str(conf)]
    elif product == "openvpn":
        common = f"dev tun0\nproto udp\nca {CONFIG}/pki/ca.crt\ncert {CONFIG}/pki/vpn.crt\nkey {CONFIG}/pki/vpn.key\ndata-ciphers AES-256-GCM\nauth SHA256\npersist-key\npersist-tun\nverb 3\n"
        if target["role"] == "vpn_server":
            text = common + "port 1194\nserver 10.54.0.0 255.255.255.0\ntopology subnet\ndh none\nkeepalive 10 60\n"
        else:
            text = common + f"client\nremote {peer['ip']} 1194\nnobind\nremote-cert-tls server\nverify-x509-name {peer['device_id']} name\n"
        command = [str(prefix / "sbin/openvpn"), "--config", str(conf)]
    elif product == "frr":
        apply_router(target, manifest)
        unit("netvuln-firewall.service", ["/usr/bin/python3", "-m", "infra.aws.network_policy", "--device", target["device_id"], "--apply"], extra_service="RemainAfterExit=yes", service_type="oneshot")
        start_unit("netvuln-firewall.service")
        index = 1 if target["device_id"].endswith("A") else 2
        settings = ["net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0",
                    "net.ipv4.conf.all.send_redirects=0", "net.ipv4.conf.default.send_redirects=0",
                    "net.ipv4.conf.all.accept_redirects=0", "net.ipv4.conf.default.accept_redirects=0"]
        for interface in Path("/proc/sys/net/ipv4/conf").iterdir():
            settings.extend([f"net.ipv4.conf.{interface.name}.send_redirects=0", f"net.ipv4.conf.{interface.name}.accept_redirects=0"])
        run(["sysctl", "-w", *settings])
        write(Path("/etc/sysctl.d/90-netvuln-router.conf"), "\n".join(settings) + "\n", 0o644)
        run(["ip", "address", "replace", f"10.255.0.{index}/32", "dev", "lo"])
        Path("/run/frr").mkdir(parents=True, exist_ok=True)
        write(CONFIG / "frr/zebra.conf", f"hostname {target['device_id']}\nlog stdout\n", 0o644)
        text = f"""hostname {target['device_id']}
log stdout
router bgp {65000 + index}
 bgp router-id {target['ip']}
 no bgp ebgp-requires-policy
 neighbor {peer['ip']} remote-as {65003 - index}
 address-family ipv4 unicast
  network 10.255.0.{index}/32
 exit-address-family
"""
        unit("netvuln-zebra.service", [str(prefix / "sbin/zebra"), "-f", str(CONFIG / "frr/zebra.conf"), "-z", "/run/frr/zserv.api", "-i", "/run/frr/zebra.pid"], extra_service="RuntimeDirectory=frr\nRuntimeDirectoryMode=0755")
        start_unit("netvuln-zebra.service")
        command = [str(prefix / "sbin/bgpd"), "-f", str(conf), "-z", "/run/frr/zserv.api", "-i", "/run/frr/bgpd.pid"]
    else:
        raise ValueError("Unsupported experiment product")
    write(conf, text, 0o644)
    extra_service = f"ExecStartPre=ip address replace 10.255.0.{index}/32 dev lo" if product == "frr" else ""
    unit("netvuln-target.service", command, extra_unit="Requires=netvuln-zebra.service netvuln-firewall.service\nAfter=netvuln-zebra.service netvuln-firewall.service" if product == "frr" else "", extra_service=extra_service)
    start_unit("netvuln-target.service")


def bootstrap_target(config: dict, manifest: dict) -> None:
    target = target_by_id(manifest, config["device_id"])
    run(["apt-get", "install", "-y", "--no-install-recommends", "openssh-server", "openssh-client", "openssl", "sudo", "python3-apt"])
    target_pki(config, target)


def build_required(target: dict, prefix: Path, expected_hash: str) -> bool:
    try:
        saved = json.loads((prefix / "build.json").read_text())
        observed = probe_binary(target["product_id"], target["version"], prefix)
        return saved["source_sha256"] != expected_hash or saved["binary_sha256"] != observed["binary_sha256"]
    except (OSError, ValueError, KeyError):
        return True


def install_target(config: dict, manifest: dict) -> dict:
    target = target_by_id(manifest, config["device_id"])
    prefix_root = Path("/opt/netvuln/products")
    prefix = prefix_root / target["product_id"] / target["version"]
    lock = load_lock(manifest)
    expected_hash = lock["sources"][f"{target['product_id']}-{target['version']}"]["sha256"]
    needs_build = build_required(target, prefix, expected_hash)
    if needs_build:
        build_target(target, manifest, lock, REPO / "artifacts/aws/sources", Path("/var/tmp/netvuln-build"), prefix_root)
    tracked = [CONFIG / "service.conf", CONFIG / "router.nft", Path("/etc/systemd/system/netvuln-target.service"), Path("/etc/systemd/system/netvuln-zebra.service"), Path("/etc/systemd/system/netvuln-firewall.service")]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None for path in tracked}
    STATE.mkdir(parents=True, exist_ok=True)
    configure_service(target, manifest, prefix)
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None for path in tracked}
    changed = needs_build or before != after
    if changed:
        if target["product_id"] == "frr":
            run(["systemctl", "restart", "netvuln-zebra.service"])
        run(["systemctl", "restart", "netvuln-target.service"])
    write(CONFIG / "facts.json", json.dumps({"target": target, "prefix": str(prefix), "management_ip": target["ip"]}, indent=2) + "\n", 0o644)
    return {"device_id": target["device_id"], "changed": changed, "version": target["version"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG / "bootstrap.json")
    parser.add_argument("--install-target", action="store_true", help="Ansible invokes application installation separately from cloud-init")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    # Service code/venvs/document roots must be readable after dropping root.
    # Credentials are written explicitly as 0600/0640 and node PKI directories as 0700.
    os.umask(0o022)
    os.environ["AWS_DEFAULT_REGION"] = config["region"]
    check_platform(native_local=config["kind"] == "management")
    manifest = load_manifest()
    if args.install_target:
        if config["kind"] != "target":
            raise ValueError("Only a registered target can be installed by this operation")
        print(json.dumps(install_target(config, manifest)))
        return 0
    if config["kind"] == "management":
        bootstrap_management(config, manifest)
    elif config["kind"] == "target":
        bootstrap_target(config, manifest)
    else:
        raise ValueError("Unknown bootstrap role")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
