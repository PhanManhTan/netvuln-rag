"""Compile a locked upstream release on Ubuntu 22.04; never choose a fallback version."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import re
import subprocess
import tarfile

from infra.aws.catalog import LOCK, MANIFEST, ROOT, load_lock, load_manifest, target_by_id
from infra.aws.sources import archive_name, sha256


BUILD_PACKAGES = (
    "build-essential", "autoconf", "automake", "libtool", "libtool-bin", "pkg-config",
    "cmake", "bison", "flex", "texinfo", "python3-dev", "python3-pip", "python3-venv",
    "libssl-dev", "zlib1g-dev", "libpcre2-dev", "libpcre3-dev", "libreadline-dev",
    "libjson-c-dev", "libc-ares-dev", "libcap-dev", "libelf-dev", "libunwind-dev",
    "libprotobuf-c-dev", "protobuf-c-compiler", "libapr1-dev", "libaprutil1-dev",
    "libuv1-dev", "libxml2-dev", "libcmocka-dev", "liblzo2-dev", "liblz4-dev",
    "libpam0g-dev", "libnl-genl-3-dev", "libsystemd-dev", "libcap-ng-dev", "nettle-dev",
    "libdbus-1-dev", "liblua5.3-dev", "libedit-dev", "ca-certificates", "curl",
    "iproute2", "iputils-ping", "dnsutils", "openssl", "openssh-client", "openssh-server", "nftables",
)


def run(command: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    print("Running: " + " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True, timeout=7200)


def check_platform(*, native_local: bool = False) -> dict[str, str]:
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip('"')
    observed = {"distribution": values.get("ID", "unknown"), "release": values.get("VERSION_ID", "unknown"), "architecture": platform.machine()}
    supported_releases = {"22.04", "24.04"} if native_local else {"22.04"}
    if observed["distribution"] != "ubuntu" or observed["release"] not in supported_releases or observed["architecture"] != "x86_64":
        raise ValueError("Builds require Ubuntu 22.04 x86_64, matching the experiment AMI")
    return observed


def extract_source(source: dict, lock: dict, cache: Path, work: Path) -> Path:
    path = cache / archive_name(source["source_id"])
    if sha256(path) != lock["sha256"] or path.stat().st_size != lock["size_bytes"]:
        raise ValueError(f"Source integrity failure: {source['source_id']}")
    destination = work / source["source_id"]
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            candidate = (root / member.name).resolve()
            if not candidate.is_relative_to(root) or member.isdev() or member.isfifo():
                raise ValueError("Unsafe source archive member")
            if member.issym() or member.islnk():
                link = (candidate.parent / member.linkname if member.issym() else root / member.linkname).resolve()
                if not link.is_relative_to(root):
                    raise ValueError("Unsafe source archive link")
        archive.extractall(destination)  # All paths and links checked for Python 3.10 compatibility.
    source_root = destination / source["archive_root"]
    if not source_root.is_dir():
        raise ValueError("Source archive root differs from manifest")
    return source_root


def binary_spec(product: str, prefix: Path) -> tuple[Path, list[str], str]:
    relative, args, regex = {
        "frr": ("sbin/bgpd", ["--version"], r"(?:FRRouting\s+|bgpd version\s+)([0-9]+\.[0-9]+\.[0-9]+)"),
        "nginx": ("sbin/nginx", ["-v"], r"nginx/([0-9.]+)"),
        "apache": ("bin/httpd", ["-v"], r"Apache/([0-9.]+)"),
        "bind": ("sbin/named", ["-v"], r"BIND\s+([0-9.]+)"),
        "openvpn": ("sbin/openvpn", ["--version"], r"OpenVPN\s+([0-9.]+)"),
        "openssh": ("sbin/sshd", ["-V"], r"OpenSSH_([0-9]+\.[0-9]+p[0-9]+)"),
        "haproxy": ("sbin/haproxy", ["-v"], r"HAProxy version\s+([0-9]+\.[0-9]+\.[0-9]+)"),
        "dnsmasq": ("sbin/dnsmasq", ["--version"], r"Dnsmasq version\s+([0-9.]+)"),
    }[product]
    return prefix / relative, args, regex


def probe_binary(product: str, expected_version: str, prefix: Path) -> dict:
    binary, args, pattern = binary_spec(product, prefix)
    process = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=30)
    output = (process.stdout + process.stderr).strip()
    match = re.search(pattern, output)
    if process.returncode != 0 or not match or match.group(1) != expected_version:
        raise ValueError(f"Binary version mismatch for {product}: {output[:1000]}")
    return {"binary": str(binary), "version": match.group(1), "binary_sha256": sha256(binary), "version_output": output}


def build_target(target: dict, manifest: dict, lock: dict, cache: Path, work: Path, prefix_root: Path, jobs: int = 2, *, native_local: bool = False) -> dict:
    observed_platform = check_platform(native_local=native_local)
    product, version = target["product_id"], target["version"]
    source_id = f"{product}-{version}"
    sources = {row["source_id"]: row for row in manifest["sources"]}
    source = extract_source(sources[source_id], lock["sources"][source_id], cache, work)
    prefix = prefix_root / product / version
    env = {**os.environ, "LC_ALL": "C.UTF-8", "SOURCE_DATE_EPOCH": "1704067200"}
    commands: list[list[str]] = []
    configure = ["./configure", f"--prefix={prefix}"]
    if product == "frr":
        yang = extract_source(sources["libyang-2.1.128"], lock["sources"]["libyang-2.1.128"], cache, work)
        yang_prefix = prefix_root / "libyang" / "2.1.128"
        run(["cmake", "-S", str(yang), "-B", str(yang / "build"), f"-DCMAKE_INSTALL_PREFIX={yang_prefix}", "-DCMAKE_BUILD_TYPE=Release", "-DENABLE_TESTS=OFF", "-DENABLE_LYD_PRIV=ON"], env=env)
        run(["cmake", "--build", str(yang / "build"), "--parallel", str(jobs)], env=env)
        run(["cmake", "--install", str(yang / "build")], env=env)
        env["PKG_CONFIG_PATH"] = f"{yang_prefix}/lib/pkgconfig:{yang_prefix}/lib/x86_64-linux-gnu/pkgconfig"
        env["LDFLAGS"] = f"-L{yang_prefix}/lib -L{yang_prefix}/lib/x86_64-linux-gnu -Wl,-rpath,{yang_prefix}/lib -Wl,-rpath,{yang_prefix}/lib/x86_64-linux-gnu"
        env["LIBS"] = "-lyang"
        commands.append(["./bootstrap.sh"])
        config_dir = str(prefix / "etc") if native_local else "/etc/netvuln/frr"
        state_dir = str(prefix / "var/run") if native_local else "/var/run/frr"
        user = pwd.getpwuid(os.geteuid()).pw_name if native_local else "root"
        group = grp.getgrgid(os.getegid()).gr_name if native_local else "root"
        configure += [f"--sysconfdir={config_dir}", f"--localstatedir={state_dir}", f"--enable-user={user}", f"--enable-group={group}", "--disable-doc", "--disable-snmp", "--disable-zeromq"]
    elif product == "nginx":
        configure += ["--with-http_ssl_module", "--with-http_v2_module", "--with-stream", "--with-stream_ssl_module"]
    elif product == "apache":
        commands.append(["./buildconf", "--with-apr=/usr/bin/apr-1-config"])
        configure += ["--with-apr=/usr/bin/apr-1-config", "--with-apr-util=/usr/bin/apu-1-config", "--enable-so", "--enable-ssl", "--enable-proxy", "--enable-proxy-http", "--enable-rewrite", "--with-mpm=event"]
    elif product == "bind":
        configure += ["--without-gssapi", "--disable-doh", "--disable-linux-caps"]
    elif product == "openvpn":
        configure += ["--disable-dco"]
    elif product == "openssh":
        configure += [f"--sysconfdir={prefix / 'etc' if native_local else '/etc/netvuln/openssh'}", f"--with-privsep-path={prefix / 'empty' if native_local else '/run/sshd'}", "--with-pam"]
    elif product == "haproxy":
        commands += [["make", f"-j{jobs}", "TARGET=linux-glibc", "USE_OPENSSL=1", "USE_ZLIB=1", "USE_PCRE2=1"], ["make", "install", f"PREFIX={prefix}"]]
    elif product == "dnsmasq":
        commands += [["make", f"-j{jobs}", "COPTS=-DHAVE_DNSSEC"], ["make", "install", f"PREFIX={prefix}"]]
    if product not in {"haproxy", "dnsmasq"}:
        commands += [configure, ["make", f"-j{jobs}"], ["make", "install"]]
    for command in commands:
        run(command, cwd=source, env=env)
    result = {
        "schema_version": 1, "device_id": target["device_id"], "product_id": product,
        "expected_version": version, "source_sha256": lock["sources"][source_id]["sha256"],
        "platform": observed_platform, "validation_environment": "native_local" if native_local else "aws_baseline_build",
        "commands": commands,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        **probe_binary(product, version, prefix),
    }
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / "build.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--cache", type=Path, default=Path("/var/cache/netvuln/sources"))
    parser.add_argument("--work", type=Path, default=Path("/var/tmp/netvuln-build"))
    parser.add_argument("--prefix-root", type=Path, default=Path("/opt/netvuln/products"))
    parser.add_argument("--jobs", type=int, default=2, choices=range(1, 9))
    parser.add_argument("--native-local", action="store_true", help="Local Ubuntu 22.04/24.04 installation; requires a private prefix under /tmp or this checkout")
    args = parser.parse_args()
    if args.native_local:
        prefix = args.prefix_root.resolve()
        if not any(prefix.is_relative_to(root) for root in (Path('/tmp'), ROOT.parents[1])):
            parser.error("Native local installation requires --prefix-root under /tmp or this checkout")
    manifest = load_manifest(args.manifest)
    result = build_target(target_by_id(manifest, args.device), manifest, load_lock(manifest, args.lock), args.cache, args.work, args.prefix_root, args.jobs, native_local=args.native_local)
    print("NETVULN_BUILD_RESULT=" + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
