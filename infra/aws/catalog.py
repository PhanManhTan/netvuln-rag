"""Read and validate the deployment matrix without importing the RAG runtime."""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "experiment.json"
LOCK = ROOT / "sources.lock.json"


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported experiment schema")
    targets = manifest["targets"]
    if len(targets) != 16 or Counter(row["product_id"] for row in targets) != {
        product: 2 for product in ("frr", "nginx", "apache", "bind", "openvpn", "openssh", "haproxy", "dnsmasq")
    }:
        raise ValueError("The full experiment requires eight products and exactly sixteen targets")
    for field in ("device_id", "ip"):
        if len({row[field] for row in targets}) != len(targets):
            raise ValueError(f"Duplicate target {field}")
    if len({(row["product_id"], row["version"]) for row in targets}) != 16:
        raise ValueError("Test versions must be distinct for each product")
    identities = {row["device_id"] for row in targets}
    source_ids = {row["source_id"] for row in manifest["sources"]}
    if len(source_ids) != len(manifest["sources"]):
        raise ValueError("Duplicate source identity")
    network = manifest["network"]
    vpc = ip_network(network["vpc_cidr"])
    subnets = {key.removesuffix("_cidr"): ip_network(value) for key, value in network.items() if key.endswith("_cidr") and key != "vpc_cidr"}
    if any(not subnet.subnet_of(vpc) for subnet in subnets.values()):
        raise ValueError("Subnets must belong to the experiment VPC")
    if any(left.overlaps(right) for index, left in enumerate(subnets.values()) for right in list(subnets.values())[index + 1:]):
        raise ValueError("Experiment subnets overlap")
    if ip_address(network["collector_ip"]) not in subnets["management"]:
        raise ValueError("Collector IP must be in the management subnet")
    for row in targets:
        if not re.fullmatch(r"[A-Z][A-Z0-9]*-[AB]", row["device_id"]):
            raise ValueError("Invalid device identity")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z]+)+", row["version"]):
            raise ValueError("Invalid test version")
        if ip_address(row["ip"]) not in subnets[row["subnet"]]:
            raise ValueError(f"Target {row['device_id']} IP is outside its subnet")
        if row.get("peer") and row["peer"] not in identities:
            raise ValueError("Unknown target peer")
        if not 1 <= row["port"] <= 65535:
            raise ValueError("Invalid target port")
        if f"{row['product_id']}-{row['version']}" not in source_ids:
            raise ValueError("Missing source for target")
    for source in manifest["sources"]:
        url = urlsplit(source["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("Sources must use credential-free HTTPS URLs")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]+", source["source_id"]):
            raise ValueError("Invalid source identity")
        if "/" in source["archive_root"] or source["archive_root"] in {"", ".", ".."}:
            raise ValueError("Invalid archive root")
    return manifest


def load_lock(manifest: dict[str, Any], path: Path = LOCK) -> dict[str, Any]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    sources = lock["sources"]
    if lock.get("schema_version") != 1 or set(sources) != {row["source_id"] for row in manifest["sources"]}:
        raise ValueError("Source lock does not cover the manifest")
    for source in manifest["sources"]:
        entry = sources[source["source_id"]]
        if entry["url"] != source["url"] or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Source lock URL/hash differs from manifest")
        if not isinstance(entry["size_bytes"], int) or entry["size_bytes"] < 1:
            raise ValueError("Source lock has an invalid size")
    return lock


def target_by_id(manifest: dict[str, Any], device_id: str) -> dict[str, Any]:
    for target in manifest["targets"]:
        if target["device_id"] == device_id:
            return target
    raise ValueError(f"Unknown experiment target: {device_id}")
