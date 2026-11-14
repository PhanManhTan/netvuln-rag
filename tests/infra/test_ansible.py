from infra.aws.ansible_control import inventory
from infra.aws.catalog import load_manifest
from infra.aws.bootstrap import build_required

import json

import pytest


def test_ansible_uses_registered_private_addresses_and_pinned_host_trust():
    manifest = load_manifest()
    group = inventory(manifest, "/private/control-key", "/private/known_hosts", "/runs/test")["all"]["children"]["netvuln_targets"]
    assert {identity: row["ansible_host"] for identity, row in group["hosts"].items()} == {row["device_id"]: row["ip"] for row in manifest["targets"]}
    assert group["vars"]["ansible_user"] == "netvulnadmin"
    assert "StrictHostKeyChecking=yes" in group["vars"]["ansible_ssh_common_args"]
    assert "UserKnownHostsFile=/private/known_hosts" in group["vars"]["ansible_ssh_common_args"]
    assert "nftables" in group["vars"]["netvuln_build_packages"]


@pytest.mark.parametrize("condition, expected", [("unchanged", False), ("missing", True), ("source", True), ("binary", True), ("version", True)])
def test_repeated_install_skips_build_only_when_the_actual_binary_matches_the_lock(tmp_path, monkeypatch, condition, expected):
    target = {"product_id": "openssh", "version": "9.6p1"}
    if condition != "missing":
        (tmp_path / "build.json").write_text(json.dumps({"source_sha256": "a" * 64, "binary_sha256": "b" * 64}))
    def probe(*args):
        if condition == "version":
            raise ValueError("Binary version mismatch")
        return {"binary_sha256": ("c" if condition == "binary" else "b") * 64}
    monkeypatch.setattr("infra.aws.bootstrap.probe_binary", probe)
    assert build_required(target, tmp_path, ("c" if condition == "source" else "a") * 64) is expected
