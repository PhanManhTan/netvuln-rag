from copy import deepcopy
from datetime import datetime, timezone

import pytest

from evaluation.pilot import accept_ansible_snapshot, expected_case


def inputs():
    snapshot = {"schema_version": 1, "device_id": "OPENSSH-A", "collected_at": datetime.now(timezone.utc).isoformat(),
                "boot_id": "fixture", "management_ip": "127.0.0.1", "collection_status": "collected", "os": {"ID": "ubuntu"},
                "software": [{"product_id": "openssh", "component": "sshd", "version": "9.6p1", "binary_sha256": "b" * 64,
                              "running": True, "configuration": {"logingracetime": "120"},
                              "evidence": {"source_sha256": "a" * 64, "process_uid": 0}}], "network": {"libc": "glibc 2.39"}}
    official = {"cveMetadata": {"cveId": "CVE-2024-6387", "state": "PUBLISHED"},
                "containers": {"cna": {"affected": [{"packageName": "OpenSSH", "versions": [{"version": "8.5p1", "lessThanOrEqual": "9.7p1", "status": "affected"}]}]}}}
    return snapshot, official


def test_pilot_label_requires_official_source_and_real_deployment_conditions():
    snapshot, official = inputs()
    expected = expected_case(snapshot, official, "a" * 64)
    assert expected["verdict"] == "affected"
    assert expected["version"] == "9.6p1"
    assert expected["review_status"] == "draft_source_backed_not_human_approved"
    assert expected["cve"] == "CVE-2024-6387"


@pytest.mark.parametrize("change", ["version", "source", "not_running", "nonroot", "libc", "grace_time", "rejected", "source_range"])
def test_pilot_refuses_to_invent_ground_truth_when_evidence_differs(change):
    snapshot, official = inputs()
    software = snapshot["software"][0]
    if change == "version":
        software["version"] = "9.8p1"
    elif change == "source":
        software["evidence"]["source_sha256"] = "c" * 64
    elif change == "not_running":
        software["running"] = False
    elif change == "nonroot":
        software["evidence"]["process_uid"] = 1000
    elif change == "libc":
        snapshot["network"]["libc"] = "musl"
    elif change == "grace_time":
        software["configuration"]["logingracetime"] = "0"
    elif change == "rejected":
        official["cveMetadata"]["state"] = "REJECTED"
    elif change == "source_range":
        official["containers"]["cna"]["affected"][0]["versions"][0]["lessThanOrEqual"] = "9.5p1"
    with pytest.raises(ValueError):
        expected_case(snapshot, official, "a" * 64)


def test_agentless_pilot_accepts_real_facts_without_starting_a_collector_daemon(tmp_path):
    snapshot, _ = inputs()
    snapshot["software"][0]["evidence"]["scope"] = "experiment_target"
    snapshot["network"]["collection_transport"] = "ansible_local"
    frozen = accept_ansible_snapshot(snapshot, tmp_path)
    assert frozen["complete"] and frozen["ready_devices"] == 1
    assert len(frozen["snapshots"][0]["snapshot_id"]) == 64
    snapshot["software"][0]["running"] = False
    with pytest.raises(ValueError, match="incomplete"):
        accept_ansible_snapshot(snapshot, tmp_path)


def test_default_pilot_refuses_to_mislabel_legacy_agent_data_as_ansible(tmp_path):
    snapshot, _ = inputs()
    with pytest.raises(ValueError, match="Ansible"):
        accept_ansible_snapshot(snapshot, tmp_path)
