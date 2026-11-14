import json
from types import SimpleNamespace

import pytest

from infra.aws.catalog import load_manifest, target_by_id
from infra.aws.network_policy import forwarding_delta, ingress_rules, isolation_cases, probe_isolation, router_evidence, router_rules, service_flows
from infra.aws.render import render_all


def permitted(rules, source_ip, protocol, port):
    return any(row["CidrIp"] == source_ip + "/32" and row["IpProtocol"] == protocol
               and row["FromPort"] <= port <= row["ToPort"] for row in rules)


def test_declared_services_and_management_work_but_forbidden_pairs_have_no_ingress():
    manifest = load_manifest()
    for target in manifest["targets"]:
        rules = ingress_rules(target, manifest)
        assert all(row["CidrIp"].endswith("/32") and row["IpProtocol"] in {"tcp", "udp"} for row in rules)
        assert permitted(rules, manifest["network"]["collector_ip"], "tcp", 22)
        for case in isolation_cases(target, manifest):
            if case["destination"] == "MGMT":
                continue  # Management has no inbound rules at all, checked below.
            destination = target_by_id(manifest, case["destination"])
            assert not permitted(ingress_rules(destination, manifest), target["ip"], "tcp", case["port"])
    for flow in service_flows(manifest):
        target = target_by_id(manifest, flow["destination"])
        assert permitted(ingress_rules(target, manifest), flow["source_ip"], flow["protocol"], flow["port"])
        if flow["router"]:
            router = target_by_id(manifest, flow["router"])
            rules = ingress_rules(router, manifest)
            assert permitted(rules, flow["source_ip"], flow["protocol"], flow["port"])
            assert permitted(rules, flow["destination_ip"], flow["protocol"], 40000)


def test_generated_nodes_use_individual_groups_and_agentless_control_ami(tmp_path):
    manifest = load_manifest()
    render_all(tmp_path, manifest)
    network = json.loads((tmp_path / "network.template.json").read_text())
    root = json.loads((tmp_path / "root.template.json").read_text())
    assert network["Resources"]["ManagementGroup"]["Properties"]["SecurityGroupIngress"] == []
    assert "TargetGroup" not in network["Resources"]
    assert "ControlAmiId" in root["Parameters"]
    assert root["Resources"]["Management"]["Properties"]["Parameters"]["AmiId"] == {"Ref": "ControlAmiId"}
    assert "ansible_control" in root["Resources"]["FleetReadiness"]["Properties"]["Parameters"]["commands"][0]
    assert not any(row["Type"] == "AWS::SecretsManager::Secret" for row in root["Resources"].values())
    for target in manifest["targets"]:
        logical = target["device_id"].replace("-", "")
        node = root["Resources"][logical]
        assert node["DependsOn"] == "Management"
        assert node["Properties"]["Parameters"]["SecurityGroupId"] == {"Fn::GetAtt": ["Network", f"Outputs.{logical}SecurityGroup"]}


def test_router_default_denies_and_only_forwards_its_registered_flows():
    manifest = load_manifest()
    for identity in ("FRR-A", "FRR-B"):
        rules = router_rules(target_by_id(manifest, identity), manifest)
        assert "policy drop" in rules
        assert "ct state established,related counter accept" in rules
        for flow in service_flows(manifest):
            assert (f'comment "{flow["id"]}"' in rules) == (flow["router"] == identity)


@pytest.mark.parametrize("error, passed", [(TimeoutError(), True), (ConnectionRefusedError(), False), (OSError("unreachable"), False)])
def test_negative_probe_requires_filtering_not_a_dead_listener(monkeypatch, error, passed):
    manifest = load_manifest()
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr("infra.aws.network_policy.socket.create_connection", fail)
    rows = probe_isolation(target_by_id(manifest, "OPENSSH-A"), manifest)
    assert rows and all(row["passed"] is passed for row in rows)


@pytest.mark.parametrize("packets,status", [(0, "failed"), (1, "passed")])
def test_router_evidence_requires_packets_for_the_expected_client_flow(monkeypatch, packets, status):
    manifest = load_manifest()
    raw = {"nftables": [{"rule": {"comment": "client-A-web", "expr": [{"counter": {"packets": packets, "bytes": 60}}]}}]}
    monkeypatch.setattr("infra.aws.network_policy.subprocess.run", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(raw)))
    assert router_evidence(target_by_id(manifest, "FRR-A"), manifest)["status"] == status


@pytest.mark.parametrize("before,after,status", [(5, 5, "failed"), (5, 6, "passed"), (5, 1, "failed"), (None, 8, "failed")])
def test_old_or_reset_router_counters_do_not_prove_the_current_run_crossed_the_router(before, after, status):
    def row(packets):
        return {"device_id": "FRR-A", "counters": {"client-A-web": packets}}
    assert forwarding_delta("FRR-A", row(before), row(after))["status"] == status
