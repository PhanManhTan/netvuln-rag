import copy
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

import pytest

from infra.aws.build import binary_spec, extract_source, probe_binary
from infra.aws.catalog import ROOT, load_lock, load_manifest
from infra.aws.deploy import deployment_plan
from infra.aws.render import render_all
from infra.aws.sources import sha256
from infra.aws.package import deployment_files


def test_full_matrix_matches_the_proposals_fixed_versions():
    manifest = load_manifest()
    text = (ROOT.parents[1] / "proposal/question-plan.md").read_text()
    expected = set(re.findall(r"\b([A-Z]+-[AB]) / ([0-9][0-9A-Za-z.]*)", text.split("## Chuẩn bị câu hỏi")[0]))
    assert {(row["device_id"], row["version"]) for row in manifest["targets"]} == expected
    assert len(expected) == 16
    assert len(load_lock(manifest)["sources"]) == 17


def test_frr_version_probe_accepts_real_daemon_banner_and_rejects_wrong_version(tmp_path, monkeypatch):
    from types import SimpleNamespace
    binary, _, _ = binary_spec("frr", tmp_path)
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"fixture ELF")
    monkeypatch.setattr("infra.aws.build.subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="bgpd version 8.5.2\nCopyright", stderr=""))
    assert probe_binary("frr", "8.5.2", tmp_path)["version"] == "8.5.2"
    with pytest.raises(ValueError, match="mismatch"):
        probe_binary("frr", "9.0.1", tmp_path)


@pytest.mark.parametrize("mutation", ["missing", "duplicate_ip", "unknown_peer", "subnet", "source", "overlap"])
def test_invalid_inventory_fails_before_deployment(tmp_path, mutation):
    manifest = copy.deepcopy(load_manifest())
    if mutation == "missing":
        manifest["targets"].pop()
    elif mutation == "duplicate_ip":
        manifest["targets"][1]["ip"] = manifest["targets"][0]["ip"]
    elif mutation == "unknown_peer":
        manifest["targets"][0]["peer"] = "UNKNOWN-A"
    elif mutation == "subnet":
        manifest["targets"][0]["ip"] = "192.168.1.1"
    elif mutation == "source":
        manifest["sources"][0]["url"] = "http://example.com/source.tar.gz"
    elif mutation == "overlap":
        manifest["network"]["service_a_cidr"] = manifest["network"]["client_a_cidr"]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        load_manifest(path)


def test_source_extraction_rejects_links_and_paths_escaping_build_directory(tmp_path):
    for index, (name, link) in enumerate((("../../outside", None), ("root/link", "../../outside"))):
        cache = tmp_path / str(index)
        cache.mkdir()
        path = cache / "test.tar"
        with tarfile.open(path, "w") as archive:
            member = tarfile.TarInfo(name)
            if link:
                member.type, member.linkname = tarfile.SYMTYPE, link
                archive.addfile(member)
            else:
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        with pytest.raises(ValueError, match="Unsafe"):
            extract_source({"source_id": "test", "archive_root": "root"}, {"sha256": sha256(path), "size_bytes": path.stat().st_size}, cache, tmp_path / "work")
    assert not (tmp_path / "outside").exists()


def test_rendered_fleet_covers_all_versions_and_waits_for_all_nodes(tmp_path):
    manifest = load_manifest()
    render_all(tmp_path, manifest)
    root = json.loads((tmp_path / "root.template.json").read_text())
    target = json.loads((tmp_path / "target.template.json").read_text())
    child_nodes = [value for value in root["Resources"].values() if value["Type"] == "AWS::CloudFormation::Stack" and "DeviceId" in value["Properties"].get("Parameters", {})]
    assert {node["Properties"]["Parameters"]["DeviceId"] for node in child_nodes} == {row["device_id"] for row in manifest["targets"]}
    for row in manifest["targets"]:
        logical = row["device_id"].replace("-", "")
        assert root["Resources"][logical]["Properties"]["Parameters"]["DeviceKey"] == logical
        assert target["Mappings"]["Targets"][logical]["Version"] == row["version"]
        assert logical in root["Resources"]["FleetReadiness"]["DependsOn"]
    assert target["Resources"]["Node"]["CreationPolicy"]["ResourceSignal"]["Timeout"] == "PT120M"
    assert target["Resources"]["Node"]["Properties"]["SourceDestCheck"] == {"Fn::If": ["IsRouter", False, True]}
    assert root["Resources"]["ClientAToServiceA"]["Properties"]["InstanceId"] == {"Fn::GetAtt": ["FRRA", "Outputs.InstanceId"]}
    assert root["Resources"]["ServiceAToClientA"]["Properties"]["InstanceId"] == {"Fn::GetAtt": ["FRRA", "Outputs.InstanceId"]}


def test_bootstrap_userdata_is_valid_shell_and_uses_arns_not_secret_values(tmp_path):
    render_all(tmp_path, load_manifest())
    values = {"ArtifactsBucket": "example-artifacts", "ArtifactsPrefix": "netvuln/run-1", "BundleSha256": "a" * 64,
              "AWS::Region": "ap-southeast-1", "AWS::StackName": "nested-stack", "FleetId": "run-1",
              "DeviceId": "NGINX-A", "DeviceSecretArn": "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:device",
              "CollectorIp": "10.53.0.10", "ReadSecretArn": "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:reader",
              "DeviceSecretsJson": '{"NGINX-A":"arn:example"}'}
    for name in ("management", "target"):
        template = json.loads((tmp_path / f"{name}.template.json").read_text())
        source = template["Resources"]["Node"]["Properties"]["UserData"]["Fn::Base64"]["Fn::Sub"]
        rendered = re.sub(r"\$\{([^}]+)\}", lambda match: values[match.group(1)], source)
        path = tmp_path / f"{name}.sh"
        path.write_text(rendered)
        subprocess.run(["bash", "-n", str(path)], check=True)
        assert len(rendered.encode()) < 16384
        assert "sha256sum --check --strict" in rendered
        assert "install -d -m 0755 /opt/netvuln /opt/netvuln/repo" in rendered
        assert "--status \"$status\"" in rendered
        raw_config = rendered.split("<<'NETVULN_CONFIG'\n", 1)[1].split("\nNETVULN_CONFIG", 1)[0]
        assert json.loads(raw_config)["kind"] == name


def test_deployment_plan_verifies_artifacts_without_an_aws_sdk_or_credentials(tmp_path, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "boto3", None)
    bundle = tmp_path / "bundle.tar.gz"
    bundle.write_bytes(b"fixture bundle")
    templates = tmp_path / "templates"
    templates.mkdir()
    root = templates / "root.template.json"
    root.write_text("{}")
    record = {"bundle_sha256": sha256(bundle), "templates": {root.name: sha256(root)}, "scope": "fixture", "pending": ["deployment"]}
    (tmp_path / "package.json").write_text(json.dumps(record))
    plan = deployment_plan(tmp_path, "test-artifacts", "ap-southeast-1", "ami-0123456789abcdef0", "test-fleet")
    assert plan["expected_targets"] == 16
    assert plan["mode"] == "create_new_stack_only"
    bundle.write_bytes(b"changed")
    with pytest.raises(ValueError, match="integrity"):
        deployment_plan(tmp_path, "test-artifacts", "ap-southeast-1", "ami-0123456789abcdef0", "test-fleet")


def test_artifact_stack_is_private_and_retains_audit_evidence(tmp_path):
    render_all(tmp_path, load_manifest())
    template = json.loads((tmp_path / "artifacts.template.json").read_text())
    bucket = template["Resources"]["Bucket"]
    assert bucket["DeletionPolicy"] == bucket["UpdateReplacePolicy"] == "Retain"
    assert all(bucket["Properties"]["PublicAccessBlockConfiguration"].values())
    assert bucket["Properties"]["BucketEncryption"]["ServerSideEncryptionConfiguration"]


def test_deployment_allowlist_excludes_pilot_gold_and_credentials(tmp_path):
    paths = ("infra/aws/experiment.json", "infra/aws/audit/pilot-results.json", "infra/aws/agent.json",
             "collector/private.json", "infra/ansible/site.yml", "collector/facts.py", ".env")
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture")
    names = {name for _, name in deployment_files(tmp_path)}
    assert names == {"infra/aws/experiment.json", "infra/ansible/site.yml", "collector/facts.py"}
