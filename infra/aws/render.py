"""Generate reviewable CloudFormation JSON templates from the pinned matrix.

Rendering writes local files only. It never creates AWS resources.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from infra.aws.catalog import ROOT, load_lock, load_manifest
from infra.aws.network_policy import ingress_rules


def ref(name: str) -> dict:
    return {"Ref": name}


def attr(name: str, value: str) -> dict:
    return {"Fn::GetAtt": [name, value]}


def sub(text: str) -> dict:
    return {"Fn::Sub": text}


def resource(kind: str, properties: dict, **extra) -> dict:
    return {"Type": kind, "Properties": properties, **extra}


def template(description: str) -> dict:
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": description, "Parameters": {}, "Resources": {}, "Outputs": {}}


def artifacts_template() -> dict:
    result = template("NetVuln private deployment artifacts and audit evidence; retained on stack deletion")
    result["Resources"]["Bucket"] = resource("AWS::S3::Bucket", {
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
        "VersioningConfiguration": {"Status": "Enabled"},
    }, DeletionPolicy="Retain", UpdateReplacePolicy="Retain")
    result["Resources"]["BucketPolicy"] = resource("AWS::S3::BucketPolicy", {"Bucket": ref("Bucket"), "PolicyDocument": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [attr("Bucket", "Arn"), sub("${Bucket.Arn}/*")], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}],
    }})
    result["Outputs"]["BucketName"] = {"Value": ref("Bucket")}
    return result


def network_template(manifest: dict) -> dict:
    result = template("NetVuln private experiment network, symmetric FRR routes supplied by root stack")
    resources, outputs = result["Resources"], result["Outputs"]
    resources["Vpc"] = resource("AWS::EC2::VPC", {"CidrBlock": manifest["network"]["vpc_cidr"], "EnableDnsSupport": True, "EnableDnsHostnames": True})
    resources["Gateway"] = resource("AWS::EC2::InternetGateway", {})
    resources["GatewayAttachment"] = resource("AWS::EC2::VPCGatewayAttachment", {"VpcId": ref("Vpc"), "InternetGatewayId": ref("Gateway")})
    subnets = {key.removesuffix("_cidr"): value for key, value in manifest["network"].items() if key.endswith("_cidr") and key != "vpc_cidr"}
    subnets["egress"] = "10.53.254.0/24"
    for name, cidr in subnets.items():
        label = "".join(part.title() for part in name.split("_"))
        resources[label + "Subnet"] = resource("AWS::EC2::Subnet", {"VpcId": ref("Vpc"), "CidrBlock": cidr, "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "MapPublicIpOnLaunch": False})
        resources[label + "RouteTable"] = resource("AWS::EC2::RouteTable", {"VpcId": ref("Vpc")})
        resources[label + "Association"] = resource("AWS::EC2::SubnetRouteTableAssociation", {"SubnetId": ref(label + "Subnet"), "RouteTableId": ref(label + "RouteTable")})
        resources[label + "DefaultRoute"] = resource("AWS::EC2::Route", {
            "RouteTableId": ref(label + "RouteTable"), "DestinationCidrBlock": "0.0.0.0/0",
            **({"GatewayId": ref("Gateway")} if name == "egress" else {"NatGatewayId": ref("Nat")}),
        }, **({"DependsOn": "GatewayAttachment"} if name == "egress" else {}))
        outputs[label + "SubnetId"] = {"Value": ref(label + "Subnet")}
        outputs[label + "RouteTableId"] = {"Value": ref(label + "RouteTable")}
    resources["NatAddress"] = resource("AWS::EC2::EIP", {"Domain": "vpc"}, DependsOn="GatewayAttachment")
    resources["Nat"] = resource("AWS::EC2::NatGateway", {"AllocationId": attr("NatAddress", "AllocationId"), "SubnetId": ref("EgressSubnet")}, DependsOn="EgressDefaultRoute")
    for target in manifest["targets"]:
        logical = target["device_id"].replace("-", "")
        resources[logical + "Group"] = resource("AWS::EC2::SecurityGroup", {
            "GroupDescription": target["device_id"] + " declared service flows and management SSH",
            "VpcId": ref("Vpc"), "SecurityGroupIngress": ingress_rules(target, manifest),
            "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0", "Description": "Bootstrap egress; destination ingress and router firewall enforce workload isolation"}],
        })
        outputs[logical + "SecurityGroup"] = {"Value": ref(logical + "Group")}
    resources["ManagementGroup"] = resource("AWS::EC2::SecurityGroup", {
        "GroupDescription": "Ansible control node; no inbound access, management uses SSM",
        "VpcId": ref("Vpc"), "SecurityGroupIngress": [],
        "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
    })
    resources["S3Endpoint"] = resource("AWS::EC2::VPCEndpoint", {
        "VpcId": ref("Vpc"), "VpcEndpointType": "Gateway", "ServiceName": sub("com.amazonaws.${AWS::Region}.s3"),
        "RouteTableIds": [ref("".join(part.title() for part in name.split("_")) + "RouteTable") for name in subnets if name != "egress"],
    })
    outputs.update(VpcId={"Value": ref("Vpc")}, ManagementSecurityGroup={"Value": ref("ManagementGroup")})
    return result


def common_parameters() -> dict:
    return {
        "ArtifactsBucket": {"Type": "String", "AllowedPattern": "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"},
        "ArtifactsPrefix": {"Type": "String", "AllowedPattern": "[a-zA-Z0-9][a-zA-Z0-9/_-]*"},
        "BundleSha256": {"Type": "String", "AllowedPattern": "[a-f0-9]{64}"},
        "AmiId": {"Type": "AWS::EC2::Image::Id"},
        "InstanceType": {"Type": "String", "Default": "t3.medium", "AllowedValues": ["t3.small", "t3.medium", "t3.large", "t3.xlarge", "m6i.large", "m6i.xlarge"]},
        "SubnetId": {"Type": "AWS::EC2::Subnet::Id"}, "SecurityGroupId": {"Type": "AWS::EC2::SecurityGroup::Id"},
        "FleetId": {"Type": "String", "AllowedPattern": "[a-zA-Z][a-zA-Z0-9-]{0,99}"},
    }


def user_data(kind: str) -> dict:
    settings = {
        "kind": kind, "artifacts_bucket": "${ArtifactsBucket}", "artifacts_prefix": "${ArtifactsPrefix}",
        "region": "${AWS::Region}", "fleet_id": "${FleetId}",
    }
    if kind == "target":
        settings.update(device_id="${DeviceId}")
    config_json = json.dumps(settings)
    script = """#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
export AWS_DEFAULT_REGION='${AWS::Region}'
signal_result() {
  result=$?
  trap - EXIT
  if command -v aws >/dev/null; then
    status=FAILURE
    if [ "$result" -eq 0 ]; then status=SUCCESS; fi
    aws cloudformation signal-resource --stack-name '${AWS::StackName}' --logical-resource-id Node --status "$status" || exit 1
  fi
  exit "$result"
}
trap signal_result EXIT
apt-get update
apt-get install -y --no-install-recommends awscli ca-certificates python3 python3-venv
install -d -m 0755 /opt/netvuln /opt/netvuln/repo
mkdir -p /etc/netvuln
aws s3 cp 's3://${ArtifactsBucket}/${ArtifactsPrefix}/bundle.tar.gz' /opt/netvuln/bundle.tar.gz --only-show-errors
printf '%s  %s\\n' '${BundleSha256}' /opt/netvuln/bundle.tar.gz | sha256sum --check --strict
tar --extract --gzip --file /opt/netvuln/bundle.tar.gz --directory /opt/netvuln/repo --no-same-owner
find /opt/netvuln/repo -type d -exec chmod 0755 {} +
cat > /etc/netvuln/bootstrap.json <<'NETVULN_CONFIG'
""" + config_json + """
NETVULN_CONFIG
cd /opt/netvuln/repo
python3 -m infra.aws.bootstrap --config /etc/netvuln/bootstrap.json
"""
    return {"Fn::Base64": sub(script)}


def node_template(kind: str, manifest: dict) -> dict:
    result = template(f"NetVuln {kind}: prepare the Ansible control node or SSH target, then signal base readiness")
    parameters = result["Parameters"] = common_parameters()
    resources, outputs = result["Resources"], result["Outputs"]
    if kind == "target":
        parameters.update(DeviceId={"Type": "String", "AllowedValues": [row["device_id"] for row in manifest["targets"]]},
                          DeviceKey={"Type": "String", "AllowedValues": [row["device_id"].replace("-", "") for row in manifest["targets"]]})
        settings_map = {row["device_id"].replace("-", ""): {"Ip": row["ip"], "Product": row["product_id"], "Version": row["version"]} for row in manifest["targets"]}
        result["Mappings"] = {"Targets": settings_map}
        key = ref("DeviceKey")
        mapping = lambda field: {"Fn::FindInMap": ["Targets", key, field]}
        result["Conditions"] = {"IsRouter": {"Fn::Equals": [mapping("Product"), "frr"]}}
        private_ip, source_dest_check = mapping("Ip"), {"Fn::If": ["IsRouter", False, True]}
        get_paths = ["bundle.tar.gz", "ssh-known-hosts", sub("pki/${DeviceId}.tar.gz")]
    else:
        private_ip, source_dest_check = manifest["network"]["collector_ip"], True
        get_paths = ["bundle.tar.gz"]
    statements = [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [sub("arn:${AWS::Partition}:s3:::${ArtifactsBucket}/${ArtifactsPrefix}/" + (path if isinstance(path, str) else path["Fn::Sub"])) for path in get_paths]},
        {"Effect": "Allow", "Action": ["cloudformation:SignalResource"], "Resource": ref("AWS::StackId")},
    ]
    if kind == "management":
        statements += [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [sub("arn:${AWS::Partition}:s3:::${ArtifactsBucket}/${ArtifactsPrefix}/ssh-known-hosts"), sub("arn:${AWS::Partition}:s3:::${ArtifactsBucket}/${ArtifactsPrefix}/pki/*"), sub("arn:${AWS::Partition}:s3:::${ArtifactsBucket}/${ArtifactsPrefix}/runs/*")]},
        ]
    resources["Role"] = resource("AWS::IAM::Role", {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": ["ec2.amazonaws.com"]}, "Action": ["sts:AssumeRole"]}]},
        "ManagedPolicyArns": [sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")],
        "Policies": [{"PolicyName": "ExperimentBootstrap", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}],
    })
    resources["Profile"] = resource("AWS::IAM::InstanceProfile", {"Roles": [ref("Role")]})
    tags = [{"Key": "NetVulnFleet", "Value": ref("FleetId")}, {"Key": "NetVulnRole", "Value": kind}]
    if kind == "target":
        tags += [{"Key": "Name", "Value": ref("DeviceId")}, {"Key": "NetVulnDevice", "Value": ref("DeviceId")}, {"Key": "NetVulnProduct", "Value": mapping("Product")}, {"Key": "NetVulnVersion", "Value": mapping("Version")}]
    else:
        tags += [{"Key": "Name", "Value": sub("${FleetId}-MGMT")}]
    resources["Node"] = resource("AWS::EC2::Instance", {
        "ImageId": ref("AmiId"), "InstanceType": ref("InstanceType"), "IamInstanceProfile": ref("Profile"),
        "SubnetId": ref("SubnetId"), "SecurityGroupIds": [ref("SecurityGroupId")], "PrivateIpAddress": private_ip,
        "SourceDestCheck": source_dest_check, "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 30, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}],
        "Tags": tags, "UserData": user_data(kind),
    }, CreationPolicy={"ResourceSignal": {"Count": 1, "Timeout": "PT120M"}})
    outputs.update(InstanceId={"Value": ref("Node")}, PrivateIp={"Value": attr("Node", "PrivateIp")})
    return result


def root_template(manifest: dict) -> dict:
    result = template("Complete NetVuln sixteen-version experiment: CloudFormation infrastructure, agentless Ansible install/facts and functional readiness")
    result["Parameters"] = {
        key: value for key, value in common_parameters().items() if key in {"ArtifactsBucket", "ArtifactsPrefix", "BundleSha256", "FleetId"}
    }
    result["Parameters"].update(AmiId={"Type": "AWS::EC2::Image::Id", "Description": "Pinned Canonical Ubuntu Server 22.04 x86_64 AMI in this Region"},
                                ControlAmiId={"Type": "AWS::EC2::Image::Id", "Description": "Pinned Canonical Ubuntu Server 24.04 x86_64 AMI for Ansible/Python 3.12 control node"},
                                TargetInstanceType=common_parameters()["InstanceType"], ManagementInstanceType={**common_parameters()["InstanceType"], "Default": "t3.large"})
    resources, outputs = result["Resources"], result["Outputs"]
    def nested(name: str, parameters: dict, **extra) -> dict:
        return resource("AWS::CloudFormation::Stack", {"TemplateURL": sub("https://${ArtifactsBucket}.s3.${AWS::Region}.${AWS::URLSuffix}/${ArtifactsPrefix}/templates/" + name + ".template.json"), "Parameters": parameters, "TimeoutInMinutes": 150}, **extra)
    resources["Network"] = nested("network", {})
    base = {key: ref(key) for key in ("ArtifactsBucket", "ArtifactsPrefix", "BundleSha256", "AmiId", "FleetId")}
    resources["Management"] = nested("management", {
        **base, "AmiId": ref("ControlAmiId"), "InstanceType": ref("ManagementInstanceType"), "SubnetId": attr("Network", "Outputs.ManagementSubnetId"),
        "SecurityGroupId": attr("Network", "Outputs.ManagementSecurityGroup"),
    })
    for row in manifest["targets"]:
        logical = row["device_id"].replace("-", "")
        subnet = "".join(part.title() for part in row["subnet"].split("_"))
        resources[logical] = nested("target", {**base, "InstanceType": ref("TargetInstanceType"), "DeviceId": row["device_id"], "DeviceKey": logical,
            "SubnetId": attr("Network", f"Outputs.{subnet}SubnetId"), "SecurityGroupId": attr("Network", f"Outputs.{logical}SecurityGroup"),
        }, DependsOn="Management")
        outputs[logical + "InstanceId"] = {"Value": attr(logical, "Outputs.InstanceId")}
    routes = [
        ("ClientAToServiceA", "ClientA", "service_a_cidr", "FRRA"), ("ServiceAToClientA", "ServiceA", "client_a_cidr", "FRRA"),
        ("ClientBToServiceB", "ClientB", "service_b_cidr", "FRRB"), ("ServiceBToClientB", "ServiceB", "client_b_cidr", "FRRB"),
        ("VpnAToB", "ClientA", "client_b_cidr", "FRRA"), ("VpnBToA", "ClientB", "client_a_cidr", "FRRA"),
    ]
    for name, subnet, destination, router in routes:
        resources[name] = resource("AWS::EC2::Route", {"RouteTableId": attr("Network", f"Outputs.{subnet}RouteTableId"), "DestinationCidrBlock": manifest["network"][destination], "InstanceId": attr(router, "Outputs.InstanceId")})
    resources["FleetReadiness"] = resource("AWS::SSM::Association", {
        "Name": "AWS-RunShellScript", "Targets": [{"Key": "InstanceIds", "Values": [attr("Management", "Outputs.InstanceId")]}],
        "Parameters": {"commands": ["cd /opt/netvuln/repo && /opt/netvuln/venv/bin/python -m infra.aws.ansible_control --config /etc/netvuln/bootstrap.json"], "executionTimeout": ["14400"]},
        "WaitForSuccessTimeoutSeconds": 14400,
    }, DependsOn=[row["device_id"].replace("-", "") for row in manifest["targets"]] + [name for name, *_ in routes])
    outputs.update(ManagementInstanceId={"Value": attr("Management", "Outputs.InstanceId")},
                   FactsPrefix={"Value": sub("s3://${ArtifactsBucket}/${ArtifactsPrefix}/runs/ansible/")},
                   CollectionTransport={"Value": "ansible_ssh_agentless"}, ExpectedTargets={"Value": "16"})
    return result


def render_all(output: Path, manifest: dict) -> list[Path]:
    load_lock(manifest)
    output.mkdir(parents=True, exist_ok=True)
    values = {"artifacts": artifacts_template(), "network": network_template(manifest), "management": node_template("management", manifest),
              "target": node_template("target", manifest), "root": root_template(manifest)}
    files = []
    for name, value in values.items():
        destination = output / f"{name}.template.json"
        destination.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        files.append(destination)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "templates")
    args = parser.parse_args()
    files = render_all(args.output, load_manifest())
    print("Rendered " + ", ".join(path.name for path in files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
