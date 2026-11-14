"""Review a local deployment plan, or explicitly execute a new immutable AWS stack.

Without --execute this command performs no AWS calls. Existing stacks are never
updated: cloud-init runs once, so a new bundle requires a new fleet/stack name.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time

from infra.aws.sources import sha256


AMI_PARAMETER = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
CONTROL_AMI_PARAMETER = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"


def deployment_plan(package: Path, bucket: str | None, region: str, ami_id: str | None, stack_name: str,
                    target_type: str = "t3.medium", management_type: str = "t3.large", control_ami_id: str | None = None) -> dict:
    if bucket is not None and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ValueError("Invalid S3 artifact bucket name")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region) or (ami_id is not None and not re.fullmatch(r"ami-(?:[a-f0-9]{8}|[a-f0-9]{17})", ami_id)):
        raise ValueError("Invalid AWS Region or AMI ID")
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]{0,99}", stack_name):
        raise ValueError("Invalid fleet/stack name")
    record = json.loads((package / "package.json").read_text())
    if sha256(package / "bundle.tar.gz") != record["bundle_sha256"]:
        raise ValueError("Deployment bundle integrity failure")
    for name, digest in record["templates"].items():
        if Path(name).name != name or sha256(package / "templates" / name) != digest:
            raise ValueError("Deployment template integrity failure")
    prefix = f"netvuln/{stack_name}/{record['bundle_sha256']}"
    parameters = {"ArtifactsBucket": bucket, "ArtifactsPrefix": prefix, "BundleSha256": record["bundle_sha256"],
                  "FleetId": stack_name, "AmiId": ami_id, "ControlAmiId": control_ami_id,
                  "TargetInstanceType": target_type, "ManagementInstanceType": management_type}
    return {"schema_version": 1, "stack_name": stack_name, "region": region, "bucket": bucket, "prefix": prefix,
            "bucket_mode": "existing" if bucket else "create_artifacts_stack", "ami_parameter": None if ami_id else AMI_PARAMETER,
            "control_ami_parameter": None if control_ami_id else CONTROL_AMI_PARAMETER,
            "parameters": parameters, "expected_targets": 16, "management_instances": 1, "nat_gateways": 1,
            "public_ingress": False, "mode": "create_new_stack_only", "scope": record["scope"], "pending": record["pending"]}


def execute_plan(plan: dict, package: Path) -> dict:
    import boto3
    from botocore.exceptions import ClientError
    session = boto3.Session(region_name=plan["region"])
    ec2, cfn, s3 = (session.client(service) for service in ("ec2", "cloudformation", "s3"))
    if plan["parameters"]["AmiId"] is None:
        plan["parameters"]["AmiId"] = session.client("ssm").get_parameter(Name=plan["ami_parameter"])["Parameter"]["Value"]
    if plan["parameters"]["ControlAmiId"] is None:
        plan["parameters"]["ControlAmiId"] = session.client("ssm").get_parameter(Name=plan["control_ami_parameter"])["Parameter"]["Value"]
    image = ec2.describe_images(ImageIds=[plan["parameters"]["AmiId"]])["Images"]
    if len(image) != 1 or image[0].get("OwnerId") != "099720109477" or image[0].get("Architecture") != "x86_64" or "ubuntu" not in image[0].get("Name", "").lower() or "22.04" not in image[0].get("Name", ""):
        raise ValueError("AMI must be a Canonical Ubuntu Server 22.04 x86_64 image")
    control_image = ec2.describe_images(ImageIds=[plan["parameters"]["ControlAmiId"]])["Images"]
    if len(control_image) != 1 or control_image[0].get("OwnerId") != "099720109477" or control_image[0].get("Architecture") != "x86_64" or "ubuntu" not in control_image[0].get("Name", "").lower() or "24.04" not in control_image[0].get("Name", ""):
        raise ValueError("Ansible control AMI must be Canonical Ubuntu Server 24.04 x86_64")
    try:
        cfn.describe_stacks(StackName=plan["stack_name"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError" or "does not exist" not in exc.response["Error"]["Message"]:
            raise
    else:
        raise ValueError("Stack already exists. Use a new fleet name for reproducible bootstrap; no in-place updates.")
    if plan["bucket_mode"] == "create_artifacts_stack":
        artifact_stack = plan["stack_name"] + "-artifacts"
        cfn.create_stack(StackName=artifact_stack, TemplateBody=(package / "templates/artifacts.template.json").read_text(),
                         Tags=[{"Key": "NetVulnFleet", "Value": plan["stack_name"]}])
        cfn.get_waiter("stack_create_complete").wait(StackName=artifact_stack, WaiterConfig={"Delay": 5, "MaxAttempts": 180})
        outputs = cfn.describe_stacks(StackName=artifact_stack)["Stacks"][0]["Outputs"]
        plan["bucket"] = next(row["OutputValue"] for row in outputs if row["OutputKey"] == "BucketName")
        plan["parameters"]["ArtifactsBucket"] = plan["bucket"]
        plan["artifact_stack"] = artifact_stack
    bucket_region = s3.get_bucket_location(Bucket=plan["bucket"]).get("LocationConstraint") or "us-east-1"
    if bucket_region == "EU":
        bucket_region = "eu-west-1"
    if bucket_region != plan["region"]:
        raise ValueError("Artifact bucket must be in the same Region as the stack")
    assets = [(package / "bundle.tar.gz", "bundle.tar.gz")]
    assets += [(path, "templates/" + path.name) for path in sorted((package / "templates").glob("*.template.json"))]
    for path, name in assets:
        s3.upload_file(str(path), plan["bucket"], plan["prefix"] + "/" + name, ExtraArgs={"ServerSideEncryption": "AES256"})
    # Validate all child templates as well as root before creating anything billable.
    for _, name in assets[1:]:
        cfn.validate_template(TemplateURL=f"https://{plan['bucket']}.s3.{plan['region']}.amazonaws.com/{plan['prefix']}/{name}")
    root_url = f"https://{plan['bucket']}.s3.{plan['region']}.amazonaws.com/{plan['prefix']}/templates/root.template.json"
    change_set = cfn.create_change_set(StackName=plan["stack_name"], ChangeSetName="netvuln-create", ChangeSetType="CREATE", TemplateURL=root_url,
                                     Parameters=[{"ParameterKey": key, "ParameterValue": value} for key, value in plan["parameters"].items()],
                                     Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "NetVulnFleet", "Value": plan["stack_name"]}])
    cfn.get_waiter("change_set_create_complete").wait(ChangeSetName=change_set["Id"], WaiterConfig={"Delay": 5, "MaxAttempts": 120})
    (package / "change-set.json").write_text(json.dumps(cfn.describe_change_set(ChangeSetName=change_set["Id"]), default=str, indent=2) + "\n")
    cfn.execute_change_set(ChangeSetName=change_set["Id"])
    deadline = time.monotonic() + 19800
    while time.monotonic() < deadline:
        stack = cfn.describe_stacks(StackName=change_set["StackId"])["Stacks"][0]
        print(f"{datetime.now(timezone.utc).isoformat()} {stack['StackStatus']}", flush=True)
        if stack["StackStatus"] == "CREATE_COMPLETE":
            result = {"stack_id": change_set["StackId"], "status": stack["StackStatus"], "outputs": stack.get("Outputs", []), "ami": image[0], "control_ami": control_image[0], "plan": plan}
            (package / "deployment-result.json").write_text(json.dumps(result, default=str, indent=2) + "\n")
            return result
        if stack["StackStatus"] not in {"CREATE_IN_PROGRESS", "REVIEW_IN_PROGRESS"}:
            raise RuntimeError(f"CloudFormation failed: {stack['StackStatus']}. Inspect stack events and bootstrap logs.")
        time.sleep(30)
    raise TimeoutError("Stack readiness did not complete before the deployment deadline")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=Path("artifacts/aws/package"))
    parser.add_argument("--bucket", help="Existing artifact bucket; otherwise CloudFormation creates a private bucket stack")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--ami-id", help="Pinned Canonical AMI; otherwise resolve the official SSM parameter once and record the selected ID")
    parser.add_argument("--control-ami-id", help="Pinned Ubuntu 24.04 AMI for the Ansible control node")
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--target-instance-type", default="t3.medium")
    parser.add_argument("--management-instance-type", default="t3.large")
    parser.add_argument("--execute", action="store_true", help="Upload artifacts, create a new stack and wait for functional readiness; creates billable resources")
    args = parser.parse_args()
    plan = deployment_plan(args.package, args.bucket, args.region, args.ami_id, args.stack_name, args.target_instance_type, args.management_instance_type, args.control_ami_id)
    (args.package / "deployment-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    print(json.dumps(plan, indent=2))
    if args.execute:
        execute_plan(plan, args.package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
