# Audit: native installation, Ansible and segmented network

Date: 2026-11-14 UTC. This milestone covers installation/facts/readiness code and
a local model integration pilot. **No AWS resources have been created.**

## Evidence and boundaries

| Check | Status | Evidence |
| --- | --- | --- |
| All 16 proposal product/version pairs represented | passed | experiment.json and proposal consistency test |
| Official source archives and libyang pinned | passed | sources.lock.json, 17 observed SHA-256 values |
| All 16 source builds and actual binary versions on Ubuntu 22.04 x86_64 | passed, historical local build validation | [build-results.json](build-results.json); raw logs/binaries under artifacts/aws/build-validation/ |
| Native nginx 1.24.0/1.26.2 installed and served HTTP on Codespace Ubuntu 24.04 | passed | artifacts/aws/native-smoke.json; isolated prefixes/listeners |
| Native OpenSSH 9.6p1 running with root privilege separation on loopback | passed | source/binary/config hashes in [pilot report](PILOT.md) |
| Ansible local facts, package inventory and effective sshd configuration | passed | artifacts/aws/ansible-pilot/, ansible-pilot-run.log; 581 packages observed |
| Repeated local playbook | passed | ok=9, changed=1, unreachable=0, failed=0; only timestamped snapshot refreshed |
| Source/binary mismatch forces rebuild; unchanged binary skips it | unit checks passed | tests/infra/test_ansible.py; not a live repeated 16-node install |
| CloudFormation schema, Ansible syntax and Python tests | passed | cfn-lint 1.60.1; both playbooks syntax checked; 257 tests passed |
| SG service-flow matrix, forbidden pairs and router default-deny | local contract tests passed | tests/infra/test_network_policy.py; generated per-device groups |
| LLM/RAG using one real Ansible snapshot | diagnostic pilot passed | [PILOT.md](PILOT.md), [pilot-results.json](pilot-results.json); whole-answer accuracy remains ungraded |
| Live SSH fan-out, IAM, AMIs, SSM, CloudFormation create/rollback | pending | Requires AWS execution |
| Live forwarding/isolation, nftables loading, BGP, DNS, VPN and 16-node snapshot | pending | AWS readiness checks implemented; Codespace lacks network administration capability |
| Appliance/API/SNMP adapters and self-managed switch firmware | pending/outside current Linux matrix | Ansible Linux facts do not imply these adapters exist |
| Reviewed gold, 100-question benchmark, full RAG inventory integration and Greenbone | pending | P4–P7 in implementation plan |

## Current implementation

- CloudFormation provisions one MGMT and 16 private targets; one NAT provides
  bootstrap egress. Target AMI is Canonical Ubuntu 22.04 x86_64. MGMT uses Ubuntu
  24.04/Python 3.12 for ansible-core 2.20.11; launcher resolves and records concrete
  AMI IDs, or accepts pinned IDs. Region provisionally defaults to us-east-1.
- MGMT creates a separate Ansible SSH key, test-client key, pinned host keys and VPN
  certificates. The control private key stays on MGMT. Each target IAM role can
  read only the deployment bundle, public known-hosts file and its own PKI bundle.
- Target cloud-init prepares SSH/Python and a sudo-enabled control account.
  Ansible builds locked native sources, configures systemd and runs one-shot facts
  over SSH. There is no custom collector daemon or timer in the default deployment.
  Original HTTPS push modules remain only for the earlier pilot's reproducibility.
- Sharing the VPC does not grant general workload access: each device has an
  ingress allowlist; MGMT has no inbound access. Client/service routes go through
  FRR symmetrically. Forwarding is default-deny with explicit flow rules and
  ICMP redirects disabled. Internet egress remains open through NAT for bootstrap.
- Probes exercise the Web chain, UDP/TCP DNS, SSH, VPN and BGP; negative probes
  reject unwanted cross-branch/admin/backend access. A refused connection does
  not count as proof of filtering. FRR packet counters must increase from a
  baseline taken before workload probes in the same run. Old counters cannot
  prove the current client Web flow crossed the router.
- Switch connectivity is AWS-managed VPC fabric, not a firmware/VLAN/STP model.
  No switch CVE verdict is assigned.
- Each Ansible run gets its own inventory, log, raw facts, content-addressed
  snapshots, service/isolation probes and router counters. Missing/stale/incorrect
  observations fail readiness; desired versions/IPs never fill missing facts.
  Results upload to private S3 even when readiness reports incomplete.
- Re-running the same locked fleet skips a source build only if the actual binary
  version/hash and source hash still match. The launcher uses a new stack for a
  changed bundle; updating cloud-init alone would not rerun an existing instance.

## Source build issues corrected

1. Apache release-tag archives require buildconf with the installed apr-1-config.
2. FRR links explicitly against pinned libyang with its library search path/rpath
   and LIBS=-lyang. Upstream source was not patched.
3. FRR's real banner is “bgpd version”; the version probe accepts and verifies it.
4. OpenVPN needs libcap-ng-dev. Both versions were rebuilt and checked.
5. Native pilot uses its own prefixes/config/ports; the system sshd was not replaced.

The 16-build report predates the Ansible/network migration and proves compilation
and version, not current AWS services. Temporary build/tools Docker images were
removed at the user's request; current provisioning creates no container image.
Source archives, binaries and logs were preserved. Raw crawl files were deleted
as requested; processed evidence used by the pilot remains pinned.

## Next audit gate

Deploy the reviewed bundle to AWS; retain root/nested stack events and the complete
16-node report, including negative probes and router packet counters. Correct live
bootstrap/network issues before signing off P2/P3. Then build independent reviewed
CVE labels and automate the full experiment. The local one-case pilot cannot
replace those gates.

See [deployment instructions](../README.md), [implementation plan](../../../proposal/implementation-plan.md)
and [AWS middlebox routing](https://docs.aws.amazon.com/vpc/latest/userguide/intra-vpc-route.html).
