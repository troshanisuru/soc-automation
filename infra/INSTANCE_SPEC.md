# Phase 3 EC2 Instance Specification

This document defines the lowest-cost academic lab EC2 design for the `soc-automation` project. It is local preparation only until `infra/instances.sh` is explicitly authorized and run.

## Target Environment

- AWS account: `908157891283`
- AWS CLI profile: `soc-project`
- Region: `ap-southeast-1`
- Availability Zone: `ap-southeast-1a`
- Project tag: `soc-automation`
- Environment tag: `lab`
- Admin CIDR: set `ADMIN_IP_CIDR=<your-admin-public-ip>/32` at run time

## Dependency IDs

The script verifies these Phase 1 and Phase 2 resources before instance creation:

- Production VPC: `vpc-01d5230934a140846`
- Security VPC: `vpc-0fb2381154ad1b418`
- VPC peering: `pcx-0d0b43fb860ec81c6`
- Web SG: `sg-01dc0bd14c2808f21`
- Management SG: `sg-0effe1d21b6836624`
- DB SG: `sg-03e665ea5e9403e11`
- Instance profile: `SOC-Middleware-Role`

Subnets are discovered by `Project` and `Name` tags rather than hardcoded IDs:

- `soc-automation-prod-public-1a`
- `soc-automation-prod-private-1a`
- `soc-automation-security-mgmt-1a`

## AMI Selection

`infra/instances.sh` resolves the AMI dynamically with `ec2:DescribeImages`.

Required AMI properties:

- Owner: Canonical account `099720109477`
- Ubuntu Server 22.04 LTS Jammy
- x86_64 architecture
- EBS-backed root device
- HVM virtualization
- Available state

The script rejects non-Canonical images and non-22.04 image names. If several images match, it sorts by `CreationDate` and `ImageId`, then chooses the newest deterministically.

## Instance Matrix

| Name | Role tag | Type | Subnet | Security group | Public IPv4 | IAM profile | Root volume | User-data |
|---|---|---:|---|---|---|---|---|---|
| `soc-automation-web` | `web` | `t3.micro` | `soc-automation-prod-public-1a` | `prod-web-sg` | enabled | none | 12 GiB encrypted gp3 | `infra/user-data/web.sh` |
| `soc-automation-db` | `db` | `t3.micro` | `soc-automation-prod-private-1a` | `prod-db-sg` | disabled | none | 12 GiB encrypted gp3 | `infra/user-data/db.sh` |
| `soc-automation-wazuh` | `wazuh` | `t3.large` | `soc-automation-security-mgmt-1a` | `security-mgmt-sg` | enabled | `SOC-Middleware-Role` | 50 GiB encrypted gp3 | `infra/user-data/wazuh-base.sh` |

Root EBS volumes use `DeleteOnTermination=true`. Detailed monitoring is left disabled because detailed monitoring is billable in ordinary EC2 usage.

## Wazuh Sizing Note

The `soc-automation-wazuh` host uses `t3.large` to keep academic lab cost low. This has less CPU than Wazuh's official 1-25-agent recommendation, so it is suitable for a constrained demonstration lab, not a production deployment. Wazuh installation and tuning remain later controlled tasks.

## User-Data Scope

- Web user-data installs and enables Nginx and keeps `/var/log/auth.log` available for Wazuh ingestion.
- DB user-data avoids `apt update`, package downloads, PostgreSQL installation, and password creation because the private subnet has no NAT gateway.
- Wazuh user-data performs only safe base configuration. It does not install Wazuh and does not create passwords.

No user-data file contains credentials, tokens, passwords, private keys, or generated secrets.

## SSH Key Design

The EC2 key pair name is `soc-automation-key`.

The script requires this existing local public key:

```bash
~/.ssh/soc-automation-ed25519.pub
```

If the public key is missing, create it locally before provisioning:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/soc-automation-ed25519 -C soc-automation-key
```

Only the `.pub` file is imported into EC2. The private key must stay outside the repository and must never be pasted into chat, user-data, evidence files, or AWS Console policy documents. Do not create or download an AWS `.pem` private key.

## Cost Controls

The design intentionally avoids:

- Elastic IPs
- NAT gateways
- RDS
- Load balancers
- VPC endpoints
- Wazuh installation during EC2 launch

Use `infra/stop-lab.sh` to stop running lab instances when they are not needed, and `infra/start-lab.sh` to restart only the expected tagged lab instances.

## Later Execution Command

Do not run this until Phase 3 provisioning is explicitly authorized:

```bash
set -o pipefail
AWS_PROFILE=soc-project \
AWS_REGION=ap-southeast-1 \
EXPECTED_AWS_ACCOUNT_ID=908157891283 \
bash infra/instances.sh \
2>&1 | tee evidence/aws-phase3-compute/instances.log
```

Before this command is run, attach [infra/deployer-compute-policy.json](/Users/user/soc-automation/infra/deployer-compute-policy.json) to `soc-project-developer` as `SOCAutomationComputeDeployerPolicy`. If the admin public IP changes before compute launch, attach [infra/deployer-sg-rule-policy.json](/Users/user/soc-automation/infra/deployer-sg-rule-policy.json) as `SOCAutomationSecurityGroupRulePolicy` and rotate `ADMIN_IP_CIDR` before running `infra/instances.sh`.
