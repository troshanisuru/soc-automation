# SOC Automation Network Infrastructure Spec

## Overview

This specification documents the PDF-aligned **Dual-VPC, Single-AZ** architecture for the SOC automation project. It replaces the earlier over-configured 6-subnet Multi-AZ version.

The design uses two VPCs in one availability zone: `${AWS_REGION}a`, which defaults to `ap-southeast-1a`.

## Required AWS Context

All infrastructure scripts are guarded for the new AWS account only:

| Setting | Required value |
| --- | --- |
| AWS CLI profile | `soc-project` |
| AWS region | `ap-southeast-1` |
| Expected account ID | `908157891283` |
| Expected caller | `arn:aws:iam::908157891283:user/soc-project-developer` |

The scripts call STS with the named profile before any write operation and stop if the authenticated account ID is not `908157891283`. They also verify that `ap-southeast-1a` is available before subnet creation.

| VPC | Purpose | CIDR |
| --- | --- | --- |
| Production VPC | Hosts the Web Server / SSH brute-force target and private DB Server | `10.0.0.0/16` |
| Security VPC | Hosts Wazuh Manager and Python/AI Middleware | `172.16.0.0/16` |

## Subnet Layout

| Subnet | VPC | CIDR | AZ | Purpose |
| --- | --- | --- | --- | --- |
| `prod-public-1a` | Production VPC | `10.0.1.0/24` | `ap-southeast-1a` | Web Server / SSH brute-force target |
| `prod-private-1a` | Production VPC | `10.0.2.0/24` | `ap-southeast-1a` | DB Server |
| `security-mgmt-1a` | Security VPC | `172.16.1.0/24` | `ap-southeast-1a` | Wazuh Manager and Python/AI Middleware |

## Internet Gateways

- `prod-igw` is attached to the Production VPC for public web/admin access to the production web target.
- `security-igw` is attached to the Security VPC because the management subnet supports admin/dashboard access.

## Route Tables

| Route Table | Associations | Routes |
| --- | --- | --- |
| `prod-public-rt` | `prod-public-1a` | `0.0.0.0/0 -> prod-igw`, `172.16.0.0/16 -> prod-to-security-peering` |
| `prod-private-rt` | `prod-private-1a` | `172.16.0.0/16 -> prod-to-security-peering` |
| `security-mgmt-rt` | `security-mgmt-1a` | `0.0.0.0/0 -> security-igw`, `10.0.0.0/16 -> prod-to-security-peering` |

## VPC Peering

- `prod-to-security-peering`: Production VPC <-> Security VPC
- Production routes to Security CIDR: `172.16.0.0/16`
- Security routes to Production CIDR: `10.0.0.0/16`

## Security Groups

| Security Group | VPC | Purpose |
| --- | --- | --- |
| `prod-web-sg` | Production VPC | Production web server / SSH brute-force target |
| `prod-db-sg` | Production VPC | Private database server |
| `security-mgmt-sg` | Security VPC | Wazuh Manager and Python/AI Middleware |

## IAM Role

- `SOC-Middleware-Role` is assumed by EC2.
- `SOC-Middleware-WebSG-Policy` allows describe actions as needed and scopes security group ingress modification only to `prod-web-sg`.
- Security Groups are allow-only and do not support explicit deny rules. The active-response design must not claim that Security Group changes can block one malicious IP while a broader allow rule still permits it; that mechanism will be redesigned separately.

## Deployer Policy

- `infra/deployer-policy.json` is superseded and should not be attached as the active AWS Console policy.
- `infra/deployer-network-policy.json` is attached as `SOCAutomationDeployerPolicy` for VPC, subnet, internet gateway, route table, VPC peering, and project Security Group setup operations.
- `infra/deployer-iam-policy.json` is attached as `SOCAutomationIAMDeployerPolicy` for `SOC-Middleware-Role`, the matching instance profile, and `SOC-Middleware-WebSG-Policy`.
- `infra/deployer-compute-policy.json` is attached as `SOCAutomationComputeDeployerPolicy` for EC2 key-pair import, instance launch, and lab start/stop operations.
- `infra/deployer-sg-rule-policy.json` is attached as `SOCAutomationSecurityGroupRulePolicy` for admin CIDR rotation only.
- `SOCAutomationSecurityGroupRulePolicy` is separate because the larger deployer policy reached AWS managed-policy size constraints. Its narrow responsibility is to modify ingress rules only on the three exact project Security Groups: `sg-01dc0bd14c2808f21`, `sg-0effe1d21b6836624`, and `sg-03e665ea5e9403e11`.
- The policies avoid `AdministratorAccess`, `iam:*`, and `ec2:*`.
- IAM write resources are scoped to `SOC-Middleware-Role`, `SOC-Middleware-Role` instance profile, and `SOC-Middleware-WebSG-Policy`.
- JSON does not support comments. Any explanation for the policy must stay in Markdown docs rather than inside the JSON file.

## Admin CIDR Rotation

- Use `infra/update-admin-cidr.sh` when the admin public IP changes.
- Provide `OLD_ADMIN_IP_CIDR` and `NEW_ADMIN_IP_CIDR` as public IPv4 `/32` values at run time.
- The script verifies the current public IP, account, profile, region, and exact Security Group IDs before changing rules.
- It adds and verifies the new admin CIDR on web SSH and management SSH/HTTPS/Wazuh API before removing the old admin CIDR.
- Database SSH is expected through `security-mgmt-sg`; direct public admin CIDR SSH is removed if a stale old rule is present.

## Scope of provision.sh

The provisioning script creates only:

1. Two VPCs with DNS support and hostnames enabled.
2. Three subnets total.
3. Two internet gateways.
4. Three route tables with required routes.
5. One VPC peering connection.

Out of scope:

- NAT gateways
- EC2 instances
- Wazuh installation
- ML or middleware implementation
- Real AWS credentials
