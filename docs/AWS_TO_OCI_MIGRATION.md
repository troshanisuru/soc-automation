# Cloud Migration Documentation: AWS to Oracle Cloud Infrastructure (OCI)

## 1. Executive Summary & Rationale for Migration

During the initial implementation phases (Phases 1–3) of the **AI-Assisted SOC Automation System**, the infrastructure was designed and provisioned on **Amazon Web Services (AWS)** in the `ap-southeast-1` (Singapore) region. While the Dual-VPC network topology, Security Groups, least-privilege IAM roles, and EC2 compute nodes were successfully verified on AWS, practical operational and budget constraints prompted a strategic migration to **Oracle Cloud Infrastructure (OCI)**.

### Key Drivers for Shifting from AWS to Oracle Cloud (OCI)

1. **Wazuh SIEM & AI Middleware Memory/CPU Requirements vs. Free Tier Limits**:
   - **AWS Constraint**: The AWS Free Tier only provides `t3.micro` / `t2.micro` instances (2 vCPUs, **1 GiB RAM**). However, the Wazuh Manager, Wazuh Indexer (OpenSearch), Wazuh Dashboard, and the Python multi-agent AI middleware require a minimum of **4–8 GiB RAM** (and ideally 4 vCPUs + 16 GiB RAM) to run without Out-Of-Memory (OOM) crashes. Provisioning `soc-automation-wazuh` on `t3.micro` could only validate base OS boot, while scaling to `t3.large` (2 vCPUs, 8 GiB RAM) or `g4dn.xlarge` incurs continuous hourly charges outside the AWS Free Tier.
   - **OCI Advantage**: OCI's **Always Free Tier** includes up to **4 OCPUs (equivalent to 8 vCPUs) and 24 GB of RAM** on Ampere A1 (`VM.Standard.A1.Flex`) ARM64 instances, plus **2 additional `VM.Standard.E2.1.Micro` x86 instances** and **200 GB of Block Volume storage** at zero cost indefinitely. This allows the Wazuh All-in-One stack (`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`) and the Python AI SOC Brain middleware to run at full production-grade capacity (`4 OCPUs, 24 GB RAM`) alongside the isolated Web (`VM.Standard.E2.1.Micro`) and DB (`VM.Standard.E2.1.Micro`) hosts completely within the Always Free allowance.

2. **Elimination of Recurring Fixed Costs for WAF and Log Ingestion**:
   - **AWS Constraint**: AWS WAFv2 charges a fixed monthly fee per Web ACL, per rule, and per million requests, in addition to S3 request/storage costs and KMS encryption fees.
   - **OCI Advantage**: OCI Network Security Groups (NSGs), VCN Flow Logs via OCI Logging, and OCI Object Storage (up to 20 GB Always Free) allow full network telemetry and automated containment without recurring fixed Web ACL fees.

3. **Simpler IAM Policy Management Without Managed-Policy Size Bottlenecks**:
   - **AWS Constraint**: In AWS, scoping least-privilege deployer permissions across VPCs, Subnets, IGWs, Route Tables, Peering, IAM, and EC2 exceeded the 6,144-character managed policy limit, forcing the deployer permissions to be split across four separate customer-managed IAM policies (`SOCAutomationDeployerPolicy`, `SOCAutomationIAMDeployerPolicy`, `SOCAutomationComputeDeployerPolicy`, and `SOCAutomationSecurityGroupRulePolicy`).
   - **OCI Advantage**: OCI uses human-readable policy statements scoped natively to a dedicated **Compartment** (`Allow group SOC-Deployers to manage all-resources in compartment soc-automation`) and **Dynamic Groups** for instance principal authentication (`Allow dynamic-group soc-middleware-dg to manage virtual-network-family in compartment soc-automation`).

---

## 2. Architectural & Service Comparables: AWS vs. Oracle Cloud (OCI)

The table below maps every AWS component from our original design to its direct equivalent in Oracle Cloud Infrastructure (OCI).

| Architectural Layer | Previous AWS Implementation | New Oracle Cloud (OCI) Implementation | Technical Comparison & Migration Notes |
| :--- | :--- | :--- | :--- |
| **Account / Isolation Boundary** | AWS Account (`908157891283`) + Resource Tags (`Project=soc-automation`) | OCI Tenancy + Dedicated **Compartment** (`soc-automation`) | AWS relies on tag-based filtering within an account; OCI provides native logical isolation via Compartments (`COMPARTMENT_OCID`). |
| **CLI & Local Authentication** | AWS CLI v2 (`~/.aws/credentials`, profile `soc-project`, STS `get-caller-identity`) | OCI CLI (`~/.oci/config`, RSA API Signing Key `oci_api_key.pem`, profile `soc-project`) | OCI binds the local workstation using an asymmetric 2048-bit RSA API signing key pair whose public key is registered to the OCI User OCID. |
| **Virtual Networks** | Dual AWS VPCs:<br>• Production VPC (`10.0.0.0/16`)<br>• Security VPC (`172.16.0.0/16`) | Dual OCI **VCNs (Virtual Cloud Networks)**:<br>• `soc-automation-prod-vcn` (`10.0.0.0/16`)<br>• `soc-automation-security-vcn` (`172.16.0.0/16`) | Identical RFC 1918 CIDR layout and DNS label resolution across two isolated virtual networks. |
| **Subnets & Availability** | Single-AZ (`ap-southeast-1a`) Subnets:<br>• `prod-public-1a` (`10.0.1.0/24`)<br>• `prod-private-1a` (`10.0.2.0/24`)<br>• `security-mgmt-1a` (`172.16.1.0/24`) | Regional OCI Subnets:<br>• `soc-automation-prod-public` (`10.0.1.0/24`)<br>• `soc-automation-prod-private` (`10.0.2.0/24`)<br>• `soc-automation-security-mgmt` (`172.16.1.0/24`) | OCI subnets are regional by default (spanning Availability Domains within the region) and enforce public/private VNIC IP assignment via `--prohibit-public-ip-on-vnic`. |
| **Cross-Network Peering** | AWS VPC Peering Connection (`pcx-*`) | OCI **Local Peering Gateways (LPGs)**:<br>• `prod-lpg` <-> `security-lpg` | In AWS, a single `pcx` resource links two VPCs. In OCI, each VCN attaches its own Local Peering Gateway (`LPG`) and establishes a peer connection between them. |
| **Internet Access & Routing** | 2x AWS Internet Gateways (`prod-igw`, `security-igw`) + 3x Route Tables | 2x OCI Internet Gateways (`prod-igw`, `security-igw`) + 3x OCI Route Tables | Both route `0.0.0.0/0` to the respective IGW on public subnets, while routing cross-VCN traffic (`10.0.0.0/16` <-> `172.16.0.0/16`) through the peering target. The private DB subnet has no internet route. |
| **Instance Firewall / Micro-segmentation** | AWS Security Groups (`prod-web-sg`, `prod-db-sg`, `security-mgmt-sg`) | OCI **Network Security Groups (NSGs)**:<br>• `soc-automation-prod-web-nsg`<br>• `soc-automation-prod-db-nsg`<br>• `soc-automation-security-mgmt-nsg` | Both support stateful ingress/egress rules and NSG-to-NSG source/destination references (within the same VCN) or CIDR-based rules across peered VCNs. Note: OCI Ubuntu images also use OS-level `iptables`, which user-data configures alongside NSGs. |
| **Compute Instances** | • Web: `t3.micro` (x86_64, 1 GiB RAM)<br>• DB: `t3.micro` (x86_64, 1 GiB RAM)<br>• Wazuh: `t3.micro` / `t3.large` (x86_64) | • Web: `VM.Standard.E2.1.Micro` (x86_64, 1 GB RAM, Always Free)<br>• DB: `VM.Standard.E2.1.Micro` (x86_64, 1 GB RAM, Always Free)<br>• Wazuh + AI Brain: `VM.Standard.A1.Flex` (ARM64 Ampere, **4 OCPUs, 24 GB RAM**, Always Free) | Huge resource upgrade for Wazuh and the AI SOC Engine at $0/month using OCI Always Free Ampere A1 shapes. |
| **Instance Identity & Least-Privilege Auth** | AWS IAM Role (`SOC-Middleware-Role`) + EC2 Instance Profile + Customer-Managed Policies | OCI **Dynamic Group** (`soc-automation-middleware-dg`) + **Instance Principals** + OCI IAM Policy | In OCI, the Wazuh/Middleware compute instance authenticates directly to OCI APIs via `oci.auth.signers.InstancePrincipalsSecurityTokenSigner()` without storing static keys on the server. |
| **Telemetry & Log Storage** | AWS WAF Logs + VPC Flow Logs -> Amazon S3 (`aws-waf-logs-soc-project-*`) -> Wazuh `<awss3>` wodle | OCI VCN Flow Logs / Edge WAF Logs -> OCI Logging & Object Storage (or S3-compatible API) + Wazuh Agents (`1514/tcp`) | OCI Object Storage provides an S3-compatible API endpoint as well as native OCI Logging / Wazuh agent log collection. |
| **Active Response Python SDK** | `boto3` (`wafv2.update_ip_set`, `ec2.revoke_security_group_ingress`) | **`oci` Python SDK** (`oci.waf.WafClient`, `oci.core.VirtualNetworkClient` for NSG rule updates & quarantine NSG isolation) | Replaced `boto3_executor.py` with `oci_executor.py`, preserving deterministic gate checks, shadow mode (`SHADOW_MODE=true`), RFC 1918 protected IP guards, and rotating JSON audit logs. |

---

## 3. Record of Past AWS Environments (Historical Project Evidence)

To support project reporting and academic evaluation, the complete lifecycle and resource inventory of the previous AWS environments are preserved below.

### 3.1 AWS Iteration 1: Legacy Multi-AZ Prototype & Verified Teardown
- **AWS Account ID**: `421515025823` (`arn:aws:iam::421515025823:user/cyber-user`)
- **Region**: `ap-southeast-1`
- **Summary**: An initial over-configured 6-subnet Multi-AZ topology (`ap-southeast-1a` and `ap-southeast-1b`) was created and subsequently torn down on `2026-09-08T15:36:47Z` to prevent cost leakage and align with a cleaner Single-AZ Dual-VPC specification.
- **Deleted Resources**:
  - VPCs: `vpc-0d53143e2f0a14450` (`soc-automation-mgmt-vpc`), `vpc-0fda586ca71a8e583` (`soc-automation-soc-vpc`)
  - Subnets (6): `subnet-0dd8f8677781c9f44`, `subnet-0e6a021cf71f8a608`, `subnet-07ce59ad6eb6d68aa`, `subnet-0a75f102db2028159`, `subnet-09232eb5d82ddab7a`, `subnet-04b84a9083b538649`
  - Internet Gateways (2): `igw-01b777b4c1c717e9f`, `igw-07cd9187e7423d4d3`
  - Route Tables (4): `rtb-053921ab07c4d5e2e`, `rtb-00f1d65a0d9a4cf2c`, `rtb-0011c474f65ad1e98`, `rtb-0dd1e11e886f4ad75`
  - VPC Peering: `pcx-0ec60bac4cf5228bc` (`soc-automation-soc-to-mgmt-peering`)
  - Security Groups (3): `sg-039424d17ef6630ec`, `sg-0dcbfd4796182c3b2`, `sg-0f0f82178384295fd`
  - IAM Resources: `SOC-Middleware-Role`, `SOC-Middleware-Profile`, `SOC-Middleware-WebSG-Policy`, `SOC-SG-Modify-Policy`

### 3.2 AWS Iteration 2: Hardened Dual-VPC Single-AZ Lab (`ap-southeast-1a`)
- **AWS Account ID**: `908157891283` (`arn:aws:iam::908157891283:user/soc-project-developer`)
- **AWS CLI Profile**: `soc-project`
- **Region / AZ**: `ap-southeast-1` / `ap-southeast-1a`

#### Phase 1: Network Topology Inventory (AWS)
| Resource Type | Name Tag | AWS Resource ID | CIDR / Target Details |
| :--- | :--- | :--- | :--- |
| **VPC** | `soc-automation-prod-vpc` | `vpc-01d5230934a140846` | `10.0.0.0/16` (DNS hostnames & support enabled) |
| **VPC** | `soc-automation-security-vpc` | `vpc-0fb2381154ad1b418` | `172.16.0.0/16` (DNS hostnames & support enabled) |
| **Subnet** | `soc-automation-prod-public-1a` | `subnet-09438c38e60394950` | `10.0.1.0/24` (`MapPublicIpOnLaunch=true`) |
| **Subnet** | `soc-automation-prod-private-1a` | `subnet-045f32f0821d7cb3e` | `10.0.2.0/24` (`MapPublicIpOnLaunch=false`) |
| **Subnet** | `soc-automation-security-mgmt-1a` | `subnet-0192340171c348f23` | `172.16.1.0/24` (`MapPublicIpOnLaunch=true`) |
| **Internet Gateway** | `soc-automation-prod-igw` | `igw-06e6b0d1f11011563` | Attached to `vpc-01d5230934a140846` |
| **Internet Gateway** | `soc-automation-security-igw` | `igw-019c11b265c872311` | Attached to `vpc-0fb2381154ad1b418` |
| **VPC Peering** | `soc-automation-prod-to-security-peering` | `pcx-0d0b43fb860ec81c6` | Active peering between Production VPC and Security VPC |
| **Route Table** | `soc-automation-prod-public-rt` | `rtb-02eedd48a40d1af95` | `0.0.0.0/0 -> igw-06e6b0d1f11011563`, `172.16.0.0/16 -> pcx-0d0b43fb860ec81c6` |
| **Route Table** | `soc-automation-prod-private-rt` | `rtb-0194a18d251c136b3` | `172.16.0.0/16 -> pcx-0d0b43fb860ec81c6` (No internet route) |
| **Route Table** | `soc-automation-security-mgmt-rt` | `rtb-07b6607b14a11e620` | `0.0.0.0/0 -> igw-019c11b265c872311`, `10.0.0.0/16 -> pcx-0d0b43fb860ec81c6` |

#### Phase 2: Security Groups & Least-Privilege IAM Inventory (AWS)
| Resource Type | Name | AWS Resource ID / ARN | Rules / Scope |
| :--- | :--- | :--- | :--- |
| **Security Group** | `soc-automation-prod-web-sg` | `sg-01dc0bd14c2808f21` | TCP 22 from `ADMIN_IP_CIDR`, TCP 80 & 443 from `0.0.0.0/0` |
| **Security Group** | `soc-automation-prod-db-sg` | `sg-03e665ea5e9403e11` | TCP 5432 from `sg-01dc0bd14c2808f21`, TCP 22 from `sg-0effe1d21b6836624` |
| **Security Group** | `soc-automation-security-mgmt-sg` | `sg-0effe1d21b6836624` | TCP 22/443/55000 from `ADMIN_IP_CIDR`, TCP 55000 from `172.16.1.0/24`, TCP 1514/1515 from `10.0.0.0/16` |
| **IAM Role & Profile** | `SOC-Middleware-Role` | `arn:aws:iam::908157891283:role/SOC-Middleware-Role` | Assumed by `ec2.amazonaws.com` on the Wazuh/Middleware host |
| **IAM Policy** | `SOC-Middleware-WebSG-Policy` | `arn:aws:iam::908157891283:policy/SOC-Middleware-WebSG-Policy` | Scoped `AuthorizeSecurityGroupIngress` / `RevokeSecurityGroupIngress` strictly to `sg-01dc0bd14c2808f21` |
| **Deployer Policies** | 4 Split Customer-Managed Policies | Attached to `soc-project-developer` | `SOCAutomationDeployerPolicy`, `SOCAutomationIAMDeployerPolicy`, `SOCAutomationComputeDeployerPolicy`, `SOCAutomationSecurityGroupRulePolicy` |

#### Phase 3: Compute Instances Inventory (AWS)
- **AMI**: Canonical Ubuntu 22.04 LTS Jammy (`ami-0d95f2f0cc4ab4566`, owner `099720109477`)
- **Instances Provisioned**:
  1. `soc-automation-web` (`i-0e92011f436a3baad`): `t3.micro`, Subnet `subnet-09438c38e60394950`, Private IP `10.0.1.195`, Public IP `52.76.39.134`, 12 GiB gp3 volume (`vol-07287577c947dba1f`)
  2. `soc-automation-db` (`i-064148a7962815669`): `t3.micro`, Subnet `subnet-045f32f0821d7cb3e`, Private IP `10.0.2.186`, No Public IP, 12 GiB gp3 volume (`vol-03d12bcffe976580d`)
  3. `soc-automation-wazuh` (`i-0fe7ae677567b5ac3`): `t3.micro` (tested) / `t3.large` (spec), Subnet `subnet-0192340171c348f23`, Private IP `172.16.1.96`, Public IP `52.77.213.48`, 50 GiB gp3 volume (`vol-0b0f17b11e4ef9ee6`), IAM Instance Profile `SOC-Middleware-Role`
