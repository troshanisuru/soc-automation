# Phase 3 OCI Compute Instance Specification (Always Free Tier)

This document defines the **Oracle Cloud Infrastructure (OCI) Always Free Tier** compute design for the `soc-automation` project.

## Target Environment

- OCI CLI profile: `soc-project`
- OCI Region: `ap-singapore-1` (configurable via `OCI_REGION`)
- Compartment OCID: set `OCI_COMPARTMENT_OCID`
- Tenancy guard: set `EXPECTED_OCI_TENANCY_OCID`
- Freeform tags on all resources: `{"Project": "soc-automation", "Environment": "lab"}`

## Instance Matrix (100% Within OCI Always Free Allowance)

| Display Name | Role Tag | OCI Shape | Architecture | OCPUs / Memory | Subnet | NSG | Public IPv4 | Boot Volume | Cloud-Init User-Data |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `soc-automation-web` | `web` | `VM.Standard.E2.1.Micro` | `x86_64` | 1 OCPU (1/8 core) / 1 GB RAM | `soc-automation-prod-public` | `soc-automation-prod-web-nsg` | Enabled | 47 GB Always Free | `infra/user-data/web.sh` |
| `soc-automation-db` | `db` | `VM.Standard.E2.1.Micro` | `x86_64` | 1 OCPU (1/8 core) / 1 GB RAM | `soc-automation-prod-private` | `soc-automation-prod-db-nsg` | Disabled | 47 GB Always Free | `infra/user-data/db.sh` |
| `soc-automation-wazuh` | `wazuh` | `VM.Standard.A1.Flex` | `aarch64` (Ampere ARM64) | **4 OCPUs / 24 GB RAM** | `soc-automation-security-mgmt` | `soc-automation-security-mgmt-nsg` | Enabled | 100 GB Always Free | `infra/user-data/wazuh-base.sh` |

> **Why this sizing works on OCI**: OCI Always Free Tier grants 2x `VM.Standard.E2.1.Micro` instances plus up to 4 OCPUs and 24 GB RAM of `VM.Standard.A1.Flex` capacity, and up to 200 GB of total Block/Boot Volume storage (`47 + 47 + 100 = 194 GB <= 200 GB`). This gives the Wazuh Manager, Indexer, Dashboard, and Python AI SOC Engine 24 GB RAM at $0 cost.

## Image Selection

`infra/instances.sh` dynamically resolves the latest official **Canonical Ubuntu 22.04 / 24.04 LTS** platform image in the target region matching each instance's shape (`VM.Standard.E2.1.Micro` -> `x86_64` Ubuntu image; `VM.Standard.A1.Flex` -> `aarch64` Ubuntu image) using `oci compute image list`.

## SSH Key Design

The instances are provisioned with the local Ed25519 SSH public key generated during local PC binding:

```text
~/.ssh/soc-automation-ed25519.pub
```

If missing, generate it via `bash infra/bind-local-pc.sh` or:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/soc-automation-ed25519 -N "" -C "soc-automation-oci-key"
```

## OS Firewall Note on OCI Ubuntu Images

Canonical Ubuntu images on OCI include preconfigured `iptables` rules that reject inbound traffic on ports other than `22/tcp` even when allowed by an OCI NSG. The cloud-init scripts in `infra/user-data/web.sh` and `infra/user-data/wazuh-base.sh` automatically open the required ports (`80, 443` on Web; `443, 1514, 1515, 55000` on Wazuh) in the host firewall and persist them.

## Execution Command

```bash
set -o pipefail
OCI_CLI_PROFILE=soc-project \
OCI_REGION=ap-singapore-1 \
EXPECTED_OCI_TENANCY_OCID="ocid1.tenancy.oc1..your_tenancy" \
OCI_COMPARTMENT_OCID="ocid1.compartment.oc1..your_compartment" \
bash infra/instances.sh \
2>&1 | tee evidence/oci-phase3-compute/instances.log
```
