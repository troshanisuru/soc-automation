# SOC Automation OCI Network & Security Infrastructure Spec

## Overview

This specification defines the **Dual-VCN (Virtual Cloud Network)** topology on **Oracle Cloud Infrastructure (OCI)** for the `soc-automation` project. It preserves the exact network isolation boundaries and RFC 1918 CIDR layout from the earlier AWS design while taking advantage of OCI Compartments, Local Peering Gateways (LPGs), Network Security Groups (NSGs), Dynamic Groups, and the OCI Always Free Compute Tier.

> For a detailed comparison with the previous AWS topology, see [docs/AWS_TO_OCI_MIGRATION.md](../docs/AWS_TO_OCI_MIGRATION.md).

## Required OCI Context & Guardrails

All infrastructure scripts are guarded for your target OCI Tenancy and Compartment only:

| Setting | Environment Variable | Required / Default Value |
| --- | --- | --- |
| OCI CLI Profile | `OCI_CLI_PROFILE` | `soc-project` |
| OCI Region | `OCI_REGION` | `ap-singapore-1` (or your subscribed home region) |
| Expected Tenancy OCID | `EXPECTED_OCI_TENANCY_OCID` | `ocid1.tenancy.oc1..*` |
| Target Compartment OCID | `OCI_COMPARTMENT_OCID` | `ocid1.compartment.oc1..*` (`soc-automation` compartment) |
| Admin Public IPv4 CIDR | `ADMIN_IP_CIDR` | `<your-admin-public-ip>/32` |

Each script verifies the authenticated Tenancy OCID and Target Compartment lifecycle state (`ACTIVE`) before any write operation.

## VCN Layout

| VCN Name | DNS Label | Purpose | CIDR Block |
| --- | --- | --- | --- |
| `soc-automation-prod-vcn` | `socprod` | Hosts the Web Server / SSH brute-force target and private DB Server | `10.0.0.0/16` |
| `soc-automation-security-vcn` | `socsec` | Hosts Wazuh Manager (All-in-One) and Python/AI SOC Middleware | `172.16.0.0/16` |

## Regional Subnet Layout

| Subnet Name | VCN | DNS Label | CIDR | Access Type | Purpose |
| --- | --- | --- | --- | --- | --- |
| `soc-automation-prod-public` | Production VCN | `prodpub` | `10.0.1.0/24` | Public (`prohibit-public-ip-on-vnic=false`) | Web Server / SSH brute-force target |
| `soc-automation-prod-private` | Production VCN | `prodpriv` | `10.0.2.0/24` | Private (`prohibit-public-ip-on-vnic=true`) | Private PostgreSQL DB Server |
| `soc-automation-security-mgmt` | Security VCN | `secmgmt` | `172.16.1.0/24` | Public (`prohibit-public-ip-on-vnic=false`) | Wazuh Manager & AI SOC Brain Middleware |

## Internet Gateways & Local Peering Gateways (LPGs)

- **Internet Gateways**:
  - `soc-automation-prod-igw`: Attached to `soc-automation-prod-vcn` for public HTTP/HTTPS and admin SSH to the Web target.
  - `soc-automation-security-igw`: Attached to `soc-automation-security-vcn` for admin SSH, Wazuh Dashboard (`443/tcp`), and Wazuh API (`55000/tcp`).
- **Local Peering Gateways (LPGs)**:
  - `soc-automation-prod-lpg` (in Production VCN) <-> `soc-automation-security-lpg` (in Security VCN).
  - Establishes private cross-VCN routing between `10.0.0.0/16` and `172.16.0.0/16` without traversing the public internet.

## Route Tables

| Route Table Name | Associated Subnet | Route Rules |
| --- | --- | --- |
| `soc-automation-prod-public-rt` | `soc-automation-prod-public` | • `0.0.0.0/0 -> soc-automation-prod-igw`<br>• `172.16.0.0/16 -> soc-automation-prod-lpg` |
| `soc-automation-prod-private-rt` | `soc-automation-prod-private` | • `172.16.0.0/16 -> soc-automation-prod-lpg` (No internet gateway route) |
| `soc-automation-security-mgmt-rt` | `soc-automation-security-mgmt` | • `0.0.0.0/0 -> soc-automation-security-igw`<br>• `10.0.0.0/16 -> soc-automation-security-lpg` |

## Network Security Groups (NSGs)

| NSG Name | VCN | Stateful Ingress Rules |
| --- | --- | --- |
| `soc-automation-prod-web-nsg` | Production VCN | • TCP `22` from `ADMIN_IP_CIDR`<br>• TCP `80` from `0.0.0.0/0`<br>• TCP `443` from `0.0.0.0/0` |
| `soc-automation-prod-db-nsg` | Production VCN | • TCP `5432` from `soc-automation-prod-web-nsg` (NSG source)<br>• TCP `22` from `172.16.1.0/24` (Security management subnet via LPG) |
| `soc-automation-security-mgmt-nsg` | Security VCN | • TCP `22`, `443`, `55000` from `ADMIN_IP_CIDR`<br>• TCP `55000` from `172.16.1.0/24`<br>• TCP `1514`, `1515` from `10.0.0.0/16` (Wazuh Agent telemetry & enrollment) |
| `soc-automation-quarantine-nsg` | Production VCN | • TCP `22`, `1514` from `172.16.1.0/24` only (Used by `oci_executor.py` for host quarantine) |

## OCI Dynamic Group & Least-Privilege IAM Policy

Instead of static credentials on the Wazuh/Middleware server, OCI uses **Dynamic Groups** and **Instance Principals**:

- **Dynamic Group (`soc-automation-middleware-dg`)**:
  - Matching rule: `ANY { instance.compartment.id = '<OCI_COMPARTMENT_OCID>' }` (or scoped to the specific Wazuh instance OCID once launched).
- **OCI IAM Policy (`soc-automation-middleware-policy`)**:
  - `Allow dynamic-group soc-automation-middleware-dg to use virtual-network-family in compartment id <OCI_COMPARTMENT_OCID>`
  - `Allow dynamic-group soc-automation-middleware-dg to manage waf-family in compartment id <OCI_COMPARTMENT_OCID>`
  - `Allow dynamic-group soc-automation-middleware-dg to read object-family in compartment id <OCI_COMPARTMENT_OCID>`

## Admin CIDR Rotation

- Use `infra/update-admin-cidr.sh` when your workstation's public IPv4 changes.
- Provide `OLD_ADMIN_IP_CIDR` and `NEW_ADMIN_IP_CIDR` as `/32` public IPv4 blocks.
- The script adds the new `/32` rules to `soc-automation-prod-web-nsg` and `soc-automation-security-mgmt-nsg`, verifies their presence, and then removes the old `/32` rules.
