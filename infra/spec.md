# SOC Automation OCI Network & Security Infrastructure Spec

## Overview

This specification defines the **Security VCN (`security-vcn`)** topology on **Oracle Cloud Infrastructure (OCI)** for the `soc-automation` project. The Security VCN hosts the separated `ollama-server` and `wazuh-manager` Ampere A1 instances (`VM.Standard.A1.Flex`, 2 OCPUs / 12 GB RAM each). The Production/Target VCN and Local Peering Gateway (LPG) will be provisioned in a separate subsequent phase.

## Required OCI Context & Guardrails

| Setting | Environment Variable | Value |
| --- | --- | --- |
| OCI CLI Profile | `OCI_CLI_PROFILE` | `soc-project` |
| OCI Region | `OCI_REGION` | `ap-mumbai-1` |
| Expected Tenancy OCID | `EXPECTED_OCI_TENANCY_OCID` | `ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q` |
| Target Compartment OCID | `OCI_COMPARTMENT_OCID` | `ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q` |
| Admin Public IPv4 CIDR | `ADMIN_IP_CIDR` | `<your-admin-public-ip>/32` |

## Security VCN Layout

| Resource Type | Name | CIDR / Details |
| --- | --- | --- |
| **VCN** | `security-vcn` | `172.16.0.0/16` (DNS label: `securityvcn`) |
| **Public Subnet** | `security-mgmt-subnet` | `172.16.1.0/24` (Public: `prohibit-public-ip-on-vnic=false`) |
| **Internet Gateway** | `security-igw` | Enabled, attached to `security-vcn` |
| **Route Table** | `security-mgmt-rt` | `0.0.0.0/0 -> security-igw` (Associated with `security-mgmt-subnet`) |
| **Default Security List** | VCN Default Security List | Emptied (`[]`) so that `security-nsg` is the sole enforcement point |

## Network Security Group (`security-nsg`)

| Direction | Protocol | Port | Source / Destination | Purpose |
| --- | --- | --- | --- | --- |
| **INGRESS** | TCP (`6`) | `22` | `<ADMIN_IP_CIDR>/32` | Admin SSH access only (never `0.0.0.0/0`) |
| **INGRESS** | TCP (`6`) | `11434` | `172.16.0.0/16` | Ollama API internal to `security-vcn` only (never `0.0.0.0/0`) |
| **INGRESS** | TCP (`6`) | `1514` | `0.0.0.0/0` | Wazuh agent telemetry ingestion |
| **INGRESS** | TCP (`6`) | `1515` | `0.0.0.0/0` | Wazuh agent registration |
| **INGRESS** | TCP (`6`) | `443` | `<ADMIN_IP_CIDR>/32` | Wazuh dashboard HTTPS from admin IP `/32` only |
| **EGRESS** | All (`all`) | All | `0.0.0.0/0` | Outbound internet access |
