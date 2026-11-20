# OCI Compute Instance Specification (Always Free Ampere A1 Pool)

This document defines the **Oracle Cloud Infrastructure (OCI) Always Free Tier** compute layout for the Security VCN (`security-vcn`).

## Instance Matrix (4 OCPUs / 24 GB RAM Total Always Free A1 Pool)

| Display Name | Role Tag | OCI Shape | Image | OCPUs / Memory | Subnet | NSG | Public IPv4 | Boot Volume |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ollama-server` | `ollama` | `VM.Standard.A1.Flex` | Canonical Ubuntu 24.04 (`aarch64` / ARM) | **2 OCPUs / 12 GB RAM** | `security-mgmt-subnet` | `security-nsg` | Enabled | Default 50 GB |
| `wazuh-manager` | `wazuh` | `VM.Standard.A1.Flex` | Canonical Ubuntu 24.04 (`aarch64` / ARM) | **2 OCPUs / 12 GB RAM** | `security-mgmt-subnet` | `security-nsg` | Enabled | Default 50 GB |

## Architectural Separation Rationale

`ollama-server` and `wazuh-manager` are provisioned as two separate `VM.Standard.A1.Flex` instances (2 OCPUs / 12 GB RAM each, totaling 4 OCPUs / 24 GB RAM) rather than combined onto a single host. Wazuh's OpenSearch Indexer and Ollama LLM inference both compete heavily for memory; isolating them onto dedicated hosts prevents RAM contention while staying 100% within Oracle Cloud's Always Free Ampere A1 pool.
