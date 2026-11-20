# Project Plan (Oracle Cloud Infrastructure Edition)

| Phase | Goal | Tasks | Expected output | Status |
| --- | --- | --- | --- | --- |
| Phase 1: Project setup, AWS-to-OCI migration planning, and local PC binding | Define the OCI architecture, document AWS-to-OCI comparables, and bind local workstation via OCI CLI & RSA API signing keys. | Update project documentation, create `docs/AWS_TO_OCI_MIGRATION.md`, generate `~/.oci` API key pair and `~/.ssh` key pair, configure OCI CLI profile `soc-project`. | Baseline OCI documentation, migration rationale, and bound local OCI CLI environment. | IN PROGRESS |
| Phase 2: OCI VCN network & NSG security scripts | Prepare guarded OCI CLI infrastructure scripts for Dual-VCN + Local Peering Gateway (LPG) + Network Security Groups (NSGs). | Build idempotent Bash scripts (`infra/provision.sh`, `infra/security.sh`, `infra/verify.sh`) guarded by `EXPECTED_OCI_TENANCY_OCID` and `OCI_COMPARTMENT_OCID`. | Guarded OCI network, NSG, and Dynamic Group IAM provisioning scripts. | READY TO RUN |
| Phase 3: OCI Always Free compute provisioning | Provision Web, DB, and Wazuh+Middleware OCI Compute instances in the `soc-automation` compartment. | Launch `soc-automation-web` (`VM.Standard.E2.1.Micro`), `soc-automation-db` (`VM.Standard.E2.1.Micro`), and `soc-automation-wazuh` (`VM.Standard.A1.Flex` 4 OCPU / 24 GB RAM) with NSGs. | Running OCI instances and sanitized `evidence/oci-phase3-compute/instances-after.json`. | READY TO RUN |
| Phase 4: Wazuh configuration and OCI alert ingestion | Configure Wazuh alert collection for authentication, OCI VCN Flow Logs, and OCI WAF / Object Storage events. | Prepare OCI alert ingestion format, custom OCI Wazuh rules, sample alerts, and parser expectations. | Wazuh OCI alert ingestion workflow. | DONE |
| Phase 5: Multi-agent LLM analysis | Build a multi-agent LLM chain for incident triage and MITRE ATT&CK mapping. | Develop prompt architectures for triage and MITRE agents, enforce schema validation, and prevent prompt injection. | Tested LLM reasoning chain. | DONE |
| Phase 6: Deterministic gate and decision engine | Build middleware logic for normalization, correlation, and response decisions. | Connect event correlator, agent pipeline, risk scoring gate, and audit logging. | Middleware decision engine. | DONE |
| Phase 7: OCI Python SDK active response integration | Integrate approved OCI API actions through the `oci` Python SDK (`ai_engine/executor/oci_executor.py`). | Implement least-privilege block action & NSG isolation workflow with shadow mode, protected-IP guards, and audit logging. | Controlled OCI active response flow (`oci_executor.py`). | DONE (Shadow Mode enabled by default) |
| Phase 8: Testing, evidence collection, and report output | Verify the full workflow on OCI and collect final project evidence. | Run system tests, collect logs, generate report output, and document results. | Test evidence and final report artifacts. | TODO |

## OCI Deployment Safety Notes

- Required OCI CLI profile: `soc-project`
- Default OCI region: `ap-singapore-1` (configurable via `OCI_REGION`)
- Required tenancy guard: `EXPECTED_OCI_TENANCY_OCID`
- Target isolation compartment: `OCI_COMPARTMENT_OCID` (`soc-automation`)
- Infrastructure scripts verify the authenticated tenancy OCID and compartment OCID before executing any write operation.
- Do not store OCI private API keys (`oci_api_key.pem`) or SSH private keys inside this repository or in `.env`.
- Historical AWS architecture and AWS-to-OCI service comparables are documented in [docs/AWS_TO_OCI_MIGRATION.md](docs/AWS_TO_OCI_MIGRATION.md).
