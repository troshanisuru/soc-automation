# Project Plan (Oracle Cloud Infrastructure Edition)

| Phase | Goal | Tasks | Expected output | Status |
| --- | --- | --- | --- | --- |
| Phase 1: Project setup, AWS-to-OCI migration planning, and local PC binding | Define the OCI architecture, document AWS-to-OCI comparables, and bind local workstation via OCI CLI & RSA API signing keys. | Update project documentation, create `docs/AWS_TO_OCI_MIGRATION.md`, generate `~/.oci` API key pair and `~/.ssh` key pair, configure OCI CLI profile `soc-project`. | Baseline OCI documentation, migration rationale, and bound local OCI CLI environment. | DONE |
| Phase 2: OCI VCN network & NSG security scripts | Prepare guarded OCI CLI infrastructure scripts for Dual-VCN + Local Peering Gateway (LPG) + Network Security Groups (NSGs). | Build idempotent scripts (`infra/provision.sh`, `infra/security.sh`, `infra/provision_prod_and_wazuh.py`, `infra/verify.sh`) guarded by tenancy and compartment OCIDs. | Dual-VCN (`prod-vcn` `10.0.0.0/16` <-> `security-vcn` `172.16.0.0/16`), LPG peering, and least-privilege NSGs. | DONE |
| Phase 3: Distributed OCI compute & host WAF provisioning | Provision distributed Web+ModSecurity WAF, Wazuh Manager, Wazuh Indexer+Dashboard, and Ollama LLM servers in OCI (`ap-mumbai-1`). | Deploy `web-server` (`10.0.1.224`, Nginx + ModSecurity v3 OWASP CRS), `wazuh-manager` (`172.16.1.10`), `wazuh-indexer` (`172.16.1.11`), and `ollama-server` (`172.16.1.20`, `llama3.2:3b`). | Live 4-node OCI deployment and custom ModSecurity Wazuh decoders/rules (`100400`–`100410`). | DONE |
| Phase 4: Wazuh configuration and OCI alert ingestion | Configure Wazuh alert collection for SSH authentication, ModSecurity WAF, and OCI VCN Flow Logs. | Deploy custom decoders (`custom_modsecurity_decoders.xml`), custom rules (`custom_modsecurity_rules.xml`, `custom_oci_rules.xml`, `custom_ssh_rules.xml`), and stateful `wazuh_poller.py`. | Deterministic Wazuh alert ingestion, deduplication, and rolling-window correlation. | DONE |
| Phase 5: Multi-agent LLM analysis | Build a 3-agent LLM chain (`TriageAgent` -> `MitreAgent` -> `DecisionAgent`) for incident triage and MITRE ATT&CK mapping. | Enforce `<untrusted_log>` prompt-injection boundaries, catalog-grounded MITRE mapping, fuzzer URL burst collapsing, and strict Pydantic schema validation. | Hardened 3-agent LLM reasoning chain (`ai_engine/agents/`). | DONE |
| Phase 6: Deterministic gate, auth policy, and observability dashboard | Build middleware logic for correlation, weighted risk scoring, false-positive baseline learning, and HITL dashboard. | Connect `EventCorrelator`, `scoring.py`, `policy.py` (R0–R5 + `BaselineStore`), and Wazuh EUI SOC Operations Dashboard (`ai_engine/dashboard/server.py`). | Fail-closed risk gate, auth policy, and HITL SOC dashboard on port `8080`. | DONE |
| Phase 7: OCI Python SDK active response & Hybrid Docker containerization | Integrate OCI WAF/NSG active response (`oci_executor.py`) and containerize `ai_engine` middleware. | Implement idempotent ETag-verified OCI WAF address-list updates, `SHADOW_MODE=true` default, protected-IP & pure-SSH guards, plus `Dockerfile`, `docker-compose.yml`, and `docker-compose.demo.yml`. | Controlled OCI executor and Hybrid Docker / offline demo stacks. | DONE |
| Phase 8: Quantitative evaluation, stress testing, and evidence collection | Evaluate the end-to-end pipeline against 20 benchmark scenarios on live OCI Ollama (`llama3.2:3b`) and unit tests. | Run `scripts/evaluate_ai_engine.py` across 7 threat/stress categories and execute 220 unit tests (`pytest ai_engine/tests`). | `evidence/ai_engine_evaluation_report.md`, `evidence/ai_engine_evaluation_report.json`, and 220 passing unit tests. | DONE |

## OCI Deployment Safety Notes

- Required OCI CLI profile: `soc-project`
- Default OCI region: `ap-singapore-1` (configurable via `OCI_REGION`)
- Required tenancy guard: `EXPECTED_OCI_TENANCY_OCID`
- Target isolation compartment: `OCI_COMPARTMENT_OCID` (`soc-automation`)
- Infrastructure scripts verify the authenticated tenancy OCID and compartment OCID before executing any write operation.
- Do not store OCI private API keys (`oci_api_key.pem`) or SSH private keys inside this repository or in `.env`.
- Historical AWS architecture and AWS-to-OCI service comparables are documented in [docs/AWS_TO_OCI_MIGRATION.md](docs/AWS_TO_OCI_MIGRATION.md).
