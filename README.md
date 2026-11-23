# AI-Assisted SOC Automation System (Oracle Cloud Infrastructure)

This project is a cybersecurity final year project for building an AI-assisted Security Operations Center (SOC) automation workflow. The system ingests security alerts, classifies and correlates events using a deterministic multi-agent LLM & scoring pipeline, and executes automated cloud response actions on **Oracle Cloud Infrastructure (OCI)**.

The system uses the **OCI Python SDK (`oci`) / OCI CLI** for cloud infrastructure and active response actions, **Wazuh** for security monitoring and alert ingestion, Python middleware (`ai_engine/`) for orchestration and deterministic gate decisions, and LLM/ML classification for identifying benign or malicious activity.

> **Migration Note**: This project was migrated from AWS to Oracle Cloud Infrastructure (OCI) to leverage OCI's Always Free Tier (`VM.Standard.A1.Flex` with 4 OCPUs and 24 GB RAM for Wazuh + AI Middleware, plus two `VM.Standard.E2.1.Micro` nodes for Web and DB). For the full migration rationale, past AWS inventory record, and side-by-side AWS vs. OCI architectural comparables, see [docs/AWS_TO_OCI_MIGRATION.md](docs/AWS_TO_OCI_MIGRATION.md).

## Local PC Binding to Oracle Cloud (OCI)

To bind your local workstation to Oracle Cloud for provisioning and management:

1. **Run the local binding helper**:
   ```bash
   bash infra/bind-local-pc.sh
   ```
   This script ensures:
   - OCI CLI (`oci`) and Python SDK are installed.
   - A 2048-bit RSA API signing key pair is generated at `~/.oci/oci_api_key.pem` (private) and `~/.oci/oci_api_key_public.pem` (public).
   - An Ed25519 SSH key pair for compute instances is generated at `~/.ssh/soc-automation-ed25519` and `~/.ssh/soc-automation-ed25519.pub`.
   - `~/.oci/config` is created with the `[soc-project]` profile template and your key fingerprint.

2. **Upload the Public API Key in OCI Console**:
   - Sign in to the Oracle Cloud Console -> **Profile Icon (top-right)** -> **My profile** -> **API keys** -> **Add API key**.
   - Select **Paste a public key** and paste the contents of `~/.oci/oci_api_key_public.pem`.
   - Copy the **Tenancy OCID**, **User OCID**, and **Region** shown in the OCI Console configuration preview and update `~/.oci/config` (or run `bash infra/bind-local-pc.sh --configure`).

3. **Verify Local PC -> OCI Connectivity**:
   ```bash
   bash infra/bind-local-pc.sh --verify
   ```

## OCI Deployment Guard

All infrastructure scripts under `infra/` enforce strict tenancy and compartment guards before performing any write operation:

- OCI CLI profile: `soc-project`
- OCI region: `ap-singapore-1` (or your subscribed home region via `OCI_REGION`)
- Expected tenancy OCID: `EXPECTED_OCI_TENANCY_OCID`
- Target compartment OCID: `OCI_COMPARTMENT_OCID`

Do not store OCI API private keys or SSH private keys in this repository or in `.env`.

## Folder Purpose

- `ai_engine/` - AI-driven 3-agent SOC reasoning (`triage_agent`, `mitre_agent`, `decision_agent`), stateful `EventCorrelator`, deterministic risk scoring gate (`scoring.py`), authentication false-positive policy (`policy.py` + SQLite `BaselineStore`), Wazuh EUI observability & HITL case management dashboard (`ai_engine/dashboard/server.py`), and OCI active-response executor (`ai_engine/executor/oci_executor.py`).
- `Dockerfile`, `docker-compose.yml`, `docker-compose.demo.yml` - Hybrid Docker containerization for `ai_engine` (`soc-poller` and `soc-dashboard` on OCI `wazuh-manager`, plus an offline Viva backup demo stack with `soc-llm-mock`).
- `archive/` - Archived prototype v1 code.
- `docs/` - Architectural migration documentation and AWS-to-OCI comparison ([docs/AWS_TO_OCI_MIGRATION.md](docs/AWS_TO_OCI_MIGRATION.md)).
- `evidence/` - Quantitative Phase 8 AI Engine evaluation reports ([evidence/ai_engine_evaluation_report.md](evidence/ai_engine_evaluation_report.md), [evidence/ai_engine_evaluation_report.json](evidence/ai_engine_evaluation_report.json)), OWASP WAF attack verification reports, and sanitized OCI inventory outputs.
- `infra/` - OCI Dual-VCN, Local Peering Gateway, Network Security Group, Dynamic Group IAM, and Compute provisioning scripts.
- `scripts/` - Deployment automation (`01`–`08`), OWASP WAF verification (`test_web_attacks.py`), Phase 8 evaluation harness (`evaluate_ai_engine.py`), and offline Ollama-compatible mock server (`soc_llm_server.py`).
- `wazuh/` - Wazuh configuration (`wazuh_ossec_oci.xml`), custom ModSecurity WAF decoders (`custom_modsecurity_decoders.xml`) and rules (`custom_modsecurity_rules.xml`, `custom_oci_rules.xml`, `custom_ssh_rules.xml`), and sample alert payloads.

## Running Tests & Phase 8 Evaluation

```bash
# Run the 220-test unit & integration suite
.venv/bin/pytest ai_engine/tests -q

# Run the 20-scenario Phase 8 quantitative benchmark against OCI Ollama
PYTHONPATH=. .venv/bin/python3 scripts/evaluate_ai_engine.py \
  --ollama-url http://172.16.1.20:11434 \
  --mode live-ollama \
  --out-json evidence/ai_engine_evaluation_report.json \
  --out-md evidence/ai_engine_evaluation_report.md

# Run via Hybrid Docker on wazuh-manager (or offline Viva demo locally)
docker compose up -d --build
docker compose -f docker-compose.demo.yml up -d --build
```
