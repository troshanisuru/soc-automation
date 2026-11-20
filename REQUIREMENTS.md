# Requirements

## Functional Requirements

| ID | Requirement |
| --- | --- |
| FR1 | The system shall ingest host authentication, web, and OCI cloud security alerts via Wazuh. |
| FR2 | The system shall normalise alert data into a consistent `NormalizedEvent` schema. |
| FR3 | The system shall classify events as benign or malicious, and map malicious activity to MITRE ATT&CK techniques. |
| FR4 | The system shall trigger an Oracle Cloud Infrastructure (OCI) API / Python SDK (`oci`) containment action (WAF IP block, rate limit, or NSG quarantine) for approved malicious events. |
| FR5 | The system shall keep a tamper-evident rotating JSON audit log of all automated and simulated actions. |

## Non-Functional Requirements

| ID | Requirement |
| --- | --- |
| NFR1 | The system shall respond in under 5 seconds for supported alert workflows. |
| NFR2 | The system shall fail safely without triggering unauthorized or incomplete actions (enforcing `SHADOW_MODE`, protected RFC 1918 CIDR checks, and deterministic risk score thresholds). |
| NFR3 | The OCI IAM and Dynamic Group design shall follow compartment-scoped least privilege principles. |
| NFR4 | The false positive rate shall remain under 2% during evaluation. |
| NFR5 | The system shall produce reproducible test evidence and document architectural comparables between AWS and OCI. |
