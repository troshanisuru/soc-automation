# Requirements

## Functional Requirements

| ID | Requirement |
| --- | --- |
| FR1 | The system shall ingest authentication and security alerts. |
| FR2 | The system shall normalise alert data into a consistent format. |
| FR3 | The system shall classify events as benign or malicious, and map malicious activity to MITRE ATT&CK techniques. |
| FR4 | The system shall trigger an AWS API/Boto3 block action for approved malicious events. |
| FR5 | The system shall keep an audit log of automated actions. |

## Non-Functional Requirements

| ID | Requirement |
| --- | --- |
| NFR1 | The system shall respond in under 5 seconds for supported alert workflows. |
| NFR2 | The system shall fail safely without triggering unauthorized or incomplete actions. |
| NFR3 | The AWS IAM design shall follow least privilege principles. |
| NFR4 | The false positive rate shall remain under 2% during evaluation. |
| NFR5 | The system shall produce reproducible test evidence. |
