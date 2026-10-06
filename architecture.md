# Autonomous Multi-Agent SOC Brain Architecture

## Overview
This project implements an autonomous Security Operations Center (SOC) incident response pipeline. Security log telemetry from AWS infrastructure (AWS WAF and VPC Flow Logs) is ingested natively by the Wazuh Security Platform, normalized into standard data models, and analyzed by an LLM-driven multi-agent framework built with a hand-rolled deterministic Python state machine.

---

## Unified Data Ingestion & SOC Pipeline Architecture

```mermaid
graph TD
    subgraph AWS Telemetry Sources
        WAF["AWS WAF Logs<br/>(Web ACL Blocks/Allows)"]
        VPC["AWS VPC Flow Logs<br/>(Network Interfaces)"]
    end

    subgraph Centralized Storage
        S3["Amazon S3 Bucket<br/>(aws-waf-logs-soc-project-*)"]
    end

    subgraph Monitoring & Detection
        Wazuh["Wazuh Manager<br/>(Native <awss3> Module)"]
        Alerts["Wazuh JSON Alerts<br/>(data.aws.* payload)"]
    end

    subgraph SOC Brain Core
        Correlate["correlate (code)"]
        Triage["triage (LLM)"]
        Val1["validate"]
        Mitre["mitre (LLM)"]
        Val2["validate"]
        Decision["decision (LLM)"]
        Val3["validate"]
        Gate["gate (code, scoring)"]
        ExecEsc["execute | escalate"]
        Audit["audit log"]
        
        Correlate --> Triage
        Triage --> Val1
        Val1 --> Mitre
        Mitre --> Val2
        Val2 --> Decision
        Decision --> Val3
        Val3 --> Gate
        Gate --> ExecEsc
        ExecEsc --> Audit
    end

    WAF -->|Logs| S3
    VPC -->|Logs| S3
    S3 -->|Pull via IAM User / 10m Interval| Wazuh
    Wazuh -->|Generate| Alerts
    Alerts -->|Ingest & Parse| Correlate

    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#FFFFFF;
    classDef wazuh fill:#00A4E4,stroke:#111111,stroke-width:2px,color:#FFFFFF;
    classDef brain fill:#2C3E50,stroke:#18BC9C,stroke-width:2px,color:#FFFFFF;

    class WAF,VPC,S3 aws;
    class Wazuh,Alerts wazuh;
    class Correlate,Triage,Val1,Mitre,Val2,Decision,Val3,Gate,ExecEsc,Audit brain;
```

---

## Data Flow Details

1. **Telemetry Ingestion Phase:**
   - AWS WAF records HTTP request details (`clientIp`, `uri`, `terminatingRuleId`).
   - AWS VPC Flow Logs record network interface IP flows (`srcaddr`, `dstaddr`, `action`).
   - Logs are continuously written to partitioned folders (`waf-logs/`, `vpc-logs/`) inside an Amazon S3 Bucket (`aws-waf-logs-soc-project-*`).

2. **Wazuh Monitoring Phase:**
   - The Wazuh Manager uses its native `<awss3>` integration module to pull raw log archives from S3 on a 10-minute poll interval. Both WAF and VPC Flow Log ingestions operate on this 10-minute interval.
   - Wazuh parses the raw log objects and emits unified JSON alerts, embedding AWS payload attributes under `data.aws.*`.

3. **Normalization Phase:**
   - The SOC Brain receives the Wazuh JSON payload.
   - Standardizes the event into a strongly-typed `NormalizedEvent` Pydantic model.

4. **Multi-Agent Decision & Mitigation Phase (Deterministic State Machine):**
   - The reasoning layer uses a hand-rolled deterministic Python state machine.
   - **Three agents in sequence**: Triage -> MITRE mapping -> Decision. 
   - Each agent has its own Pydantic schema, and the output is strictly validated before the next stage runs.
   - **Deterministic Gate**: Evaluates risk scores against defined policy thresholds (autonomous_threshold: 0.75, soft_threshold: 0.45) to validate mitigation plans before executing actions. If validation fails at any point, the pipeline short-circuits to escalate and logs to the audit log.
