# Wazuh Configuration and Assets (`wazuh/`) - Oracle Cloud Infrastructure Edition

This directory contains all Wazuh platform configuration files, custom XML rules, sample alert payloads, and deployment resources for the **Autonomous Multi-Agent SOC Brain** on **Oracle Cloud Infrastructure (OCI)**.

## Folder Structure

```text
wazuh/
├── config/
│   └── wazuh_ossec_oci.xml      # OCI Object Storage S3-compatible integration configuration for OCI WAF & VCN Flow logs
├── rules/
│   ├── custom_oci_rules.xml     # Custom XML detection rules for OCI WAF blocks and VCN Flow rejections
│   └── custom_ssh_rules.xml     # Custom XML detection rules for SSH authentication anomalies
└── alerts/
    ├── sample_wazuh_waf_sqli.json      # Sample Wazuh alert for WAF SQL Injection attack
    └── sample_wazuh_ssh_failure.json   # Sample Wazuh alert for Linux SSH brute-force login failure
```

---

## Component Details

### 1. Configuration (`wazuh/config/`)
- **`wazuh_ossec_oci.xml`**: Configuration snippet to append to `/var/ossec/etc/ossec.conf` on the Wazuh Manager (`soc-automation-wazuh` running on OCI Ampere `VM.Standard.A1.Flex`). It configures Wazuh to pull OCI WAF and VCN Flow Log archives from OCI Object Storage (`oci-waf-vcn-logs-soc-project`) using OCI's S3-compatible endpoint at 10-minute intervals.

### 2. Detection Rules (`wazuh/rules/`)
- **`custom_oci_rules.xml`**: Defines custom Wazuh rules (Rule IDs `100201` and `100202`) that categorize OCI WAF `BLOCK` actions and OCI VCN Flow `REJECT` actions with MITRE ATT&CK framework mapping (`T1190`, `T1046`).
- **`custom_ssh_rules.xml`**: Defines custom SSH authentication correlation rules for brute-force detection on `soc-automation-web`.

### 3. Sample Alerts (`wazuh/alerts/`)
- **`sample_wazuh_waf_sqli.json`**: Sample payload demonstrating how Wazuh wraps WAF HTTP request telemetry.
- **`sample_wazuh_ssh_failure.json`**: Sample host-level SSH authentication failure alert from `soc-automation-web`.
