# Wazuh Configuration and Assets (`wazuh/`)

This directory contains all Wazuh platform configuration files, custom XML rules, sample alert payloads, and deployment resources for the **Autonomous Multi-Agent SOC Brain**.

## Folder Structure

```text
wazuh/
├── config/
│   └── wazuh_ossec_aws.xml      # S3 integration module configuration (<awss3>) for AWS WAF & VPC Flow logs
├── rules/
│   └── custom_aws_rules.xml     # Custom XML detection rules for AWS WAF blocks and VPC Flow rejections
└── alerts/
    ├── sample_wazuh_waf_sqli.json      # Sample Wazuh alert for AWS WAF SQL Injection attack
    └── sample_wazuh_ssh_failure.json   # Sample Wazuh alert for Linux SSH brute-force login failure
```

---

## Component Details

### 1. Configuration (`wazuh/config/`)
- **`wazuh_ossec_aws.xml`**: Configuration snippet to append to `/var/ossec/etc/ossec.conf` on the Wazuh Manager instance. It enables the native `<awss3>` module to poll AWS WAF and VPC Flow Log archives from S3 at 10-minute intervals.

### 2. Detection Rules (`wazuh/rules/`)
- **`custom_aws_rules.xml`**: Defines custom Wazuh rules (Rule IDs `100201` and `100202`) that categorize AWS WAF `BLOCK` actions and VPC Flow `REJECT` actions with MITRE ATT&CK framework mapping.

### 3. Sample Alerts (`wazuh/alerts/`)
- **`sample_wazuh_waf_sqli.json`**: Real-world sample payload demonstrating how Wazuh wraps AWS WAF HTTP request telemetry under `data.aws.*`.
- **`sample_wazuh_ssh_failure.json`**: Sample host-level SSH authentication failure alert.
