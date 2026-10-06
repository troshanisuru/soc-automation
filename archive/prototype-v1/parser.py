from schema import NormalizedEvent
from datetime import datetime
from typing import Dict, Any

def parse_wazuh_alert(raw_wazuh_log: Dict[str, Any]) -> NormalizedEvent:
    """
    Parses Wazuh JSON alerts, including nested AWS WAF and VPC Flow logs routed via S3.
    Wazuh nests AWS-specific telemetry payload under data.aws.*
    """
    timestamp_str = raw_wazuh_log.get("timestamp")
    if timestamp_str:
        try:
            # Handle ISO string timestamps
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now()
    else:
        ts = datetime.now()

    rule_info = raw_wazuh_log.get("rule", {})
    severity = int(rule_info.get("level", 0))
    rule_id = str(rule_info.get("id", ""))
    rule_desc = rule_info.get("description", "No description")
    agent_name = raw_wazuh_log.get("agent", {}).get("name", "wazuh-agent")

    data = raw_wazuh_log.get("data", {})
    aws_data = data.get("aws", {})

    # 1. AWS WAF Log routed through Wazuh S3 integration
    if aws_data and ("httpRequest" in aws_data or "terminatingRuleId" in aws_data or "waf" in str(rule_info.get("groups", "")).lower()):
        http_req = aws_data.get("httpRequest", {})
        client_ip = http_req.get("clientIp") or aws_data.get("clientIp") or "0.0.0.0"
        target_uri = http_req.get("uri") or agent_name
        action = aws_data.get("action") or ("BLOCK" if severity >= 7 else "ALLOW")
        indicator = f"WAF Rule [{aws_data.get('terminatingRuleId', rule_id)}]: {rule_desc}"

        return NormalizedEvent(
            source="aws_waf",
            timestamp=ts,
            source_ip=client_ip,
            target_asset=target_uri,
            severity=severity,
            raw_indicator=indicator,
            event_type="web_waf_alert",
            action=action,
            rule_id=rule_id
        )

    # 2. AWS VPC Flow Log routed through Wazuh S3 integration
    if aws_data and ("srcaddr" in aws_data or "dstaddr" in aws_data or "vpc" in str(rule_info.get("groups", "")).lower()):
        src_ip = aws_data.get("srcaddr") or "0.0.0.0"
        dst_ip = aws_data.get("dstaddr") or agent_name
        action = aws_data.get("action", "REJECT")
        indicator = f"VPC Flow {action} on port {aws_data.get('dstport', '')}: {rule_desc}"

        return NormalizedEvent(
            source="aws_vpcflow",
            timestamp=ts,
            source_ip=src_ip,
            target_asset=dst_ip,
            severity=severity,
            raw_indicator=indicator,
            event_type="network_flow_alert",
            action=action,
            rule_id=rule_id
        )

    # 3. Standard Host-level Wazuh Alert (e.g. SSH brute force, syslog)
    src_ip = data.get("srcip") or data.get("src_ip") or "0.0.0.0"
    return NormalizedEvent(
        source="wazuh",
        timestamp=ts,
        source_ip=src_ip,
        target_asset=agent_name,
        severity=severity,
        raw_indicator=rule_desc,
        event_type="host_alert",
        rule_id=rule_id
    )

def parse_waf_log(raw_waf_log: Dict[str, Any]) -> NormalizedEvent:
    """Direct WAF log fallback parser."""
    return NormalizedEvent(
        source="waf",
        timestamp=datetime.fromtimestamp(raw_waf_log.get("timestamp", 0) / 1000),
        source_ip=raw_waf_log.get("httpRequest", {}).get("clientIp", "0.0.0.0"),
        target_asset=raw_waf_log.get("httpRequest", {}).get("uri", "web_server"),
        severity=8 if raw_waf_log.get("action") == "BLOCK" else 3,
        raw_indicator=raw_waf_log.get("terminatingRuleId", "Unknown Rule"),
        event_type="web_alert",
        action=raw_waf_log.get("action", "ALLOW")
    )
