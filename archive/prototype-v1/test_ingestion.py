#!/usr/bin/env python3
"""
test_ingestion.py
Verification script for AWS WAF & VPC Flow Log ingestion via Wazuh JSON alerts.
"""

import json
from parser import parse_wazuh_alert
from schema import NormalizedEvent

def test_waf_via_wazuh_ingestion():
    print("==========================================================")
    print("  TESTING WAZUH AWS LOG INGESTION & NORMALIZATION")
    print("==========================================================")

    with open("test_log.json", "r") as f:
        raw_log = json.load(f)

    print("\n1. Loaded Raw Wazuh JSON Alert:")
    print(json.dumps(raw_log, indent=2))

    # Parse raw Wazuh alert containing nested data.aws attributes
    event: NormalizedEvent = parse_wazuh_alert(raw_log)

    print("\n2. Parsed NormalizedEvent (Pydantic Model):")
    print(repr(event))

    print("\n3. Normalized Event Attributes:")
    print(f"  Source System:  {event.source}")
    print(f"  Event Type:     {event.event_type}")
    print(f"  Source IP:      {event.source_ip}")
    print(f"  Target Asset:   {event.target_asset}")
    print(f"  Severity Level: {event.severity}/15")
    print(f"  WAF Action:     {event.action}")
    print(f"  Raw Indicator:  {event.raw_indicator}")
    print(f"  Timestamp:      {event.timestamp.isoformat()}")

    # Assertions to ensure strict compliance
    assert event.source == "aws_waf", f"Expected source 'aws_waf', got '{event.source}'"
    assert event.source_ip == "198.51.100.44", f"Expected source_ip '198.51.100.44', got '{event.source_ip}'"
    assert event.severity == 10, f"Expected severity 10, got {event.severity}"
    assert event.action == "BLOCK", f"Expected action 'BLOCK', got '{event.action}'"

    print("\n==========================================================")
    print("  SUCCESS: All Ingestion & Normalization Checks Passed!")
    print("==========================================================")

if __name__ == "__main__":
    test_waf_via_wazuh_ingestion()
