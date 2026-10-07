import pytest
import json
from datetime import datetime
from ai_engine.ingest.wazuh_poller import parse_wazuh_alert

def test_parse_wazuh_ssh_alert():
    raw_json = """{
      "timestamp": "2026-09-26T03:15:22.123Z",
      "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "id": "5710"
      },
      "agent": {
        "id": "001",
        "name": "production-web-01"
      },
      "data": {
        "srcip": "192.168.1.105",
        "dstuser": "admin_test"
      }
    }"""
    
    alert_dict = json.loads(raw_json)
    event = parse_wazuh_alert(alert_dict)
    
    assert event.source == "wazuh"
    assert event.source_ip == "192.168.1.105"
    assert event.asset_tag == "production-web-01"
    assert event.severity == 5
    assert event.raw_indicator == "sshd: Attempt to login using a non-existent user"
    assert event.timestamp.isoformat() == "2026-09-26T03:15:22.123000+00:00"

def test_parse_wazuh_waf_alert():
    raw_json = """{
      "timestamp": "2026-09-27T11:30:15.456Z",
      "rule": {
        "level": 10,
        "description": "AWS WAF: SQL Injection attack detected in HTTP GET request URI parameter",
        "id": "100201"
      },
      "agent": {
        "name": "wazuh-aws-collector"
      },
      "data": {
        "aws": {
          "httpRequest": {
            "clientIp": "198.51.100.44"
          }
        }
      }
    }"""
    
    alert_dict = json.loads(raw_json)
    event = parse_wazuh_alert(alert_dict)
    
    assert event.source == "wazuh"
    assert event.source_ip == "198.51.100.44"
    assert event.asset_tag == "wazuh-aws-collector"
    assert event.severity == 10
    assert event.raw_indicator == "AWS WAF: SQL Injection attack detected in HTTP GET request URI parameter"
    assert event.timestamp.isoformat() == "2026-09-27T11:30:15.456000+00:00"
