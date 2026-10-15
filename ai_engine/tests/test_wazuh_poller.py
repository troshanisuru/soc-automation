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

    assert event.username == "admin_test"
    assert event.auth_outcome == "failure"
    assert event.user_valid is False

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
    assert event.username is None
    assert event.auth_outcome is None
    assert event.user_valid is None

def test_parse_wazuh_rule_5716_valid_user_bad_password():
    alert = {
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "5716", "level": 5, "description": "sshd: authentication failed"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "192.168.1.100", "dstuser": "alice"}
    }
    event = parse_wazuh_alert(alert)
    assert event.username == "alice"
    assert event.auth_outcome == "failure"
    assert event.user_valid is True

def test_parse_wazuh_rule_5715_successful_login():
    alert = {
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "5715", "level": 3, "description": "sshd: authentication succeeded"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "192.168.1.100", "dstuser": "bob"}
    }
    event = parse_wazuh_alert(alert)
    assert event.username == "bob"
    assert event.auth_outcome == "success"
    assert event.user_valid is True

def test_parse_wazuh_rule_100301_custom_ssh_bruteforce():
    alert = {
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "100301", "level": 10, "description": "sshd: multiple failed logins"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "192.168.1.100", "dstuser": "charlie"}
    }
    event = parse_wazuh_alert(alert)
    assert event.username == "charlie"
    assert event.auth_outcome is None
    assert event.user_valid is None

def test_parse_wazuh_other_rule_leaves_auth_fields_none():
    alert = {
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "9999", "level": 2, "description": "other rule"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "192.168.1.100", "dstuser": "david"}
    }
    event = parse_wazuh_alert(alert)
    assert event.username is None
    assert event.auth_outcome is None
    assert event.user_valid is None

def test_parse_wazuh_sanitizes_and_truncates_username():
    raw_user = "attacker\n" + ("x" * 500)
    alert = {
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "192.168.1.100", "dstuser": raw_user}
    }
    event = parse_wazuh_alert(alert)
    assert "\n" not in event.username
    assert len(event.username) == 64
    assert event.username == ("attacker " + ("x" * 500))[:64]
