import pytest
import json
from datetime import datetime
from unittest.mock import MagicMock, patch
from ai_engine.ingest.wazuh_poller import parse_wazuh_alert, process_lines

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


@pytest.mark.parametrize(
    "final_decision,proposed_action,expected_called",
    [
        ("escalate", "block_ip_waf", None),
        ("escalate", "soft_rate_limit", None),
        ("soft_contain", "block_ip_waf", "soft_rate_limit"),
        ("soft_contain", "soft_rate_limit", "soft_rate_limit"),
        ("autonomous", "block_ip_waf", "block_ip_waf"),
        ("autonomous", "isolate_sg", "isolate_sg"),
        ("autonomous", "soft_rate_limit", "soft_rate_limit"),
        ("autonomous", "no_action", "no_action"),
    ],
)
def test_poller_executor_dispatch_for_decisions(final_decision, proposed_action, expected_called):
    mock_state = MagicMock()
    mock_state.incident_id = "inc-001"
    mock_state.final_decision = final_decision
    mock_state.decision = MagicMock()
    mock_state.decision.proposed_action = proposed_action

    alert_line = json.dumps({
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "5710", "level": 5, "description": "test alert"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.44", "dstuser": "alice"}
    })

    store = MagicMock()

    with patch("ai_engine.ingest.wazuh_poller.run_incident", return_value=mock_state), \
         patch("ai_engine.ingest.wazuh_poller.execute_block_ip_waf") as m_block, \
         patch("ai_engine.ingest.wazuh_poller.execute_isolate_sg") as m_isolate, \
         patch("ai_engine.ingest.wazuh_poller.execute_soft_rate_limit") as m_rate, \
         patch("ai_engine.ingest.wazuh_poller.execute_no_action") as m_no_action:

        process_lines([alert_line], store=store)

        executors = {
            "block_ip_waf": m_block,
            "isolate_sg": m_isolate,
            "soft_rate_limit": m_rate,
            "no_action": m_no_action,
        }

        if expected_called is None:
            # Escalate must never call any executor
            for name, mock_fn in executors.items():
                assert mock_fn.call_count == 0, f"Expected {name} not to be called for {final_decision}"
        else:
            for name, mock_fn in executors.items():
                if name == expected_called:
                    assert mock_fn.call_count == 1, f"Expected {name} to be called once"
                    assert mock_fn.call_args[0][0] == mock_state
                else:
                    assert mock_fn.call_count == 0, f"Expected {name} not to be called"


def test_parse_wazuh_custom_modsecurity_alert_clamps_severity_and_sets_waf_source():
    """Verify ModSecurity custom rules (100400-100410) map to source='waf', clamp level 12 -> 10, and enrich indicator."""
    from pathlib import Path
    sample_path = Path(__file__).resolve().parent.parent.parent / "wazuh" / "alerts" / "sample_wazuh_modsecurity_sqli.json"
    alert = json.loads(sample_path.read_text(encoding="utf-8"))

    event = parse_wazuh_alert(alert)
    assert event.source == "waf"
    assert event.source_ip == "198.51.100.44"
    assert event.asset_tag == "prod-web-server"
    assert event.severity == 10  # Clamped from Wazuh level 12
    assert "CRS=949110" in event.raw_indicator
    assert "url=/?cmd=cat%20/etc/passwd" in event.raw_indicator


def test_custom_wazuh_rules_and_decoders_valid_xml():
    """Verify all custom Wazuh decoder and rule XML files parse cleanly with no syntax errors."""
    import xml.etree.ElementTree as ET
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent.parent
    xml_files = [
        repo_root / "wazuh" / "decoders" / "custom_modsecurity_decoders.xml",
        repo_root / "wazuh" / "rules" / "custom_modsecurity_rules.xml",
        repo_root / "wazuh" / "rules" / "custom_oci_rules.xml",
        repo_root / "wazuh" / "rules" / "custom_ssh_rules.xml",
    ]
    for path in xml_files:
        assert path.exists(), f"Missing Wazuh XML file: {path}"
        wrapped = f"<root>\n{path.read_text(encoding='utf-8')}\n</root>"
        ET.fromstring(wrapped)


def test_auth_allowlist_bypasses_min_level_and_suppresses_benign_success_only(monkeypatch):
    """Bug 1: Rules 5710/5715/5716 bypass WAZUH_MIN_ALERT_LEVEL=7; 5715 learns baseline without calling run_incident."""
    from datetime import timezone
    from ai_engine.baseline.store import BaselineStore

    monkeypatch.setenv("WAZUH_MIN_ALERT_LEVEL", "7")
    store = BaselineStore(db_path=":memory:", min_age_seconds=0)

    benign_5715 = json.dumps({
        "id": "1727320522.100",
        "timestamp": "2026-09-26T03:15:22.123Z",
        "rule": {"id": "5715", "level": 3, "description": "sshd: authentication succeeded"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.10", "dstuser": "deploy"},
    })
    low_non_auth = json.dumps({
        "id": "1727320522.101",
        "timestamp": "2026-09-26T03:15:25.123Z",
        "rule": {"id": "9999", "level": 5, "description": "low noise event"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.10"},
    })
    fail_5710 = json.dumps({
        "id": "1727320522.102",
        "timestamp": "2026-09-26T03:15:30.123Z",
        "rule": {"id": "5710", "level": 5, "description": "sshd: invalid user"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.20", "dstuser": "baduser"},
    })
    fail_5716 = json.dumps({
        "id": "1727320522.103",
        "timestamp": "2026-09-26T03:15:35.123Z",
        "rule": {"id": "5716", "level": 5, "description": "sshd: authentication failed"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.30", "dstuser": "alice"},
    })
    succ_after_fail = json.dumps({
        "id": "1727320522.104",
        "timestamp": "2026-09-26T03:15:40.123Z",
        "rule": {"id": "5715", "level": 3, "description": "sshd: authentication succeeded"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.30", "dstuser": "alice"},
    })

    calls = []
    with patch("ai_engine.ingest.wazuh_poller.run_incident", side_effect=lambda evs, **kw: calls.append(evs) or None):
        process_lines([benign_5715, low_non_auth, fail_5710, fail_5716, succ_after_fail], store=store)

    now = datetime.now(timezone.utc)
    # 198.51.100.10 only had 5715 -> baseline learned, run_incident NOT called; 9999 lvl 5 was filtered out
    assert store.is_known_pair("deploy", "198.51.100.10", now) is True
    # 198.51.100.30 had 5716 failure + 5715 success -> baseline NOT learned, run_incident called
    assert store.is_known_pair("alice", "198.51.100.30", now) is False

    called_ips = {evs[0].source_ip for evs in calls}
    assert called_ips == {"198.51.100.20", "198.51.100.30"}
    store.close()


def test_deterministic_event_id_and_stateful_correlator_polling(monkeypatch):
    """Bug 2: parse_wazuh_alert uses Wazuh alert id deterministically and EventCorrelator deduplicates & merges across polls."""
    from datetime import timedelta, timezone
    from ai_engine.baseline.store import BaselineStore
    from ai_engine.correlation.correlate import EventCorrelator

    alert1 = {
        "id": "1727320522.99999",
        "timestamp": "2026-09-26T03:15:22.000Z",
        "rule": {"id": "100402", "level": 10, "description": "SQLi blocked"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.77"},
    }
    alert2 = {
        "id": "1727320522.100000",
        "timestamp": "2026-09-26T03:16:00.000Z",
        "rule": {"id": "100403", "level": 10, "description": "XSS blocked"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "198.51.100.77"},
    }
    ev1 = parse_wazuh_alert(alert1)
    assert ev1.event_id == "1727320522.99999"

    ev_sanitized = parse_wazuh_alert({**alert1, "id": "id with spaces/slashes"})
    assert ev_sanitized.event_id == "id_with_spaces_slashes"

    ev_fallback = parse_wazuh_alert({k: v for k, v in alert1.items() if k != "id"})
    assert ev_fallback.event_id.startswith("evt-")

    store = BaselineStore(db_path=":memory:")
    correlator = EventCorrelator(window_seconds=60)
    t0 = datetime(2026, 9, 26, 3, 15, 25, tzinfo=timezone.utc)

    dispatched_states = []
    with patch("ai_engine.ingest.wazuh_poller.run_incident_state", side_effect=lambda st, **kw: dispatched_states.append(st) or None):
        # Poll 1: alert1 arrives (and duplicate alert1 should be ignored)
        process_lines([json.dumps(alert1), json.dumps(alert1)], store=store, correlator=correlator, now=t0)
        assert len(dispatched_states) == 0

        # Poll 2 (35s later, still inside 60s window): alert2 merges into the open incident
        process_lines([json.dumps(alert2)], store=store, correlator=correlator, now=t0 + timedelta(seconds=35))
        assert len(dispatched_states) == 0

        # Poll 3 (window expired): finalized single incident with 2 deduplicated events
        process_lines([], store=store, correlator=correlator, now=t0 + timedelta(seconds=120))
        assert len(dispatched_states) == 1
        assert [e.event_id for e in dispatched_states[0].events] == ["1727320522.99999", "1727320522.100000"]
    store.close()


def test_modsecurity_sqli_rule_100402_does_not_false_match_generic_post():
    """Bug 4: Rule 100402 must not classify arbitrary blocked POST / HTTP requests as SQL Injection."""
    import re
    import xml.etree.ElementTree as ET
    from pathlib import Path

    rule_path = Path(__file__).resolve().parent.parent.parent / "wazuh" / "rules" / "custom_modsecurity_rules.xml"
    root = ET.fromstring(f"<root>\n{rule_path.read_text(encoding='utf-8')}\n</root>")
    rule_100402 = root.find(".//rule[@id='100402']")
    assert rule_100402 is not None
    regex_pattern = rule_100402.findtext("regex")
    assert regex_pattern is not None
    assert "POST / HTTP" not in regex_pattern

    # Strip PCRE2 inline (?i) for Python re with re.IGNORECASE
    py_pattern = regex_pattern.removeprefix("(?i)")
    assert re.search(py_pattern, 'ModSecurity: Access denied with code 403 ... [request "POST / HTTP/1.1"]', re.IGNORECASE) is None
    assert re.search(py_pattern, 'ModSecurity: Access denied with code 403 [id "942100"] [data "Matched Data: UNION SELECT"]', re.IGNORECASE) is not None
