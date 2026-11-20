import json
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import pytest

from ai_engine.executor.oci_executor import (
    execute_block_ip_waf,
    execute_soft_rate_limit,
    execute_isolate_sg,
    execute_no_action,
)
from ai_engine.schemas.models import IncidentState, NormalizedEvent


def make_incident(final_decision: str, ip: str = "1.2.3.4") -> IncidentState:
    event = NormalizedEvent(
        event_id="evt-1",
        source="wazuh",
        timestamp=datetime.now(timezone.utc),
        source_ip=ip if ip not in ["not-an-ip", "999.999.999.999", ""] else "1.2.3.4",
        asset_tag="test-asset",
        severity=5,
        raw_indicator="test",
    )
    return IncidentState(
        incident_id="inc-test",
        correlation_key=(ip, "test-asset"),
        events=[event],
        status="open",
        final_decision=final_decision,
    )


@pytest.fixture(autouse=True)
def setup_env_vars(monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "true")
    monkeypatch.setenv("OCI_WAF_BLOCK_LIST_NAME", "TestOCIBlockList")
    monkeypatch.setenv("OCI_WAF_BLOCK_LIST_OCID", "ocid1.wafnetworkaddresslist.oc1..test-block")
    monkeypatch.setenv("OCI_WAF_RATELIMIT_LIST_NAME", "TestOCIRateLimitList")
    monkeypatch.setenv("OCI_WAF_RATELIMIT_LIST_OCID", "ocid1.wafnetworkaddresslist.oc1..test-ratelimit")
    monkeypatch.setenv("OCI_REGION", "ap-singapore-1")
    monkeypatch.setenv("QUARANTINE_NSG_OCID", "ocid1.networksecuritygroup.oc1..test-nsg")


@patch("ai_engine.executor.oci_executor._audit")
def test_escalate_is_refused(mock_audit):
    state = make_incident("escalate")
    res = execute_block_ip_waf(state)
    assert res.status == "refused"
    assert "escalate decision refuses" in res.details["error"]

    res2 = execute_soft_rate_limit(state)
    assert res2.status == "refused"


@patch("ai_engine.executor.oci_executor._audit")
def test_soft_contain_limits_actions(mock_audit):
    state = make_incident("soft_contain")

    # Not allowed
    res_block = execute_block_ip_waf(state)
    assert res_block.status == "refused"
    assert "soft_contain decision refuses" in res_block.details["error"]

    res_iso = execute_isolate_sg(state)
    assert res_iso.status == "refused"

    # Allowed
    res_rate = execute_soft_rate_limit(state)
    assert res_rate.status == "simulated"

    res_none = execute_no_action(state)
    assert res_none.status == "executed"


@patch("ai_engine.executor.oci_executor.get_oci_client")
@patch("ai_engine.executor.oci_executor._audit")
def test_shadow_mode_simulates_only(mock_audit, mock_oci_client):
    state = make_incident("autonomous")

    # By default SHADOW_MODE=true in fixture
    res = execute_block_ip_waf(state)
    assert res.status == "simulated"

    # Verify OCI client was NEVER called
    mock_oci_client.assert_not_called()

    # Verify audit logger was called with kwargs
    mock_audit.assert_called()
    call_record = mock_audit.call_args[0][0]
    assert call_record["status"] == "simulated"
    assert call_record["shadow_mode"] is True
    assert call_record["kwargs"]["display_name"] == "TestOCIBlockList"
    assert call_record["kwargs"]["addresses"] == ["1.2.3.4/32"]


@patch("ai_engine.executor.oci_executor.get_oci_client")
@patch("ai_engine.executor.oci_executor._audit")
def test_isolate_sg_builds_correct_kwargs(mock_audit, mock_oci_client, monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "false")
    state = make_incident("autonomous")
    res = execute_isolate_sg(state)

    assert res.status == "simulated"
    mock_oci_client.assert_not_called()

    call_record = mock_audit.call_args[0][0]
    assert "quarantine NSG" in call_record["details"]


@patch("ai_engine.executor.oci_executor._audit")
def test_protected_ip_is_refused(mock_audit):
    # Public IP should be allowed (simulated)
    state_public = make_incident("autonomous", ip="8.8.8.8")
    res_public = execute_block_ip_waf(state_public)
    assert res_public.status == "simulated"

    # Private IPs should be refused
    private_ips = ["10.1.2.3", "172.16.5.4", "192.168.1.1", "127.0.0.1"]
    for ip in private_ips:
        state = make_incident("autonomous", ip=ip)
        res = execute_block_ip_waf(state)
        assert res.status == "refused"
        assert "is protected or malformed" in res.details["error"]

    # Malformed IPs should be refused
    malformed_ips = ["not-an-ip", "999.999.999.999", ""]
    for ip in malformed_ips:
        state = MagicMock(spec=IncidentState)
        state.correlation_key = (ip, "test-asset")
        state.final_decision = "autonomous"
        state.incident_id = "inc-test"
        res = execute_block_ip_waf(state)
        assert res.status == "refused"
        assert "is protected or malformed" in res.details["error"]


@patch("ai_engine.executor.oci_executor._audit")
def test_env_protected_cidrs(mock_audit, monkeypatch):
    monkeypatch.setenv("PROTECTED_CIDRS", "203.0.113.0/24, 198.51.100.0/24")

    state = make_incident("autonomous", ip="203.0.113.5")
    res = execute_block_ip_waf(state)
    assert res.status == "refused"

    state2 = make_incident("autonomous", ip="8.8.8.8")
    res2 = execute_block_ip_waf(state2)
    assert res2.status == "simulated"
