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


@patch("ai_engine.executor.oci_executor.oci")
@patch("ai_engine.executor.oci_executor.get_oci_client")
@patch("ai_engine.executor.oci_executor._audit")
def test_live_mode_waf_merges_addresses_with_etag_and_is_idempotent(mock_audit, mock_get_client, mock_oci, monkeypatch):
    """Bug 3: Live mode reads existing list + etag, merges IP/32 without overwriting, and skips update if already present."""
    monkeypatch.setenv("SHADOW_MODE", "false")
    mock_oci.waf.models.UpdateNetworkAddressListAddressesDetails.side_effect = lambda **kw: kw

    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    # Case 1: Existing addresses do not yet include 1.2.3.4/32
    existing_resp = MagicMock()
    existing_resp.data.addresses = ["203.0.113.99/32"]
    existing_resp.headers = {"etag": "etag-v1"}
    mock_client.get_network_address_list.return_value = existing_resp

    update_resp = MagicMock()
    update_resp.data = {"id": "updated"}
    mock_client.update_network_address_list.return_value = update_resp

    state = make_incident("autonomous", ip="1.2.3.4")
    res = execute_block_ip_waf(state)

    assert res.status == "executed"
    assert res.details["addresses"] == ["203.0.113.99/32", "1.2.3.4/32"]
    mock_client.get_network_address_list.assert_called_once_with("ocid1.wafnetworkaddresslist.oc1..test-block")
    mock_client.update_network_address_list.assert_called_once_with(
        network_address_list_id="ocid1.wafnetworkaddresslist.oc1..test-block",
        update_network_address_list_details={
            "display_name": "TestOCIBlockList",
            "addresses": ["203.0.113.99/32", "1.2.3.4/32"],
        },
        if_match="etag-v1",
    )

    # Case 2: IP already present -> idempotent skip without overwriting
    mock_client.reset_mock()
    existing_resp2 = MagicMock()
    existing_resp2.data.addresses = ["203.0.113.99/32", "1.2.3.4/32"]
    existing_resp2.headers = {"etag": "etag-v2"}
    mock_client.get_network_address_list.return_value = existing_resp2

    state_rate = make_incident("soft_contain", ip="1.2.3.4")
    res_rate = execute_soft_rate_limit(state_rate)
    assert res_rate.status == "executed"
    assert res_rate.details["already_present"] is True
    assert res_rate.details["addresses"] == ["203.0.113.99/32", "1.2.3.4/32"]
    mock_client.update_network_address_list.assert_not_called()


@patch("ai_engine.executor.oci_executor._audit")
def test_block_ip_waf_is_refused_for_pure_ssh_auth_incident(mock_audit):
    """Fix 4: Pure host SSH authentication incidents cannot be remediated via HTTP WAF block."""
    ssh_event = NormalizedEvent(
        event_id="evt-ssh-1",
        source="wazuh",
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.77",
        asset_tag="web-server",
        severity=5,
        raw_indicator="sshd: authentication failed",
        username="admin",
        auth_outcome="failure",
        user_valid=True,
    )
    state = IncidentState(
        incident_id="inc-ssh-only",
        correlation_key=("198.51.100.77", "web-server"),
        events=[ssh_event],
        status="closed",
        final_decision="autonomous",
    )
    res = execute_block_ip_waf(state)
    assert res.status == "refused"
    assert "pure host SSH" in res.details["error"]
