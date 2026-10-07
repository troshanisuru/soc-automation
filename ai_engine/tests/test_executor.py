import json
from unittest.mock import patch

import pytest

from ai_engine.executor.boto3_executor import (
    execute_block_ip_waf,
    execute_soft_rate_limit,
    execute_isolate_sg,
    execute_no_action
)
from ai_engine.schemas.models import IncidentState, NormalizedEvent
from datetime import datetime, timezone

def make_incident(final_decision: str) -> IncidentState:
    event = NormalizedEvent(
        event_id="evt-1",
        source="wazuh",
        timestamp=datetime.now(timezone.utc),
        source_ip="1.2.3.4",
        asset_tag="test-asset",
        severity=5,
        raw_indicator="test"
    )
    return IncidentState(
        incident_id="inc-test",
        correlation_key=("1.2.3.4", "test-asset"),
        events=[event],
        status="open",
        final_decision=final_decision
    )

@pytest.fixture(autouse=True)
def setup_env_vars(monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "true")
    monkeypatch.setenv("WAF_BLOCK_IP_SET_NAME", "TestBlockSet")
    monkeypatch.setenv("WAF_BLOCK_IP_SET_ID", "test-block-id")
    monkeypatch.setenv("WAF_RATELIMIT_IP_SET_NAME", "TestRateLimitSet")
    monkeypatch.setenv("WAF_RATELIMIT_IP_SET_ID", "test-ratelimit-id")
    monkeypatch.setenv("WAF_SCOPE", "REGIONAL")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("ISOLATE_SG_ID", "sg-test1234")

@patch("ai_engine.executor.boto3_executor._audit")
def test_escalate_is_refused(mock_audit):
    state = make_incident("escalate")
    res = execute_block_ip_waf(state)
    assert res.status == "refused"
    assert "escalate decision refuses" in res.details["error"]
    
    res2 = execute_soft_rate_limit(state)
    assert res2.status == "refused"

@patch("ai_engine.executor.boto3_executor._audit")
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

@patch("ai_engine.executor.boto3_executor.boto3.client")
@patch("ai_engine.executor.boto3_executor._audit")
def test_shadow_mode_simulates_only(mock_audit, mock_boto3):
    state = make_incident("autonomous")
    
    # By default SHADOW_MODE=true in fixture
    res = execute_block_ip_waf(state)
    assert res.status == "simulated"
    
    # Verify boto3 was NEVER called
    mock_boto3.assert_not_called()
    
    # Verify audit logger was called with kwargs
    mock_audit.assert_called()
    call_record = mock_audit.call_args[0][0]
    assert call_record["status"] == "simulated"
    assert call_record["shadow_mode"] is True
    assert call_record["kwargs"]["Name"] == "TestBlockSet"
    assert call_record["kwargs"]["Addresses"] == ["1.2.3.4/32"]
    
@patch("ai_engine.executor.boto3_executor.boto3.client")
@patch("ai_engine.executor.boto3_executor._audit")
def test_isolate_sg_builds_correct_kwargs(mock_audit, mock_boto3):
    state = make_incident("autonomous")
    res = execute_isolate_sg(state)
    
    assert res.status == "simulated"
    call_record = mock_audit.call_args[0][0]
    
    kwargs = call_record["kwargs"]
    assert kwargs["GroupId"] == "sg-test1234"
    assert kwargs["IpPermissions"][0]["IpProtocol"] == "-1"
    assert kwargs["IpPermissions"][0]["IpRanges"][0]["CidrIp"] == "1.2.3.4/32"
