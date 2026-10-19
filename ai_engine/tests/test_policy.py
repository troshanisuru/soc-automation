"""Tests for auth policy layer (ai_engine/gate/policy.py):
Rules R0-R5, rank-only-lowers guarantee, fail-closed handling, and NullBaseline.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from ai_engine.baseline.store import BaselineStore
from ai_engine.gate.policy import NullBaseline, _lower_decision, apply_auth_policy
from ai_engine.schemas.models import IncidentState
from ai_engine.tests.helpers import fill_stages, make_event, make_incident


@pytest.fixture
def memory_store():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    yield store
    store.close()


def _make_incident_with_decision(
    events,
    decision="autonomous",
    action="block_ip_waf",
    risk_score=0.85,
    asset=None,
    ip=None,
) -> IncidentState:
    if asset is None:
        asset = events[0].asset_tag if events else "web-server-01"
    if ip is None:
        ip = events[0].source_ip if events else "198.51.100.44"
    inc = make_incident(events, asset=asset, ip=ip)
    fill_stages(inc, action=action, cite=[e.event_id for e in events[:2]])
    inc.final_decision = decision
    inc.risk_score = risk_score
    return inc


# ------------------------------------------------------------------ NullBaseline & Helpers
def test_null_baseline_always_returns_false():
    nb = NullBaseline()
    assert nb.is_known_pair("alice", "198.51.100.44") is False
    assert nb.is_known_pair(None, "198.51.100.44") is False
    assert nb.is_known_pair("root", "127.0.0.1", datetime.now(timezone.utc)) is False


def test_lower_decision_rank_guarantees():
    # autonomous can be lowered to soft_contain or escalate
    assert _lower_decision("autonomous", "soft_contain") == "soft_contain"
    assert _lower_decision("autonomous", "escalate") == "escalate"
    assert _lower_decision("autonomous", "autonomous") == "autonomous"

    # soft_contain cannot be raised to autonomous
    assert _lower_decision("soft_contain", "autonomous") == "soft_contain"
    assert _lower_decision("soft_contain", "soft_contain") == "soft_contain"
    assert _lower_decision("soft_contain", "escalate") == "escalate"

    # escalate can NEVER be raised
    assert _lower_decision("escalate", "autonomous") == "escalate"
    assert _lower_decision("escalate", "soft_contain") == "escalate"
    assert _lower_decision("escalate", "escalate") == "escalate"

    # Unknown / None defaults to escalate
    assert _lower_decision(None, "autonomous") == "escalate"


# ------------------------------------------------------------------ Rule R0: No auth failures
def test_r0_no_auth_failures_maintains_gate_decision(memory_store):
    events = [
        make_event("evt-1", 0, source="waf", severity=9, indicator="SQLi"),
        make_event("evt-2", 5, source="wazuh", severity=8, indicator="web exploit"),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store)
    assert state.final_decision == "autonomous"


# ------------------------------------------------------------------ Rule R1: Multi-source
def test_r1_multi_source_incident_never_downgraded(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "alice"
    memory_store.record_success(user, ip, now - timedelta(days=2))

    # Multi-source: 1 WAF alert + 3 Wazuh auth failure alerts
    events = [
        make_event("evt-waf", 0, ip=ip, source="waf", severity=9, indicator="Bad WAF probe"),
        make_event("evt-auth-1", 10, ip=ip, source="wazuh", username=user, auth_outcome="failure"),
        make_event("evt-auth-2", 50, ip=ip, source="wazuh", username=user, auth_outcome="failure"),
        make_event("evt-auth-3", 90, ip=ip, source="wazuh", username=user, auth_outcome="failure"),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    # Even though user/IP is known and gaps >= 30s, multi-source retains autonomous
    assert state.final_decision == "autonomous"


# ------------------------------------------------------------------ Rule R2: Username spray
def test_r2_high_diversity_spray_never_downgraded(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"

    events = [
        make_event("evt-1", 0, ip=ip, username="admin", auth_outcome="failure"),
        make_event("evt-2", 35, ip=ip, username="root", auth_outcome="failure"),
        make_event("evt-3", 70, ip=ip, username="testuser", auth_outcome="failure"),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "autonomous"


def test_r2_invalid_user_ratio_never_downgraded(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"

    # 2 invalid users out of 3 (> 50% invalid)
    events = [
        make_event("evt-1", 0, ip=ip, username="ghost1", auth_outcome="failure", user_valid=False),
        make_event("evt-2", 35, ip=ip, username="ghost2", auth_outcome="failure", user_valid=False),
        make_event("evt-3", 70, ip=ip, username="realuser", auth_outcome="failure", user_valid=True),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "autonomous"


# ------------------------------------------------------------------ Rule R3: Stale credentials
def test_r3_stale_credentials_known_pair_downgrades_to_soft_contain(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "alice"
    memory_store.record_success(user, ip, now - timedelta(days=2))

    # Single known user, 60s gaps (>= 30s)
    events = [
        make_event(f"evt-{i}", offset=i * 60, ip=ip, username=user, auth_outcome="failure", user_valid=True)
        for i in range(5)
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "soft_contain"


def test_r3_does_not_downgrade_if_median_gap_too_fast(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "alice"
    memory_store.record_success(user, ip, now - timedelta(days=2))

    # Gaps are 10s (< 30s)
    events = [
        make_event(f"evt-{i}", offset=i * 10, ip=ip, username=user, auth_outcome="failure", user_valid=True)
        for i in range(5)
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    # Does not qualify for R3 stale password; remains autonomous
    assert state.final_decision == "autonomous"


def test_r3_does_not_downgrade_if_unknown_pair(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "unknown_user"
    # Not recorded in memory_store

    events = [
        make_event(f"evt-{i}", offset=i * 60, ip=ip, username=user, auth_outcome="failure", user_valid=True)
        for i in range(5)
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "autonomous"


# ------------------------------------------------------------------ Rule R4: Success after failure
def test_r4_success_after_failure_downgrades_to_soft_contain(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "bob"

    events = [
        make_event("evt-1", 0, ip=ip, username=user, auth_outcome="failure"),
        make_event("evt-2", 15, ip=ip, username=user, auth_outcome="failure"),
        make_event("evt-3", 30, ip=ip, username=user, auth_outcome="success"),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "soft_contain"


def test_r4_multiple_users_does_not_downgrade(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"

    events = [
        make_event("evt-1", 0, ip=ip, username="user1", auth_outcome="failure"),
        make_event("evt-2", 10, ip=ip, username="user2", auth_outcome="failure"),
        make_event("evt-3", 20, ip=ip, username="user1", auth_outcome="success"),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "autonomous"


# ------------------------------------------------------------------ Rule R5: Fast burst unknown pair
def test_r5_fast_burst_unknown_pair_maintains_gate_decision(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "stranger"

    events = [
        make_event(f"evt-{i}", offset=i * 2.0, ip=ip, username=user, auth_outcome="failure")
        for i in range(4)
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "autonomous"


# ------------------------------------------------------------------ Rank-Only-Lowers Guarantee
def test_rank_only_lowers_escalate_never_promoted(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "alice"
    memory_store.record_success(user, ip, now - timedelta(days=2))

    # Qualifies for R3, but gate decision was already 'escalate'
    events = [
        make_event(f"evt-{i}", offset=i * 60, ip=ip, username=user, auth_outcome="failure")
        for i in range(5)
    ]
    state = _make_incident_with_decision(events, decision="escalate")
    apply_auth_policy(state, baseline=memory_store, now=now)
    # Must remain escalate; can never raise!
    assert state.final_decision == "escalate"


def test_rank_only_lowers_soft_contain_never_promoted_to_autonomous(memory_store):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    events = [
        make_event("evt-1", 0, ip=ip, source="waf", severity=9),
    ]
    state = _make_incident_with_decision(events, decision="soft_contain")
    apply_auth_policy(state, baseline=memory_store, now=now)
    assert state.final_decision == "soft_contain"


# ------------------------------------------------------------------ Fail-Closed Guarantee
def test_fail_closed_on_none_decision(memory_store):
    events = [make_event("evt-1", 0, auth_outcome="failure")]
    state = _make_incident_with_decision(events, decision="autonomous")
    state.final_decision = None
    apply_auth_policy(state, baseline=memory_store)
    assert state.final_decision == "escalate"


def test_fail_closed_on_policy_exception():
    failing_baseline = MagicMock()
    failing_baseline.is_known_pair.side_effect = RuntimeError("Database disk full")

    events = [
        make_event("evt-1", 0, username="user", auth_outcome="failure"),
        make_event("evt-2", 30, username="user", auth_outcome="failure"),
        make_event("evt-3", 60, username="user", auth_outcome="failure"),
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    apply_auth_policy(state, baseline=failing_baseline)
    assert state.final_decision == "escalate"


# ------------------------------------------------------------------ Default NullBaseline behavior
def test_default_baseline_is_null_baseline():
    # Calling apply_auth_policy without baseline uses NullBaseline
    now = datetime.now(timezone.utc)
    ip = "198.51.100.44"
    user = "alice"

    events = [
        make_event(f"evt-{i}", offset=i * 60, ip=ip, username=user, auth_outcome="failure")
        for i in range(5)
    ]
    state = _make_incident_with_decision(events, decision="autonomous")
    # baseline=None -> NullBaseline: is_known_pair is False, so R3 does NOT match
    apply_auth_policy(state, baseline=None, now=now)
    assert state.final_decision == "autonomous"
