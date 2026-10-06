"""Pipeline tests: correlate -> triage -> mitre -> decision -> gate, with every LLM stage mocked."""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_engine.agents import base
from ai_engine.main import run_incident
from ai_engine.schemas.models import DecisionOutput, MitreOutput, TriageOutput
from ai_engine.tests.helpers import make_event

ASSET = "prod-web-server"
P = "ai_engine.graph.pipeline"


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    monkeypatch.setenv("AI_ENGINE_AUDIT_LOG", str(path))
    monkeypatch.setattr(base, "_audit_logger", None)
    audit = logging.getLogger("ai_engine.audit")
    audit.handlers.clear()
    yield path
    for h in list(audit.handlers):
        h.close()
    audit.handlers.clear()


def events():
    return [
        make_event("evt-101", 0, asset=ASSET, source="flowlog", severity=7, indicator="outbound beacon"),
        make_event("evt-102", 5, asset=ASSET, source="waf", severity=9, indicator="SQL injection"),
        make_event("evt-103", 9, asset=ASSET, source="wazuh", severity=8, indicator="web shell created"),
    ]


def triage(cite):
    return TriageOutput(timeline=["exploit", "beacon"], entities={"ips": ["198.51.100.44"]}, cited_event_ids=cite)


def mitre(cite, techniques=("T1190", "T1071")):
    return MitreOutput(techniques=list(techniques), justification={t: "x" for t in techniques}, cited_event_ids=cite)


def decision(cite, action="block_ip_waf"):
    return DecisionOutput(proposed_action=action, justification="proportionate", cited_event_ids=cite)


def audit_records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def test_clean_incident_reaches_autonomous(isolated_audit):
    cite = ["evt-101", "evt-102", "evt-103"]
    with patch(f"{P}.run_triage_agent", return_value=triage(cite)) as t, \
         patch(f"{P}.run_mitre_agent", return_value=mitre(cite)) as m, \
         patch(f"{P}.run_decision_agent", return_value=decision(cite)) as d:
        state = run_incident(events())
    assert (t.call_count, m.call_count, d.call_count) == (1, 1, 1)
    assert state.validation_errors == []
    assert state.risk_score >= 0.75
    assert state.final_decision == "autonomous"
    (record,) = audit_records(isolated_audit)
    assert record["record"] == "pipeline_decision" and record["final_decision"] == "autonomous"
    assert record["halted_at"] == "gate"


def test_triage_validation_failure_escalates_without_calling_mitre_or_decision(isolated_audit):
    with patch(f"{P}.run_triage_agent", return_value=triage(["evt-999"])), \
         patch(f"{P}.run_mitre_agent") as m, \
         patch(f"{P}.run_decision_agent") as d:
        state = run_incident(events())
    assert m.call_count == 0 and d.call_count == 0
    assert state.final_decision == "escalate"
    assert any("evt-999" in e for e in state.validation_errors)
    assert state.mitre is None and state.decision is None
    (record,) = audit_records(isolated_audit)
    assert record["halted_at"] == "triage" and record["final_decision"] == "escalate"


def test_agent_returning_none_escalates_and_stops(isolated_audit):
    with patch(f"{P}.run_triage_agent", return_value=None), \
         patch(f"{P}.run_mitre_agent") as m, patch(f"{P}.run_decision_agent") as d:
        state = run_incident(events())
    assert m.call_count == 0 and d.call_count == 0
    assert state.final_decision == "escalate" and state.validation_errors


def test_mitre_validation_failure_stops_before_decision(isolated_audit):
    cite = ["evt-101"]
    with patch(f"{P}.run_triage_agent", return_value=triage(cite)), \
         patch(f"{P}.run_mitre_agent", return_value=mitre(cite, ("T9999",))), \
         patch(f"{P}.run_decision_agent") as d:
        state = run_incident(events())
    assert d.call_count == 0 and state.final_decision == "escalate"
    assert audit_records(isolated_audit)[0]["halted_at"] == "mitre"


def test_agent_exception_fails_closed(isolated_audit):
    with patch(f"{P}.run_triage_agent", side_effect=RuntimeError("boom")):
        state = run_incident(events())
    assert state.final_decision == "escalate"


def test_empty_events_rejected():
    with pytest.raises(ValueError):
        run_incident([])
