"""LangGraph graph wiring and supervisor logic.

Plan section 8, as a strictly sequential, fail-closed chain:

    correlate (code) -> triage (LLM) -> validate -> mitre (LLM) -> validate
        -> decision (LLM) -> validate -> gate (code, scoring) -> execute | escalate -> audit log

Every stage failure (agent returned None, agent raised, validation errors) short-circuits
straight to ``escalate`` plus an audit entry - nothing falls through to the next stage.
Agents only propose; the only thing this module decides is the ordering. The final
decision is always written by ``gate.scoring`` or forced to "escalate" here.

No executor exists yet (``cooldown_seconds`` is reserved for it), so "execute" is limited
to recording the gate verdict; a future executor must act only on ``final_decision``.
"""

import logging
import time
from datetime import timedelta
from typing import Callable, List, Optional

from ai_engine.agents import base
from ai_engine.agents.decision_agent import run_decision_agent
from ai_engine.agents.mitre_agent import run_mitre_agent
from ai_engine.agents.triage_agent import run_triage_agent
from ai_engine.correlation.correlate import EventCorrelator
from ai_engine.gate.scoring import apply_gate
from ai_engine.gate.validator import validate_incident_state
from ai_engine.schemas.models import IncidentState, NormalizedEvent

logger = logging.getLogger("ai_engine.pipeline")


class PipelineInputError(ValueError):
    """The supplied events cannot form exactly one incident."""


def _audit_final(state: IncidentState, stage: str, started: float) -> None:
    base._audit(
        {
            "ts": time.time(),
            "record": "pipeline_decision",
            "incident_id": state.incident_id,
            "correlation_key": list(state.correlation_key),
            "event_count": len(state.events),
            "halted_at": stage,
            "risk_score": state.risk_score,
            "final_decision": state.final_decision,
            "proposed_action": state.decision.proposed_action if state.decision else None,
            "validation_errors": list(state.validation_errors),
            "duration_ms": round((time.perf_counter() - started) * 1000),
        }
    )


def _escalate(state: IncidentState, stage: str, reason: str, started: float) -> IncidentState:
    if reason not in state.validation_errors:
        state.validation_errors.append(reason)
    state.final_decision = "escalate"
    logger.warning("[%s] halting pipeline, escalating: %s", stage, reason)
    _audit_final(state, stage, started)
    return state


def _correlate(events: List[NormalizedEvent]) -> IncidentState:
    if not events:
        raise PipelineInputError("no events supplied")
    correlator = EventCorrelator()
    for event in events:
        correlator.process_event(event)
    latest = max(e.timestamp for e in events)
    incidents = correlator.finalize_expired_incidents(latest + timedelta(days=1))
    if len(incidents) != 1:
        raise PipelineInputError(
            f"events formed {len(incidents)} incidents; run_incident needs exactly one correlation key/window"
        )
    return incidents[0]


def _run_stage(state: IncidentState, name: str, fn: Callable[[], object], started: float) -> bool:
    """Run one LLM stage + validation. True = proceed; False = state already escalated."""
    try:
        output = fn()
    except Exception as exc:  # contract: never raise into the caller
        _escalate(state, name, f"{name} stage raised {type(exc).__name__}", started)
        return False
    if output is None:
        _escalate(state, name, f"{name} stage produced no valid output (timeout/invalid/oversized)", started)
        return False
    setattr(state, name, output)
    validate_incident_state(state)
    if state.validation_errors:
        _escalate(state, name, f"{name} validation failed", started)
        return False
    return True


def run_pipeline(events: List[NormalizedEvent]) -> IncidentState:
    started = time.perf_counter()
    state = _correlate(events)

    if not _run_stage(state, "triage", lambda: run_triage_agent(state.events), started):
        return state
    if not _run_stage(state, "mitre", lambda: run_mitre_agent(state.triage.timeline, state.events), started):
        return state
    if not _run_stage(state, "decision", lambda: run_decision_agent(state.triage, state.mitre), started):
        return state

    try:
        apply_gate(state)
    except Exception as exc:
        return _escalate(state, "gate", f"gate raised {type(exc).__name__}", started)
    _audit_final(state, "gate", started)
    return state
