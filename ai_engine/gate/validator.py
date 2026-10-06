"""Deterministic content validator - runs after every agent call, before the next stage.

Schema shape is already enforced at the LLM-call level; this layer checks *content*:
every cited event_id really exists, every MITRE id is in the local reference, and an
agent cannot dodge the evidence check by citing nothing. Pure functions, no LLM.

Idempotent: it is called after each stage and re-checks the whole state, so errors are
de-duplicated instead of piling up on every call.
"""

import logging
from typing import Iterable, Optional, Set

from ai_engine.config.loader import ConfigError, get_mitre_reference
from ai_engine.schemas.models import IncidentState

logger = logging.getLogger("ai_engine.gate.validator")


def load_mitre_techniques() -> Set[str]:
    """Valid technique ids from reference/mitre_attack.json (raises ConfigError if unusable)."""
    return set(get_mitre_reference())


def _add_error(state: IncidentState, message: str) -> None:
    if message not in state.validation_errors:
        state.validation_errors.append(message)


def _check_citations(
    state: IncidentState,
    label: str,
    cited: Iterable[str],
    valid_ids: Set[str],
    *,
    required: bool,
) -> None:
    cited = list(dict.fromkeys(cited))  # de-duplicate, keep order
    if required and not cited:
        _add_error(state, f"{label} cited no evidence event_ids")
    for cid in cited:
        if cid not in valid_ids:
            _add_error(state, f"{label} cited non-existent event_id {cid!r} (hallucinated evidence)")


def validate_incident_state(
    state: IncidentState,
    known_mitre_techniques: Optional[Set[str]] = None,
) -> IncidentState:
    """Append every content violation to ``state.validation_errors`` and return the state.

    Checks:
      1. Every cited_event_id (triage / mitre / decision) exists in ``state.events``.
      2. Triage and MITRE must cite at least one event; a decision must too unless it is
         ``no_action`` (otherwise an agent could pass by citing nothing).
      3. Every proposed MITRE technique exists in the local reference.
      4. Every MITRE justification key refers to a proposed technique.
    If the MITRE reference cannot be loaded the gate fails closed (error recorded -> escalate).
    """
    valid_ids = {event.event_id for event in state.events}

    if state.triage:
        _check_citations(state, "Triage", state.triage.cited_event_ids, valid_ids, required=True)

    if state.mitre:
        _check_citations(state, "MITRE agent", state.mitre.cited_event_ids, valid_ids, required=True)

        known = known_mitre_techniques
        if known is None and state.mitre.techniques:
            try:
                known = load_mitre_techniques()
            except ConfigError as exc:
                logger.error("MITRE reference unavailable: %s", exc)
                _add_error(state, "MITRE reference unavailable; cannot validate techniques (fail closed)")
        if known is not None:
            for technique in dict.fromkeys(state.mitre.techniques):
                if technique not in known:
                    _add_error(state, f"MITRE agent proposed unknown technique ID {technique!r}")

        proposed = set(state.mitre.techniques)
        for key in state.mitre.justification:
            if key not in proposed:
                _add_error(state, f"MITRE justification given for non-proposed technique {key!r}")

    if state.decision:
        _check_citations(
            state,
            "Decision agent",
            state.decision.cited_event_ids,
            valid_ids,
            required=state.decision.proposed_action != "no_action",
        )

    return state
