"""Deterministic risk scoring and the final gate decision - pure functions, no LLM.

All numbers (weights, thresholds, tactic weights, asset tiers) come from
config/thresholds.yaml and the MITRE reference; nothing is duplicated in code.
"""

import re
from typing import Literal, Mapping, Optional

from ai_engine.config.loader import ConfigError, Thresholds, get_mitre_reference, get_thresholds
from ai_engine.schemas.models import IncidentState, NormalizedEvent

Decision = Literal["autonomous", "soft_contain", "escalate"]

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_TRAILING_DIGITS = re.compile(r"\d+$")
_MAX_SOURCES = 3  # wazuh, waf, flowlog


def get_asset_criticality(asset_tag: str, thresholds: Optional[Thresholds] = None) -> float:
    """Asset criticality (0..1) from the static asset map.

    The tag is split into whole tokens (trailing digits stripped, so ``db01`` -> ``db``) and
    the highest matching tier wins. Whole-token matching replaces the old substring test,
    under which e.g. ``feedback-web`` matched ``db`` and ``latest-box`` matched ``test``.
    """
    cfg = thresholds or get_thresholds()
    tokens = (_TRAILING_DIGITS.sub("", t) for t in _TOKEN_SPLIT.split(asset_tag.lower()))
    scores = [cfg.asset_tiers[t] for t in tokens if t and t in cfg.asset_tiers]
    return max(scores) if scores else cfg.asset_default


def technique_severity(technique_id: str, thresholds: Optional[Thresholds] = None) -> float:
    """Tactic-weighted severity. Unknown techniques score 0.0 - a hallucinated technique
    must never raise the score (the validator also flags it, forcing escalation)."""
    cfg = thresholds or get_thresholds()
    try:
        technique = get_mitre_reference().get(technique_id)
    except ConfigError:
        return 0.0
    return cfg.tactic_weights.get(technique.tactic, 0.0) if technique else 0.0


def _cited_events(state: IncidentState) -> list[NormalizedEvent]:
    """Events actually cited by the agents (plan: 'distinct source values in cited events').
    Non-existent ids are ignored here; the validator reports them."""
    cited_ids: set[str] = set()
    for stage in (state.triage, state.mitre, state.decision):
        if stage is not None:
            cited_ids.update(stage.cited_event_ids)
    return [e for e in state.events if e.event_id in cited_ids]


def compute_risk_score(state: IncidentState, weights: Optional[Mapping[str, float]] = None) -> float:
    """Weighted sum in [0, 1] of:
      * MITRE technique severity (tactic-weighted, max over proposed techniques)
      * asset criticality (static map, from the correlation key)
      * evidence source count (distinct ``source`` among cited events, out of 3)
      * signature confidence (max native severity among cited events, 0-10 -> 0-1)
    Not rounded: rounding before the threshold comparison could push 0.7496 over 0.75.
    """
    cfg = get_thresholds()
    w = cfg.weights if weights is None else weights

    mitre = state.mitre
    mitre_score = max((technique_severity(t, cfg) for t in mitre.techniques), default=0.0) if mitre else 0.0

    asset_score = get_asset_criticality(state.correlation_key[1], cfg)

    cited = _cited_events(state)
    source_score = min(len({e.source for e in cited}) / _MAX_SOURCES, 1.0)
    signature_score = max((e.severity for e in cited), default=0) / 10.0

    score = (
        w["mitre_severity"] * mitre_score
        + w["asset_criticality"] * asset_score
        + w["source_diversity"] * source_score
        + w["signature_confidence"] * signature_score
    )
    return float(min(max(score, 0.0), 1.0))


def _decide(state: IncidentState, score: float, autonomous: float, soft: float) -> Decision:
    # Any validation error overrides every score.
    if state.validation_errors:
        return "escalate"
    # Any stage that produced nothing (timeout / crash / invalid schema) forces escalation.
    if state.triage is None or state.mitre is None or state.decision is None:
        return "escalate"
    # A high-risk incident that the model wants to ignore is exactly what a successful
    # prompt injection looks like - a human must look at it.
    if state.decision.proposed_action == "no_action" and score >= soft:
        return "escalate"
    if score >= autonomous:
        return "autonomous"
    if score >= soft:
        # soft tier: only the least-invasive action may run unattended
        return "soft_contain" if state.decision.proposed_action == "soft_rate_limit" else "escalate"
    return "escalate"


def determine_final_decision(
    state: IncidentState,
    autonomous_threshold: Optional[float] = None,
    soft_contain_threshold: Optional[float] = None,
) -> Decision:
    """Final decision from the score tiers. Always recomputes the score from the evidence:
    a ``risk_score`` already on the state (e.g. from a deserialised/forged object) is never trusted."""
    cfg = get_thresholds()
    autonomous = cfg.autonomous_threshold if autonomous_threshold is None else autonomous_threshold
    soft = cfg.soft_threshold if soft_contain_threshold is None else soft_contain_threshold
    return _decide(state, compute_risk_score(state), autonomous, soft)


def apply_gate(state: IncidentState) -> IncidentState:
    """Compute the risk score once and set ``risk_score`` and ``final_decision`` (gate-only fields)."""
    cfg = get_thresholds()
    score = compute_risk_score(state)
    state.risk_score = score
    state.final_decision = _decide(state, score, cfg.autonomous_threshold, cfg.soft_threshold)
    return state
