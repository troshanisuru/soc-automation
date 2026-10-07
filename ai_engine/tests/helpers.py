"""Shared test helpers."""

from datetime import datetime, timedelta, timezone

from ai_engine.schemas.models import (
    DecisionOutput,
    IncidentState,
    MitreOutput,
    NormalizedEvent,
    TriageOutput,
)

T0 = datetime.now(timezone.utc) - timedelta(seconds=60)


def make_event(
    event_id: str,
    offset: float = 0,
    ip: str = "198.51.100.44",
    asset: str = "web-server-01",
    source: str = "wazuh",
    severity: int = 5,
    indicator: str = "test indicator",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        source=source,
        timestamp=T0 + timedelta(seconds=offset),
        source_ip=ip,
        asset_tag=asset,
        severity=severity,
        raw_indicator=indicator,
    )


def make_incident(events, asset: str = "prod-web-server", ip: str = "198.51.100.44") -> IncidentState:
    return IncidentState(
        incident_id="inc-test",
        correlation_key=(ip, asset),
        events=list(events),
        status="closed",
    )


def fill_stages(
    state: IncidentState,
    techniques=("T1190", "T1071"),
    action: str = "block_ip_waf",
    cite=("evt-101", "evt-102"),
) -> IncidentState:
    """Populate triage/mitre/decision with well-formed, valid agent outputs."""
    state.triage = TriageOutput(
        timeline=["web exploit observed", "outbound beacon observed"],
        entities={"ips": [state.correlation_key[0]], "assets": [state.correlation_key[1]]},
        cited_event_ids=list(cite),
    )
    state.mitre = MitreOutput(
        techniques=list(techniques),
        justification={t: "mapped from evidence" for t in techniques},
        cited_event_ids=list(cite),
    )
    state.decision = DecisionOutput(
        proposed_action=action,
        justification="proportionate to the evidence",
        cited_event_ids=list(cite),
    )
    return state
