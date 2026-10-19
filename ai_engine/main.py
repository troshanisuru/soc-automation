"""AI Engine Entrypoint: event in -> decision out."""

from datetime import datetime
from typing import Any, List, Optional

from ai_engine.graph.pipeline import run_pipeline
from ai_engine.schemas.models import IncidentState, NormalizedEvent


def run_incident(
    events: List[NormalizedEvent],
    baseline: Any = None,
    now: Optional[datetime] = None,
) -> IncidentState:
    """Run the full chain (correlate -> triage -> mitre -> decision -> gate -> policy) and return the
    final state. ``final_decision`` is always set; any failure yields "escalate"."""
    return run_pipeline(events, baseline=baseline, now=now)
