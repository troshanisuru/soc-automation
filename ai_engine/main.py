"""AI Engine Entrypoint: event in -> decision out."""

from typing import List

from ai_engine.graph.pipeline import run_pipeline
from ai_engine.schemas.models import IncidentState, NormalizedEvent


def run_incident(events: List[NormalizedEvent]) -> IncidentState:
    """Run the full chain (correlate -> triage -> mitre -> decision -> gate) and return the
    final state. ``final_decision`` is always set; any failure yields "escalate"."""
    return run_pipeline(events)
