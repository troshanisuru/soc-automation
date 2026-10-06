from typing import List, Optional

from ai_engine.agents.base import call_agent, format_events_for_prompt
from ai_engine.schemas.models import NormalizedEvent, TriageOutput

TRIAGE_SYSTEM_PROMPT = """You are a Security Operations Center (SOC) Triage Agent.
Examine the correlated security events, build an ordered timeline of what happened, extract the key entities, and cite the event_ids you used as evidence.

Output fields:
- timeline: ordered list of short, human-readable steps.
- entities: object with keys "ips" (list of IP strings) and "assets" (list of asset tags).
- cited_event_ids: event_id values copied exactly from the input. Never invent an event_id.
"""


def run_triage_agent(events: List[NormalizedEvent]) -> Optional[TriageOutput]:
    """Triage Agent. Input: correlated events. Output: TriageOutput (None on any failure)."""
    if not events:
        return None
    return call_agent(
        agent_name="triage_agent",
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_payload=format_events_for_prompt(events),
        schema=TriageOutput,
    )
