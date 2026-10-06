import json
from typing import List, Optional

from ai_engine.agents.base import call_agent, format_events_for_prompt
from ai_engine.schemas.models import MitreOutput, NormalizedEvent

MITRE_SYSTEM_PROMPT = """You are a MITRE ATT&CK Mapping Agent in a Security Operations Center.
Map the observed activity (triage timeline + events) to MITRE ATT&CK technique IDs.

Output fields:
- techniques: list of technique IDs in the exact form T#### (for example T1190, T1071, T1021). No sub-techniques.
- justification: object mapping each technique ID you list to a one-line reason.
- cited_event_ids: event_id values copied exactly from the input. Never invent an event_id.
If nothing maps to a technique, return an empty techniques list.
"""

_MAX_TIMELINE_STEPS = 25


def run_mitre_agent(timeline: List[str], events: List[NormalizedEvent]) -> Optional[MitreOutput]:
    """MITRE Agent. Input: triage timeline + events. Output: MitreOutput (None on any failure).

    The timeline is itself model output derived from untrusted logs, so it is quoted
    (json.dumps) and travels inside the <untrusted_log> boundary like everything else."""
    if not events:
        return None
    steps = "\n".join(f"- {json.dumps(step)}" for step in timeline[:_MAX_TIMELINE_STEPS]) or "- (none)"
    payload = f"Triage timeline:\n{steps}\n\nEvents:\n{format_events_for_prompt(events)}"
    return call_agent(
        agent_name="mitre_agent",
        system_prompt=MITRE_SYSTEM_PROMPT,
        user_payload=payload,
        schema=MitreOutput,
    )
