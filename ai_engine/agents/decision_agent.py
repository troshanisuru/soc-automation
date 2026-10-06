import json
from typing import Optional

from ai_engine.agents.base import call_agent
from ai_engine.schemas.models import DecisionOutput, MitreOutput, TriageOutput

DECISION_SYSTEM_PROMPT = """You are a SOC Response Decision Agent. You only PROPOSE an action; you never execute anything.
Review the triage summary and MITRE analysis and propose exactly ONE action:
- "block_ip_waf": active web exploitation (SQLi, injection) from one source IP
- "isolate_sg": confirmed host compromise, command-and-control, or lateral movement toward a database
- "soft_rate_limit": moderate scanning, unconfirmed probing, mild brute force
- "no_action": benign traffic or a false positive

Output fields:
- proposed_action: one of the four values above.
- justification: one or two sentences explaining why the action is proportionate.
- cited_event_ids: event_id values copied exactly from "Available evidence event IDs". Never invent one.
"""

_MAX_TIMELINE_STEPS = 25


def run_decision_agent(
    triage: Optional[TriageOutput], mitre: Optional[MitreOutput]
) -> Optional[DecisionOutput]:
    """Decision Agent. Input: TriageOutput + MitreOutput. Output: DecisionOutput (None on any failure).

    Never calls Boto3 / any executor - it only proposes. Evidence ids are sorted so the
    prompt is deterministic (stable for caching and reproducible tests)."""
    if triage is None and mitre is None:
        return None
    timeline = [json.dumps(t) for t in (triage.timeline[:_MAX_TIMELINE_STEPS] if triage else [])]
    entities = json.dumps(triage.entities, sort_keys=True) if triage else "{}"
    techniques = list(mitre.techniques) if mitre else []
    evidence = sorted(
        set((triage.cited_event_ids if triage else []) + (mitre.cited_event_ids if mitre else []))
    )
    payload = (
        "Triage timeline:\n" + ("\n".join(f"- {t}" for t in timeline) or "- (none)") + "\n"
        f"Entities: {entities}\n"
        f"MITRE techniques: {json.dumps(techniques)}\n"
        f"Available evidence event IDs: {json.dumps(evidence)}"
    )
    return call_agent(
        agent_name="decision_agent",
        system_prompt=DECISION_SYSTEM_PROMPT,
        user_payload=payload,
        schema=DecisionOutput,
    )
