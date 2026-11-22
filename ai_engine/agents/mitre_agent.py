import json
from typing import List, Optional

from ai_engine.agents.base import call_agent, format_events_for_prompt
from ai_engine.config.loader import ConfigError, get_mitre_reference
from ai_engine.schemas.models import MitreOutput, NormalizedEvent

_MITRE_BASE_PROMPT = """You are a MITRE ATT&CK Mapping Agent in a Security Operations Center.
Map the observed activity (triage timeline + events) ONLY to exact technique IDs from the Allowed Catalog below.

Mapping Guidelines:
- Web attacks against HTTP/WAF (SQL injection, XSS, ModSecurity 403 blocks, web exploits) -> T1190 (NOT T1021 or T1210!).
- OS command injection, RCE, /bin/sh, /bin/bash, shell spawning -> T1059.
- Path traversal / reading /etc/passwd or /etc/shadow -> T1005 (and T1190 if via web).
- Sensitive credential/config file access (/.env, /.git) -> T1552.
- Automated vulnerability scanners (sqlmap, nikto) -> T1595. Port scanning -> T1046.
- SSH/login brute force or username spraying -> T1110.
- Use T1021 / T1210 ONLY for confirmed internal lateral movement between hosts (e.g. web tier -> DB tier), NEVER for external HTTP WAF blocks.

Output fields:
- techniques: list of technique IDs in the exact form T#### from the Allowed Catalog. No sub-techniques.
- justification: object mapping each technique ID you list to a one-line reason.
- cited_event_ids: event_id values copied exactly from the input. Never invent an event_id.
If nothing maps to a technique, return an empty techniques list.
"""


def _build_mitre_system_prompt() -> str:
    """Attach the exact validated MITRE ATT&CK catalog from reference/mitre_attack.json so small LLMs never mis-map IDs."""
    try:
        ref = get_mitre_reference()
        catalog_lines = [
            f"- {tid}: {tech.name} ({tech.tactic})"
            for tid, tech in sorted(ref.items())
        ]
        return _MITRE_BASE_PROMPT + "\nAllowed Catalog:\n" + "\n".join(catalog_lines)
    except ConfigError:
        return _MITRE_BASE_PROMPT


MITRE_SYSTEM_PROMPT = _build_mitre_system_prompt()

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
        system_prompt=_build_mitre_system_prompt(),
        user_payload=payload,
        schema=MitreOutput,
    )
