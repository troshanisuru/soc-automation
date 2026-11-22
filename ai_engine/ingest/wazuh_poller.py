import os
import re
import json
import time
import uuid
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional
from ai_engine.schemas.models import EVENT_ID_PATTERN, IncidentState, NormalizedEvent
from ai_engine.correlation.correlate import EventCorrelator
from ai_engine.graph.pipeline import run_incident_state
from ai_engine.main import run_incident
from ai_engine.baseline.store import BaselineStore
from ai_engine.executor.oci_executor import (
    ExecutionResult,
    execute_block_ip_waf,
    execute_isolate_sg,
    execute_no_action,
    execute_soft_rate_limit,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AUTH_ALLOWLIST_RULES = {"5710", "5715", "5716", "100301"}
_EVENT_ID_RE = re.compile(EVENT_ID_PATTERN)
_INVALID_EVENT_ID_CHARS = re.compile(r"[^A-Za-z0-9._:\-]")

_baseline_store: Optional[BaselineStore] = None
_correlator: Optional[EventCorrelator] = None

def get_baseline_store() -> BaselineStore:
    global _baseline_store
    if _baseline_store is None:
        _baseline_store = BaselineStore()
    return _baseline_store

def get_correlator() -> EventCorrelator:
    global _correlator
    if _correlator is None:
        _correlator = EventCorrelator()
    return _correlator

def _derive_event_id(alert_dict: dict) -> str:
    raw_id = alert_dict.get("id")
    if raw_id is not None:
        cleaned = _INVALID_EVENT_ID_CHARS.sub("_", str(raw_id).strip())[:128]
        if _EVENT_ID_RE.fullmatch(cleaned):
            return cleaned
    return f"evt-{uuid.uuid4().hex[:8]}"

def parse_wazuh_alert(alert_dict: dict) -> NormalizedEvent:
    """Convert a Wazuh alert JSON dict into a NormalizedEvent."""
    # Extract timestamp
    raw_ts = alert_dict.get("timestamp", datetime.now(timezone.utc).isoformat())
    if raw_ts.endswith("Z"):
        raw_ts = raw_ts[:-1] + "+00:00"
    
    # Extract source IP
    data = alert_dict.get("data", {})
    src_ip = data.get("srcip")
    if not src_ip:
        # Check OCI WAF / VCN Flow Log format or S3-compatible WAF format
        src_ip = (
            data.get("oci", {}).get("httpRequest", {}).get("clientIp")
            or data.get("oci", {}).get("sourceAddress")
            or data.get("aws", {}).get("httpRequest", {}).get("clientIp")
        )
    if not src_ip:
        src_ip = "0.0.0.0"
        
    # Extract asset tag
    asset_tag = alert_dict.get("agent", {}).get("name", "unknown")
    
    # Extract rule info (clamp Wazuh 0-15 scale into NormalizedEvent 0-10 severity scale)
    rule = alert_dict.get("rule", {})
    raw_level = rule.get("level", 1)
    severity = min(max(int(raw_level), 0), 10)
    raw_indicator = rule.get("description", "Unknown alert")

    rule_id = str(rule.get("id", ""))
    rule_groups = set(rule.get("groups", []) or [])
    event_source = "waf" if (rule_id.startswith("1004") or "modsecurity" in rule_groups) else "wazuh"

    # Enrich ModSecurity WAF indicators with extracted CRS rule ID, target URL, and Wazuh native MITRE hints
    if event_source == "waf":
        modsec = data.get("modsec", {}) if isinstance(data.get("modsec"), dict) else {}
        extras = []
        if modsec.get("rule_id"):
            extras.append(f"CRS={modsec['rule_id']}")
        if data.get("url"):
            extras.append(f"url={data['url']}")
        mitre_ids = rule.get("mitre", {}).get("id") if isinstance(rule.get("mitre"), dict) else None
        if isinstance(mitre_ids, list) and mitre_ids:
            extras.append(f"mitre_hint={','.join(str(m) for m in mitre_ids)}")
        if extras:
            raw_indicator = f"{raw_indicator} ({', '.join(extras)})"

    username = None
    auth_outcome = None
    user_valid = None

    if rule_id in ("5710", "5716", "5715", "100301"):
        username = data.get("dstuser") or data.get("srcuser")
        if rule_id == "5710":
            auth_outcome = "failure"
            user_valid = False
        elif rule_id == "5716":
            auth_outcome = "failure"
            user_valid = True
        elif rule_id == "5715":
            auth_outcome = "success"
            user_valid = True
        elif rule_id == "100301":
            auth_outcome = None
            user_valid = None

    return NormalizedEvent(
        event_id=_derive_event_id(alert_dict),
        source=event_source,
        timestamp=datetime.fromisoformat(raw_ts),
        source_ip=src_ip,
        asset_tag=asset_tag,
        severity=severity,
        raw_indicator=raw_indicator,
        username=username,
        auth_outcome=auth_outcome,
        user_valid=user_valid,
    )

def poll_alerts(log_path: str, interval: int = 30):
    logger.info(f"Starting Wazuh poller on {log_path} (interval: {interval}s)")
    if not os.path.exists(log_path):
        logger.warning(f"Alert log file not found: {log_path}")

    start_from_end = os.getenv("WAZUH_START_FROM_END", "false").lower() in ("true", "1", "yes")
    last_pos = os.path.getsize(log_path) if (start_from_end and os.path.exists(log_path)) else 0
    if start_from_end:
        logger.info(f"Starting from EOF offset {last_pos} bytes")

    store = get_baseline_store()
    correlator = get_correlator()

    while True:
        complete_lines = []
        if os.path.exists(log_path):
            file_size = os.path.getsize(log_path)
            if file_size < last_pos:
                last_pos = 0  # handle log rotation
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(last_pos)
                while True:
                    pos_before = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith('\n'):
                        # Incomplete write in progress; rewind and read on next poll
                        f.seek(pos_before)
                        break
                    complete_lines.append(line)
                last_pos = f.tell()

        process_lines(complete_lines, store=store, correlator=correlator)
        time.sleep(interval)

def dispatch_execution(incident_state: IncidentState) -> Optional[ExecutionResult]:
    """Execute action based on incident's final_decision.

    - escalate: no call (returns None)
    - soft_contain: soft_rate_limit only
    - autonomous: matching execute_* for proposed_action
    """
    decision = incident_state.final_decision
    if decision == "escalate":
        return None
    elif decision == "soft_contain":
        return execute_soft_rate_limit(incident_state)
    elif decision == "autonomous":
        proposed = incident_state.decision.proposed_action if incident_state.decision else None
        if proposed == "block_ip_waf":
            return execute_block_ip_waf(incident_state)
        elif proposed == "isolate_sg":
            return execute_isolate_sg(incident_state)
        elif proposed == "soft_rate_limit":
            return execute_soft_rate_limit(incident_state)
        elif proposed == "no_action":
            return execute_no_action(incident_state)
        else:
            logger.warning(f"No executor matching autonomous proposed_action: {proposed}")
            return None
    return None


def _is_only_benign_auth_success(events: list) -> bool:
    return bool(events) and all(e.auth_outcome == "success" for e in events)


def _handle_incident_result(incident_state: Optional[IncidentState]) -> None:
    if incident_state:
        execution_result = dispatch_execution(incident_state)
        logger.info(
            f"Final Decision for incident {incident_state.incident_id}: {incident_state.final_decision} | Execution: {execution_result}"
        )
    else:
        logger.warning("run_incident returned None")


def process_lines(
    lines: list,
    store: Optional[BaselineStore] = None,
    correlator: Optional[EventCorrelator] = None,
    now: Optional[datetime] = None,
):
    if store is None:
        store = get_baseline_store()

    events_by_key = defaultdict(list)
    all_events = []
    ips_with_failures = set()
    
    min_level = int(os.getenv("WAZUH_MIN_ALERT_LEVEL", "0"))
    require_srcip = os.getenv("WAZUH_REQUIRE_SRCIP", "false").lower() in ("true", "1", "yes")

    for line in lines:
        if not line.strip():
            continue
        try:
            alert = json.loads(line)
            rule = alert.get("rule", {})
            rule_id = str(rule.get("id", ""))
            rule_level = int(rule.get("level", 0))
            if min_level > 0 and rule_level < min_level and rule_id not in AUTH_ALLOWLIST_RULES:
                continue
            event = parse_wazuh_alert(alert)
            if require_srcip and event.source_ip in ("0.0.0.0", "::"):
                continue
            all_events.append(event)
            if event.auth_outcome == "failure":
                ips_with_failures.add(event.source_ip)
            key = (event.source_ip, event.asset_tag)
            events_by_key[key].append(event)
        except json.JSONDecodeError:
            logger.error("Failed to parse alert line as JSON")
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            
    # Baseline learning: record successes only if source_ip had no failures in this batch
    for event in all_events:
        if event.auth_outcome == "success" and event.source_ip not in ips_with_failures:
            if event.username:
                store.record_success(event.username, event.source_ip, event.timestamp)

    if correlator is not None:
        for event in all_events:
            correlator.process_event(event, now=now)
        for incident in correlator.finalize_expired_incidents(current_time=now):
            if _is_only_benign_auth_success(incident.events):
                logger.info(
                    f"Skipping incident {incident.incident_id} for key {incident.correlation_key}: benign auth successes only"
                )
                continue
            logger.info(
                f"Running correlated incident {incident.incident_id} for key {incident.correlation_key} with {len(incident.events)} events"
            )
            try:
                with correlator.processing_lock(incident) as acquired:
                    if not acquired:
                        continue
                    incident_state = run_incident_state(incident, baseline=store, now=now)
                    _handle_incident_result(incident_state)
            except Exception as e:
                logger.error(f"Error running incident: {e}")
        return

    for key, events in events_by_key.items():
        if _is_only_benign_auth_success(events):
            logger.info(f"Skipping incident for key {key}: benign auth successes only")
            continue
        logger.info(f"Running incident for key: {key} with {len(events)} events")
        try:
            incident_state = run_incident(events, baseline=store)
            _handle_incident_result(incident_state)
        except Exception as e:
            logger.error(f"Error running incident: {e}")

if __name__ == "__main__":
    ALERTS_FILE = os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
    POLL_INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "30"))
    poll_alerts(ALERTS_FILE, POLL_INTERVAL)
