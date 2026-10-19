import os
import json
import time
import uuid
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional
from ai_engine.schemas.models import IncidentState, NormalizedEvent
from ai_engine.main import run_incident
from ai_engine.baseline.store import BaselineStore
from ai_engine.executor.boto3_executor import (
    ExecutionResult,
    execute_block_ip_waf,
    execute_isolate_sg,
    execute_no_action,
    execute_soft_rate_limit,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_baseline_store: Optional[BaselineStore] = None

def get_baseline_store() -> BaselineStore:
    global _baseline_store
    if _baseline_store is None:
        _baseline_store = BaselineStore()
    return _baseline_store

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
        # Check AWS WAF format
        src_ip = data.get("aws", {}).get("httpRequest", {}).get("clientIp")
    if not src_ip:
        src_ip = "0.0.0.0"
        
    # Extract asset tag
    asset_tag = alert_dict.get("agent", {}).get("name", "unknown")
    
    # Extract rule info
    rule = alert_dict.get("rule", {})
    severity = rule.get("level", 1)
    raw_indicator = rule.get("description", "Unknown alert")
    
    rule_id = str(rule.get("id", ""))
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
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        source="wazuh",
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
    
    last_pos = 0
    
    while True:
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                f.seek(last_pos)
                lines = f.readlines()
                last_pos = f.tell()
                
                if lines:
                    process_lines(lines)
        
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


def process_lines(lines: list, store: Optional[BaselineStore] = None):
    if store is None:
        store = get_baseline_store()

    events_by_key = defaultdict(list)
    all_events = []
    ips_with_failures = set()
    
    for line in lines:
        if not line.strip():
            continue
        try:
            alert = json.loads(line)
            event = parse_wazuh_alert(alert)
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

    for key, events in events_by_key.items():
        logger.info(f"Running incident for key: {key} with {len(events)} events")
        try:
            incident_state = run_incident(events, baseline=store)
            if incident_state:
                execution_result = dispatch_execution(incident_state)
                logger.info(
                    f"Final Decision for incident {incident_state.incident_id}: {incident_state.final_decision} | Execution: {execution_result}"
                )
            else:
                logger.warning("run_incident returned None")
        except Exception as e:
            logger.error(f"Error running incident: {e}")

if __name__ == "__main__":
    ALERTS_FILE = os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
    POLL_INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "30"))
    poll_alerts(ALERTS_FILE, POLL_INTERVAL)
