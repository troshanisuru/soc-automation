import os
import json
import time
import uuid
import logging
from datetime import datetime
from collections import defaultdict
from ai_engine.schemas.models import NormalizedEvent
from ai_engine.main import run_incident

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_wazuh_alert(alert_dict: dict) -> NormalizedEvent:
    """Convert a Wazuh alert JSON dict into a NormalizedEvent."""
    # Extract timestamp
    raw_ts = alert_dict.get("timestamp", datetime.utcnow().isoformat() + "Z")
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
    
    return NormalizedEvent(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        source="wazuh",
        timestamp=datetime.fromisoformat(raw_ts),
        source_ip=src_ip,
        asset_tag=asset_tag,
        severity=severity,
        raw_indicator=raw_indicator
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

def process_lines(lines: list):
    events_by_key = defaultdict(list)
    
    for line in lines:
        if not line.strip():
            continue
        try:
            alert = json.loads(line)
            event = parse_wazuh_alert(alert)
            key = (event.source_ip, event.asset_tag)
            events_by_key[key].append(event)
        except json.JSONDecodeError:
            logger.error("Failed to parse alert line as JSON")
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            
    for key, events in events_by_key.items():
        logger.info(f"Running incident for key: {key} with {len(events)} events")
        try:
            incident_state = run_incident(events)
            if incident_state:
                logger.info(f"Final Decision for incident {incident_state.incident_id}: {incident_state.final_decision}")
            else:
                logger.warning("run_incident returned None")
        except Exception as e:
            logger.error(f"Error running incident: {e}")

if __name__ == "__main__":
    ALERTS_FILE = os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
    POLL_INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", "30"))
    poll_alerts(ALERTS_FILE, POLL_INTERVAL)
