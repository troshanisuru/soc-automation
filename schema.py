from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal, Optional

class NormalizedEvent(BaseModel):
    source: Literal["wazuh", "waf", "flowlog", "aws_waf", "aws_vpcflow"]
    timestamp: datetime
    source_ip: str
    target_asset: str
    severity: int
    raw_indicator: str
    event_type: str
    action: Optional[str] = None
    rule_id: Optional[str] = None

class IncidentState(BaseModel):
    incident_id: str
    correlation_key: str
    events: list[NormalizedEvent] = []
    risk_score: float = 0.0
    status: Literal["open", "contained", "escalated"] = "open"
