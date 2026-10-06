"""Pydantic data contracts - the single source of truth for everything agents read/write.

Hardening (why this file is stricter than the plan's sketch):
* Every string that is later interpolated into an LLM prompt (event_id, asset_tag,
  source_ip, raw_indicator) is length-capped and restricted/sanitised, so a log line
  cannot break prompt structure or flood the context window.
* Timestamps are normalised to timezone-aware UTC (mixing naive and aware datetimes
  used to raise TypeError inside the correlator).
* Evidence (NormalizedEvent) is immutable; agent outputs reject unknown keys and bound
  every list/string (fail closed instead of silently dropping or accepting extras).
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

MAX_RAW_INDICATOR_CHARS = 512

# NB: pydantic-core uses the Rust regex engine where `$` matches only at the true end of
# the string (Python's `re` would also accept a trailing newline).
EVENT_ID_PATTERN = r"^[A-Za-z0-9._:\-]{1,128}$"
ASSET_TAG_PATTERN = r"^[A-Za-z0-9._\-]{1,64}$"
TECHNIQUE_ID_PATTERN = r"^T\d{4}$"
INCIDENT_ID_PATTERN = r"^[A-Za-z0-9\-]{1,64}$"

EventId = Annotated[str, StringConstraints(pattern=EVENT_ID_PATTERN)]
AssetTag = Annotated[str, StringConstraints(pattern=ASSET_TAG_PATTERN)]
TechniqueId = Annotated[str, StringConstraints(pattern=TECHNIQUE_ID_PATTERN)]
IncidentId = Annotated[str, StringConstraints(pattern=INCIDENT_ID_PATTERN)]
ShortText = Annotated[str, StringConstraints(max_length=300)]
LongText = Annotated[str, StringConstraints(max_length=600)]

# C0/C1 control chars, zero-width and bidi-override characters (log forging / "trojan source").
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")


def sanitize_text(value: str, max_chars: int) -> str:
    """Replace control/bidi characters, collapse whitespace, truncate."""
    cleaned = " ".join(_UNSAFE_CHARS.sub(" ", value).split())
    return cleaned[:max_chars]


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId                  # stable, referenced by agents as evidence
    source: Literal["wazuh", "waf", "flowlog"]
    timestamp: datetime
    source_ip: str
    asset_tag: AssetTag
    severity: int = Field(ge=0, le=10)  # 0-10, mapped from native severity
    raw_indicator: str                 # short, sanitised description

    @field_validator("timestamp")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def _canonical_ip(cls, value: str) -> str:
        if "%" in value:  # IPv6 zone ids have no place in a correlation key
            raise ValueError("IP must not contain a zone id")
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("raw_indicator", mode="before")
    @classmethod
    def _clean_indicator(cls, value: object) -> object:
        if isinstance(value, str):
            return sanitize_text(value, MAX_RAW_INDICATOR_CHARS)
        return value  # non-str: let normal type validation reject it


class TriageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeline: list[ShortText] = Field(max_length=25)               # ordered, human-readable steps
    entities: dict[str, list[ShortText]] = Field(max_length=10)    # {"ips": [...], "assets": [...]}
    cited_event_ids: list[EventId] = Field(max_length=200)         # must all exist in input events


class MitreOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    techniques: list[TechniqueId] = Field(max_length=10)           # e.g. ["T1190", "T1071"]
    justification: dict[str, ShortText] = Field(max_length=10)     # technique_id -> one-line reason
    cited_event_ids: list[EventId] = Field(max_length=200)


class DecisionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposed_action: Literal["block_ip_waf", "isolate_sg", "soft_rate_limit", "no_action"]
    justification: LongText
    cited_event_ids: list[EventId] = Field(max_length=200)


class IncidentState(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    incident_id: IncidentId
    correlation_key: tuple[str, str]   # (source_ip, asset_tag)
    events: list[NormalizedEvent]
    status: Literal["open", "closed"]
    triage: Optional[TriageOutput] = None
    mitre: Optional[MitreOutput] = None
    decision: Optional[DecisionOutput] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)   # GATE writes this, never an agent
    final_decision: Optional[Literal["autonomous", "soft_contain", "escalate"]] = None
    validation_errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _events_match_key(self) -> "IncidentState":
        """Integrity invariant: an incident only ever holds events for its own key."""
        ip, asset = self.correlation_key
        for event in self.events:
            if (event.source_ip, event.asset_tag) != (ip, asset):
                raise ValueError(
                    f"event {event.event_id!r} does not belong to correlation_key {self.correlation_key!r}"
                )
        return self
