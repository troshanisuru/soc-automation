import statistics
from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from pydantic import BaseModel, ConfigDict
from ai_engine.schemas.models import NormalizedEvent


class AuthFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    failure_count: int
    distinct_usernames: int
    invalid_user_ratio: Optional[float] = None
    known_pair: bool
    median_gap_seconds: Optional[float] = None
    success_after_failure: bool
    source_count: int


def compute_auth_features(
    events: Sequence[NormalizedEvent], baseline: Any, now: Optional[datetime] = None
) -> AuthFeatures:
    """Compute authentication context features for an incident's events.

    Pure function: no LLM, no I/O beyond calling baseline.is_known_pair.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    failures = [e for e in events if e.auth_outcome == "failure"]
    failure_count = len(failures)

    distinct_usernames = len({e.username.strip().lower() for e in failures if e.username})

    validity_failures = [e for e in failures if e.user_valid is not None]
    if validity_failures:
        invalid_count = sum(1 for e in validity_failures if e.user_valid is False)
        invalid_user_ratio = float(invalid_count) / len(validity_failures)
    else:
        invalid_user_ratio = None

    failures_with_user = [e for e in failures if e.username]
    known_pair = bool(failures_with_user) and all(
        baseline.is_known_pair(e.username, e.source_ip, now) for e in failures_with_user
    )

    if len(failures) < 3:
        median_gap_seconds = None
    else:
        sorted_ts = sorted(e.timestamp for e in failures)
        gaps = [(sorted_ts[i] - sorted_ts[i - 1]).total_seconds() for i in range(1, len(sorted_ts))]
        median_gap_seconds = float(statistics.median(gaps))

    earliest_failure_by_ip = {}
    for e in failures:
        if e.source_ip not in earliest_failure_by_ip or e.timestamp < earliest_failure_by_ip[e.source_ip]:
            earliest_failure_by_ip[e.source_ip] = e.timestamp

    success_after_failure = any(
        e.auth_outcome == "success"
        and e.source_ip in earliest_failure_by_ip
        and e.timestamp > earliest_failure_by_ip[e.source_ip]
        for e in events
    )

    source_count = len({e.source for e in events})

    return AuthFeatures(
        failure_count=failure_count,
        distinct_usernames=distinct_usernames,
        invalid_user_ratio=invalid_user_ratio,
        known_pair=known_pair,
        median_gap_seconds=median_gap_seconds,
        success_after_failure=success_after_failure,
        source_count=source_count,
    )
