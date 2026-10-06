"""Deterministic event correlation - pure Python, NO LLM calls.

Responsibilities (plan section 3):
* Group NormalizedEvents by (source_ip, asset_tag).
* Rolling correlation window; new event for an open key appends to that incident.
* Emit every finalized IncidentState exactly once (events only, no agent fields).
* Per-key processing lock so two pipeline runs can never act on one key in parallel.

Safety properties (this module sits on the untrusted-input edge):
* Every piece of state is bounded - dedupe table (TTL + size cap), open incidents,
  events per incident, incident span - so a flood of spoofed IPs / replayed ids /
  drip-fed events cannot grow memory or starve processing.
* Expiry uses *arrival* time, so future-dated event timestamps cannot keep an incident
  open forever; joining uses event time and tolerates out-of-order arrival.
* process_event is atomic: if anything fails nothing is recorded (no half-applied state).
"""

import bisect
import logging
import threading
import uuid
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Deque, Dict, Iterator, List, Optional, Tuple

from ai_engine.config.loader import get_thresholds
from ai_engine.schemas.models import IncidentState, NormalizedEvent

logger = logging.getLogger("ai_engine.correlation")

CorrelationKey = Tuple[str, str]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _Meta:
    first_arrival: datetime
    last_arrival: datetime


def _pick(name: str, value: Optional[int], default: int) -> int:
    chosen = default if value is None else value
    if not isinstance(chosen, int) or isinstance(chosen, bool) or chosen < 1:
        raise ValueError(f"{name} must be a positive integer (got {chosen!r})")
    return chosen


class EventCorrelator:
    """Thread-safe correlator. A single coarse lock guards all state: the work done under
    it is O(log n) pure-Python, so finer-grained locks add risk without measurable gain."""

    def __init__(
        self,
        window_seconds: Optional[int] = None,
        max_incident_seconds: Optional[int] = None,
        max_events_per_incident: Optional[int] = None,
        max_open_incidents: Optional[int] = None,
        dedupe_ttl_seconds: Optional[int] = None,
        dedupe_max_entries: Optional[int] = None,
        processing_ttl_seconds: Optional[int] = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        cfg = get_thresholds()
        self._window = timedelta(seconds=_pick("window_seconds", window_seconds, cfg.window_seconds))
        self._max_incident = timedelta(
            seconds=_pick("max_incident_seconds", max_incident_seconds, cfg.max_incident_seconds)
        )
        self._max_events = _pick("max_events_per_incident", max_events_per_incident, cfg.max_events_per_incident)
        self._max_open = _pick("max_open_incidents", max_open_incidents, cfg.max_open_incidents)
        self._dedupe_ttl = timedelta(seconds=_pick("dedupe_ttl_seconds", dedupe_ttl_seconds, cfg.dedupe_ttl_seconds))
        self._dedupe_max = _pick("dedupe_max_entries", dedupe_max_entries, cfg.dedupe_max_entries)
        self._processing_ttl = timedelta(
            seconds=_pick("processing_ttl_seconds", processing_ttl_seconds, cfg.processing_ttl_seconds)
        )
        self._clock = clock

        self._lock = threading.RLock()
        self._open: Dict[CorrelationKey, IncidentState] = {}      # insertion order == creation order
        self._meta: Dict[str, _Meta] = {}                          # incident_id -> arrival bookkeeping
        self._finalized: Deque[IncidentState] = deque()            # closed, waiting to be drained
        self._processing: Dict[CorrelationKey, Tuple[str, datetime]] = {}
        self._seen: "OrderedDict[str, datetime]" = OrderedDict()   # event_id -> arrival (dedupe)

    # ------------------------------------------------------------------ ingestion
    def process_event(self, event: NormalizedEvent, now: Optional[datetime] = None) -> Optional[IncidentState]:
        """Add one event. Returns the open incident it joined/created, or None for a duplicate.

        Any incident closed as a side effect is queued for ``finalize_expired_incidents``
        (it is never dropped)."""
        now = now or self._clock()
        key: CorrelationKey = (event.source_ip, event.asset_tag)
        with self._lock:
            if self._is_duplicate(event.event_id, now):
                return None

            incident = self._open.get(key)
            if incident is not None and not self._can_join(incident, event, now):
                self._close(key)
                incident = None

            if incident is None:
                if len(self._open) >= self._max_open:
                    oldest = next(iter(self._open))
                    logger.warning("open-incident cap reached; force-closing oldest key")
                    self._close(oldest)
                incident = IncidentState(
                    incident_id=f"inc-{uuid.uuid4().hex}",  # 128-bit: no realistic collisions
                    correlation_key=key,
                    events=[event],
                    status="open",
                )
                self._open[key] = incident
                self._meta[incident.incident_id] = _Meta(first_arrival=now, last_arrival=now)
            else:
                bisect.insort(incident.events, event, key=lambda e: e.timestamp)  # keep timeline ordered
                self._meta[incident.incident_id].last_arrival = now

            self._remember(event.event_id, now)  # only after everything above succeeded
            return incident

    def finalize_expired_incidents(self, current_time: Optional[datetime] = None) -> List[IncidentState]:
        """Close incidents whose window elapsed, then return (and clear) every closed incident
        not yet handed over - including ones closed implicitly by ``process_event``."""
        now = current_time or self._clock()
        with self._lock:
            for key, incident in list(self._open.items()):
                meta = self._meta[incident.incident_id]
                idle = now - meta.last_arrival > self._window
                too_old = now - meta.first_arrival > self._max_incident
                if idle or too_old:
                    self._close(key)
            return self.drain_finalized()

    def drain_finalized(self) -> List[IncidentState]:
        with self._lock:
            out = list(self._finalized)
            self._finalized.clear()
            return out

    # ------------------------------------------------------------------ processing lock
    def begin_processing(self, incident: IncidentState, now: Optional[datetime] = None) -> bool:
        """Claim the per-key processing lock. False means another run owns this key (the
        caller should retry later; the incident stays queued - nothing is lost)."""
        now = now or self._clock()
        key = incident.correlation_key
        with self._lock:
            holder = self._processing.get(key)
            if holder is not None:
                if now - holder[1] <= self._processing_ttl:
                    return False
                logger.warning("reclaiming stale processing lock (previous holder hung or crashed)")
            self._processing[key] = (incident.incident_id, now)
            return True

    def end_processing(self, incident: IncidentState) -> bool:
        """Release the lock - only the incident that owns it can release it."""
        with self._lock:
            holder = self._processing.get(incident.correlation_key)
            if holder is not None and holder[0] == incident.incident_id:
                del self._processing[incident.correlation_key]
                return True
            return False

    @contextmanager
    def processing_lock(self, incident: IncidentState) -> Iterator[bool]:
        """``with correlator.processing_lock(inc) as acquired:`` - always releases, even on error."""
        acquired = self.begin_processing(incident)
        try:
            yield acquired
        finally:
            if acquired:
                self.end_processing(incident)

    # ------------------------------------------------------------------ introspection
    def open_incidents(self) -> Dict[CorrelationKey, IncidentState]:
        with self._lock:
            return dict(self._open)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "open": len(self._open),
                "pending_finalized": len(self._finalized),
                "processing": len(self._processing),
                "dedupe_entries": len(self._seen),
            }

    # ------------------------------------------------------------------ internals (lock held)
    def _can_join(self, incident: IncidentState, event: NormalizedEvent, now: datetime) -> bool:
        events = incident.events  # kept sorted by timestamp
        if len(events) >= self._max_events:
            return False
        first_ts, last_ts = events[0].timestamp, events[-1].timestamp
        if event.timestamp > last_ts + self._window or event.timestamp < first_ts - self._window:
            return False  # outside the rolling window (tolerates out-of-order arrival inside it)
        if max(last_ts, event.timestamp) - min(first_ts, event.timestamp) > self._max_incident:
            return False  # hard span cap: a drip-feed must not keep one incident open forever
        if now - self._meta[incident.incident_id].first_arrival > self._max_incident:
            return False  # same cap on arrival time (defeats future-dated timestamps)
        return True

    def _close(self, key: CorrelationKey) -> None:
        incident = self._open.pop(key)
        incident.status = "closed"
        self._meta.pop(incident.incident_id, None)
        self._finalized.append(incident)

    def _is_duplicate(self, event_id: str, now: datetime) -> bool:
        cutoff = now - self._dedupe_ttl
        while self._seen:
            oldest_id, seen_at = next(iter(self._seen.items()))
            if seen_at >= cutoff:
                break
            del self._seen[oldest_id]
        return event_id in self._seen

    def _remember(self, event_id: str, now: datetime) -> None:
        self._seen[event_id] = now
        while len(self._seen) > self._dedupe_max:
            self._seen.popitem(last=False)
