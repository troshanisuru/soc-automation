import concurrent.futures
from datetime import datetime, timedelta, timezone

import pytest

from ai_engine.correlation.correlate import EventCorrelator
from ai_engine.schemas.models import NormalizedEvent
from ai_engine.tests.helpers import T0, make_event


def make(**kwargs):
    """Correlator with an injectable clock (returns (correlator, clock-dict))."""
    clock = {"now": T0}
    return EventCorrelator(clock=lambda: clock["now"], **kwargs), clock


def test_groups_events_with_same_key():
    c, _ = make(window_seconds=60)
    inc1 = c.process_event(make_event("e1", 0))
    inc2 = c.process_event(make_event("e2", 30))
    assert inc2.incident_id == inc1.incident_id
    assert [e.event_id for e in inc2.events] == ["e1", "e2"]
    assert inc1.correlation_key == ("198.51.100.44", "web-server-01")
    assert inc1.status == "open"


def test_different_keys_make_different_incidents():
    c, _ = make()
    a = c.process_event(make_event("e1", ip="198.51.100.44"))
    b = c.process_event(make_event("e2", ip="203.0.113.50"))
    d = c.process_event(make_event("e3", ip="198.51.100.44", asset="db-01"))
    assert len({a.incident_id, b.incident_id, d.incident_id}) == 3


def test_duplicate_event_is_ignored():
    c, _ = make()
    event = make_event("dup", 0)
    assert c.process_event(event) is not None
    assert c.process_event(event) is None
    assert len(c.open_incidents()[event.source_ip, event.asset_tag].events) == 1


def test_window_expiry_closes_and_EMITS_the_old_incident():
    """Regression: the old incident used to be marked closed and then silently dropped."""
    c, _ = make(window_seconds=60)
    first = c.process_event(make_event("e1", 0))
    second = c.process_event(make_event("e2", 75))  # outside the 60s window
    assert second.incident_id != first.incident_id and second.status == "open"

    emitted = c.finalize_expired_incidents()
    assert [i.incident_id for i in emitted] == [first.incident_id]
    assert emitted[0].status == "closed" and [e.event_id for e in emitted[0].events] == ["e1"]


def test_window_is_rolling_not_fixed():
    c, _ = make(window_seconds=60)
    ids = {c.process_event(make_event(f"e{i}", i * 50)).incident_id for i in range(3)}  # 0, 50, 100
    assert len(ids) == 1


def test_out_of_order_arrival_joins_and_timeline_stays_sorted():
    c, _ = make(window_seconds=60)
    c.process_event(make_event("late", 50))
    c.process_event(make_event("early", 10))
    inc = c.process_event(make_event("mid", 30))
    assert [e.event_id for e in inc.events] == ["early", "mid", "late"]


def test_finalize_emits_each_incident_exactly_once():
    c, _ = make(window_seconds=60)
    inc = c.process_event(make_event("e1", 0))
    out = c.finalize_expired_incidents(current_time=T0 + timedelta(seconds=90))
    assert [i.incident_id for i in out] == [inc.incident_id] and out[0].status == "closed"
    assert c.finalize_expired_incidents(current_time=T0 + timedelta(seconds=200)) == []
    assert c.stats()["open"] == 0


def test_open_incident_not_finalized_inside_window():
    c, _ = make(window_seconds=60)
    c.process_event(make_event("e1", 0))
    assert c.finalize_expired_incidents(current_time=T0 + timedelta(seconds=30)) == []


def test_hard_span_cap_stops_drip_feed_starvation():
    c, _ = make(window_seconds=60, max_incident_seconds=100)
    for i, off in enumerate([0, 50, 100, 150]):  # each within 60s of the last, but span > 100
        c.process_event(make_event(f"e{i}", off))
    out = c.finalize_expired_incidents(current_time=T0 + timedelta(seconds=1000))
    assert sorted(len(i.events) for i in out) == [1, 3]


def test_max_events_per_incident_cap():
    c, _ = make(max_events_per_incident=3)
    for i in range(5):
        c.process_event(make_event(f"e{i}", i))
    out = c.finalize_expired_incidents(current_time=T0 + timedelta(seconds=1000))
    assert sorted(len(i.events) for i in out) == [2, 3]


def test_future_dated_timestamps_cannot_keep_an_incident_open():
    c, clock = make(window_seconds=60, max_incident_seconds=300)
    far_future = 10 * 86400
    for i in range(12):  # arrives every 30s for 330s, always "inside the window" by event time
        clock["now"] = T0 + timedelta(seconds=30 * i)
        c.process_event(make_event(f"f{i}", far_future + i), now=clock["now"])
    emitted = c.finalize_expired_incidents()
    assert len(emitted) == 1 and len(emitted[0].events) == 11  # forced closed by the arrival-age cap


def test_dedupe_entries_expire_after_ttl():
    c, clock = make(dedupe_ttl_seconds=10)
    assert c.process_event(make_event("e1", 0)) is not None
    clock["now"] = T0 + timedelta(seconds=5)
    assert c.process_event(make_event("e1", 0)) is None          # inside TTL
    clock["now"] = T0 + timedelta(seconds=11)
    assert c.process_event(make_event("e1", 0)) is not None      # TTL elapsed


def test_dedupe_table_is_bounded():
    c, _ = make(dedupe_max_entries=100)
    for i in range(500):
        c.process_event(make_event(f"e{i}", 0, ip=f"10.0.{i // 250}.{i % 250 + 1}"))
    assert c.stats()["dedupe_entries"] <= 100


def test_open_incident_cap_force_closes_oldest_without_losing_any():
    c, _ = make(max_open_incidents=5)
    for i in range(8):
        c.process_event(make_event(f"e{i}", 0, ip=f"10.1.0.{i + 1}"))
    stats = c.stats()
    assert stats["open"] <= 5
    assert stats["open"] + len(c.drain_finalized()) == 8


def test_processing_lock_prevents_parallel_runs_for_one_key():
    c, _ = make(window_seconds=60)
    c.process_event(make_event("e1", 0))
    c.process_event(make_event("e2", 100))  # new incident for the same key
    a, b = c.finalize_expired_incidents(current_time=T0 + timedelta(seconds=1000))
    assert a.correlation_key == b.correlation_key

    assert c.begin_processing(a) is True
    assert c.begin_processing(a) is False        # idempotent: already held
    assert c.begin_processing(b) is False        # second run for the same key must wait
    assert c.end_processing(b) is False          # non-owner cannot release
    assert c.end_processing(a) is True
    assert c.begin_processing(b) is True


def test_processing_lock_context_manager_releases_on_error():
    c, _ = make()
    inc = c.process_event(make_event("e1", 0))
    with pytest.raises(RuntimeError):
        with c.processing_lock(inc) as acquired:
            assert acquired
            raise RuntimeError("pipeline crashed")
    assert c.stats()["processing"] == 0


def test_stale_processing_lock_is_reclaimed():
    c, clock = make(processing_ttl_seconds=10)
    a = c.process_event(make_event("e1", 0))
    assert c.begin_processing(a, now=T0)
    clock["now"] = T0 + timedelta(seconds=11)
    assert c.begin_processing(a, now=clock["now"]) is True  # holder presumed dead


def test_concurrent_events_and_duplicates_are_race_free():
    c, _ = make(window_seconds=60)
    events = [make_event(f"e{i}", i) for i in range(20)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(c.process_event, events + events))  # every event submitted twice
    (incident,) = c.open_incidents().values()
    assert len(incident.events) == 20
    assert [e.event_id for e in incident.events] == [f"e{i}" for i in range(20)]


def test_naive_and_aware_timestamps_do_not_crash():
    """Regression: mixing naive/aware datetimes raised TypeError inside the lock."""
    c, _ = make()
    naive = NormalizedEvent(
        event_id="n1", source="waf", timestamp=datetime(2026, 10, 6, 12, 0, 5),
        source_ip="198.51.100.44", asset_tag="web-server-01", severity=3, raw_indicator="x",
    )
    inc = c.process_event(make_event("a1", 0))
    assert c.process_event(naive).incident_id == inc.incident_id


def test_incident_ids_are_unique_and_128_bit():
    c, _ = make()
    ids = {c.process_event(make_event(f"e{i}", ip=f"10.2.0.{i + 1}")).incident_id for i in range(50)}
    assert len(ids) == 50 and all(len(i) == len("inc-") + 32 for i in ids)


def test_invalid_limits_are_rejected():
    for bad in (0, -1):
        with pytest.raises(ValueError):
            EventCorrelator(window_seconds=bad)
