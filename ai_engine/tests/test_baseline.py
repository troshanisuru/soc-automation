from datetime import datetime, timedelta, timezone
from ai_engine.baseline.store import BaselineStore
from ai_engine.ingest.wazuh_poller import process_lines


def test_first_seen_age_requirement():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)

    # 1 hour old -> not known (less than 86400 seconds)
    store.record_success("alice", "10.0.0.1", now - timedelta(hours=1))
    assert store.is_known_pair("alice", "10.0.0.1", now) is False

    # 2 days old -> known
    store.record_success("bob", "10.0.0.2", now - timedelta(days=2))
    assert store.is_known_pair("bob", "10.0.0.2", now) is True
    store.close()


def test_sql_injection_username():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=2)

    sqli_user = "admin' OR '1'='1"
    store.record_success(sqli_user, "192.168.1.50", ts)

    assert store.is_known_pair(sqli_user, "192.168.1.50", now) is True
    assert store.is_known_pair("admin", "192.168.1.50", now) is False
    assert store.is_known_pair("admin' OR '2'='2", "192.168.1.50", now) is False
    store.close()


def test_upsert_and_case_insensitivity():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)
    t1 = now - timedelta(days=5)
    t2 = now - timedelta(days=3)

    store.record_success("Alice_User", "10.1.1.1", t1)
    store.record_success("alice_user", "10.1.1.1", t2)

    assert store.is_known_pair("ALICE_USER", "10.1.1.1", now) is True

    cursor = store._conn.execute(
        "SELECT first_seen, last_seen, success_count FROM known_pairs WHERE username = ? AND source_ip = ?",
        ("alice_user", "10.1.1.1"),
    )
    row = cursor.fetchone()
    assert row is not None
    first_seen, last_seen, count = row
    assert count == 2
    assert first_seen == t1.isoformat()
    assert last_seen == t2.isoformat()
    store.close()


def test_poller_records_success_only_for_clean_ips(monkeypatch):
    store = BaselineStore(db_path=":memory:", min_age_seconds=0)

    # Prevent run_incident from calling graph during test
    monkeypatch.setattr("ai_engine.ingest.wazuh_poller.run_incident", lambda events: None)

    # IP 10.0.0.1 has both a failure and a success in this batch
    line_fail_1 = (
        '{"timestamp": "2026-09-26T03:15:22.123Z", "rule": {"id": "5710"}, '
        '"agent": {"name": "web-01"}, "data": {"srcip": "10.0.0.1", "dstuser": "attacker"}}'
    )
    line_succ_1 = (
        '{"timestamp": "2026-09-26T03:16:22.123Z", "rule": {"id": "5715"}, '
        '"agent": {"name": "web-01"}, "data": {"srcip": "10.0.0.1", "dstuser": "attacker"}}'
    )
    # IP 10.0.0.2 has only a success in this batch
    line_succ_2 = (
        '{"timestamp": "2026-09-26T03:17:22.123Z", "rule": {"id": "5715"}, '
        '"agent": {"name": "web-01"}, "data": {"srcip": "10.0.0.2", "dstuser": "legit"}}'
    )

    process_lines([line_fail_1, line_succ_1, line_succ_2], store=store)

    now = datetime.now(timezone.utc)
    # 10.0.0.1 had a failure in batch -> NOT learned
    assert store.is_known_pair("attacker", "10.0.0.1", now) is False
    # 10.0.0.2 had no failures in batch -> LEARNED
    assert store.is_known_pair("legit", "10.0.0.2", now) is True
    store.close()
