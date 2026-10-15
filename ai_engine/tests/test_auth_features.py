from datetime import datetime, timedelta, timezone
from ai_engine.baseline.store import BaselineStore
from ai_engine.gate.auth_features import compute_auth_features
from ai_engine.tests.helpers import make_event


def test_stale_credential_case():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)
    ip = "192.168.1.100"
    user = "dev_user"

    # Known pair: succeeded 3 days ago
    store.record_success(user, ip, now - timedelta(days=3))

    # 20 failures, 60s gaps
    events = [
        make_event(
            f"evt-{i}",
            offset=i * 60,
            ip=ip,
            username=user,
            auth_outcome="failure",
            user_valid=True,
        )
        for i in range(20)
    ]

    features = compute_auth_features(events, store, now)
    assert features.failure_count == 20
    assert features.distinct_usernames == 1
    assert features.invalid_user_ratio == 0.0
    assert features.known_pair is True
    assert features.median_gap_seconds == 60.0
    assert features.success_after_failure is False
    assert features.source_count == 1
    store.close()


def test_spray_case():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)
    ip = "192.168.1.100"

    # 8 usernames, mostly user_valid=False (7 False, 1 True), 1s gaps
    events = [
        make_event(
            f"evt-{i}",
            offset=i * 1.0,
            ip=ip,
            username=f"target_user_{i}",
            auth_outcome="failure",
            user_valid=(False if i < 7 else True),
        )
        for i in range(8)
    ]

    features = compute_auth_features(events, store, now)
    assert features.failure_count == 8
    assert features.distinct_usernames == 8
    assert features.invalid_user_ratio == 7 / 8
    assert features.known_pair is False
    assert features.median_gap_seconds == 1.0
    assert features.success_after_failure is False
    store.close()


def test_success_after_failure_case():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)
    ip = "192.168.1.100"

    fail_evt = make_event("evt-f", offset=0, ip=ip, auth_outcome="failure")
    succ_evt = make_event("evt-s", offset=15, ip=ip, auth_outcome="success")

    # Success occurs after failure from same IP -> True
    features = compute_auth_features([fail_evt, succ_evt], store, now)
    assert features.success_after_failure is True

    # Success before failure -> False
    features_reversed = compute_auth_features([succ_evt, make_event("evt-f2", offset=30, ip=ip, auth_outcome="failure")], store, now)
    assert features_reversed.success_after_failure is False
    store.close()


def test_fewer_than_3_failures_median_gap():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)
    ip = "192.168.1.100"

    # 0 failures
    assert compute_auth_features([], store, now).median_gap_seconds is None

    # 1 failure
    e1 = make_event("e1", offset=0, ip=ip, auth_outcome="failure")
    assert compute_auth_features([e1], store, now).median_gap_seconds is None

    # 2 failures
    e2 = make_event("e2", offset=10, ip=ip, auth_outcome="failure")
    assert compute_auth_features([e1, e2], store, now).median_gap_seconds is None

    # 3 failures: gaps are 10s and 30s -> median is (10 + 30)/2 = 20.0
    e3 = make_event("e3", offset=40, ip=ip, auth_outcome="failure")
    features = compute_auth_features([e1, e2, e3], store, now)
    assert features.median_gap_seconds == 20.0
    store.close()


def test_source_count_and_null_username():
    store = BaselineStore(db_path=":memory:", min_age_seconds=86400)
    now = datetime.now(timezone.utc)

    e1 = make_event("e1", source="wazuh", auth_outcome="failure", username=None)
    e2 = make_event("e2", source="flowlog", auth_outcome="failure", username="Alice")

    features = compute_auth_features([e1, e2], store, now)
    assert features.source_count == 2
    assert features.distinct_usernames == 1
    assert features.known_pair is False
    store.close()
