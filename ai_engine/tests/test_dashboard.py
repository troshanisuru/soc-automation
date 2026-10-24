"""Tests for SOC Observability Dashboard (Health Checker, Audit Log Reader, API Server)."""

import json
from pathlib import Path
import socket
import threading
import time
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

import pytest

from ai_engine.dashboard.server import (
    AuditLogReader,
    HealthChecker,
    create_server,
    get_default_audit_log_path,
    get_default_executor_audit_path,
    get_default_targets_path,
)


# --------------------------------------------------------------------------- Fixtures
@pytest.fixture
def sample_targets_file(tmp_path: Path) -> Path:
    targets_yaml = tmp_path / "targets.yaml"
    targets_yaml.write_text(
        """targets:
  - name: test_tcp_target
    type: tcp_port
    host: 127.0.0.1
    port: 9999
  - name: test_http_target
    type: http
    host: 127.0.0.1
    port: 8888
    path: /api/test
"""
    )
    return targets_yaml


# --------------------------------------------------------------------------- Health Checker Tests
def test_tcp_target_reachable():
    """Test TCP target successfully connecting reports status 'up' with latency."""
    mock_sock = MagicMock()
    with patch("socket.create_connection", return_value=mock_sock):
        target = {"name": "test_tcp", "type": "tcp_port", "host": "127.0.0.1", "port": 1514}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "up"
        assert res["latency_ms"] is not None
        assert res["latency_ms"] >= 0
        assert res["error"] is None
        mock_sock.close.assert_called_once()


def test_tcp_target_connection_refused():
    """Test TCP target with ConnectionRefusedError reports down with 'Connection refused'."""
    with patch("socket.create_connection", side_effect=ConnectionRefusedError(61, "Connection refused")):
        target = {"name": "test_tcp", "type": "tcp_port", "host": "127.0.0.1", "port": 1514}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "down"
        assert res["latency_ms"] is None
        assert "Connection refused" in res["error"]


def test_tcp_target_timeout():
    """Test TCP target timing out reports down with 'Connection timed out'."""
    with patch("socket.create_connection", side_effect=TimeoutError("Connection timed out")):
        target = {"name": "test_tcp", "type": "tcp_port", "host": "127.0.0.1", "port": 1514}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "down"
        assert res["latency_ms"] is None
        assert "timed out" in res["error"].lower()


def test_tcp_target_dns_failure():
    """Test TCP target failing DNS resolution reports down with 'DNS failure'."""
    with patch("socket.create_connection", side_effect=socket.gaierror(8, "nodename nor servname provided")):
        target = {"name": "test_tcp", "type": "tcp_port", "host": "nonexistent.example.internal", "port": 1514}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "down"
        assert res["latency_ms"] is None
        assert "DNS failure" in res["error"]


def test_http_target_reachable():
    """Test HTTP target returning 200 reports up with latency."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        target = {"name": "test_http", "type": "http", "host": "127.0.0.1", "port": 11434, "path": "/api/tags"}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "up"
        assert res["latency_ms"] is not None
        assert res["latency_ms"] >= 0
        assert res["error"] is None


def test_http_target_http_error():
    """Test HTTP target returning 500 reports down with HTTP error code."""
    err = urllib.error.HTTPError(
        url="http://127.0.0.1:11434/api/tags",
        code=500,
        msg="Internal Server Error",
        hdrs={},  # type: ignore[arg-type]
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=err):
        target = {"name": "test_http", "type": "http", "host": "127.0.0.1", "port": 11434, "path": "/api/tags"}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "down"
        assert "HTTP 500" in res["error"]


def test_http_target_connection_refused():
    """Test HTTP target connection refused reports down with 'Connection refused'."""
    err = urllib.error.URLError(ConnectionRefusedError("Connection refused"))
    with patch("urllib.request.urlopen", side_effect=err):
        target = {"name": "test_http", "type": "http", "host": "127.0.0.1", "port": 11434}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "down"
        assert "Connection refused" in res["error"]


def test_http_target_dns_failure():
    """Test HTTP target DNS failure reports down with 'DNS failure'."""
    err = urllib.error.URLError(socket.gaierror("nodename nor servname provided"))
    with patch("urllib.request.urlopen", side_effect=err):
        target = {"name": "test_http", "type": "http", "host": "bad.host.test", "port": 80}
        res = HealthChecker.check_target(target, timeout=2.0)
        assert res["status"] == "down"
        assert "DNS failure" in res["error"]


def test_health_checker_check_all(sample_targets_file: Path):
    """Test HealthChecker running check_all updates cached results."""
    checker = HealthChecker(targets_path=sample_targets_file, probe_timeout=1.0)
    assert len(checker._targets) == 2

    with patch.object(
        HealthChecker,
        "check_target",
        side_effect=[
            {
                "name": "test_tcp_target",
                "type": "tcp_port",
                "host": "127.0.0.1",
                "port": 9999,
                "status": "up",
                "latency_ms": 5.2,
                "error": None,
                "last_checked": "2026-10-24T00:00:00Z",
            },
            {
                "name": "test_http_target",
                "type": "http",
                "host": "127.0.0.1",
                "port": 8888,
                "path": "/api/test",
                "status": "down",
                "latency_ms": None,
                "error": "Connection refused",
                "last_checked": "2026-10-24T00:00:00Z",
            },
        ],
    ):
        results = checker.check_all()
        assert len(results) == 2

        status_obj = checker.get_status()
        assert status_obj["status"] == "ok"
        targets = status_obj["targets"]
        assert len(targets) == 2
        assert targets[0]["name"] == "test_tcp_target"
        assert targets[1]["name"] == "test_http_target"


# --------------------------------------------------------------------------- Audit Log Reader Tests
def test_audit_reader_empty_state(tmp_path: Path):
    """A fresh environment with missing or empty audit files returns an empty list gracefully."""
    missing_agent = tmp_path / "nonexistent_agent.log"
    missing_exec = tmp_path / "nonexistent_exec.log"

    reader = AuditLogReader(audit_log_path=missing_agent, executor_audit_path=missing_exec)
    incidents = reader.load_incidents()
    assert incidents == []
    assert reader.get_incident("inc-12345") is None


def test_audit_reader_synthetic_pipeline_incident(tmp_path: Path):
    """Test grouping and stage breakdown for a complete autonomous pipeline incident."""
    agent_log = tmp_path / "agent_audit.log"
    exec_log = tmp_path / "executor_audit.log"

    inc_id = "inc-synthetic-001"
    now_ts = 1791283000.0

    # Write triage, mitre, decision LLM calls + pipeline_decision
    agent_lines = [
        {
            "ts": now_ts + 10,
            "incident_id": inc_id,
            "agent": "triage_agent",
            "model": "llama3.1:latest",
            "attempt": 1,
            "outcome": "ok",
            "latency_ms": 1250,
        },
        {
            "ts": now_ts + 20,
            "incident_id": inc_id,
            "agent": "mitre_agent",
            "model": "llama3.1:latest",
            "attempt": 1,
            "outcome": "ok",
            "latency_ms": 1100,
        },
        {
            "ts": now_ts + 30,
            "incident_id": inc_id,
            "agent": "decision_agent",
            "model": "llama3.1:latest",
            "attempt": 1,
            "outcome": "ok",
            "latency_ms": 950,
        },
        {
            "ts": now_ts + 35,
            "record": "pipeline_decision",
            "incident_id": inc_id,
            "correlation_key": ["198.51.100.22", "prod-db-server"],
            "event_count": 3,
            "halted_at": "gate",
            "risk_score": 0.82,
            "final_decision": "autonomous",
            "proposed_action": "soft_rate_limit",
            "validation_errors": [],
            "duration_ms": 3500,
        },
    ]

    exec_lines = [
        {
            "ts": now_ts + 36,
            "incident_id": inc_id,
            "action": "soft_rate_limit",
            "status": "simulated",
            "shadow_mode": True,
            "details": {"Addresses": ["198.51.100.22/32"]},
        }
    ]

    agent_log.write_text("\n".join(json.dumps(x) for x in agent_lines) + "\n")
    exec_log.write_text("\n".join(json.dumps(x) for x in exec_lines) + "\n")

    reader = AuditLogReader(audit_log_path=agent_log, executor_audit_path=exec_log)
    incidents = reader.load_incidents()
    assert len(incidents) == 1

    inc = incidents[0]
    assert inc["incident_id"] == inc_id
    assert inc["correlation_key"] == ["198.51.100.22", "prod-db-server"]
    assert inc["final_decision"] == "autonomous"
    assert inc["proposed_action"] == "soft_rate_limit"
    assert inc["risk_score"] == 0.82

    # Check stage breakdown
    stages = inc["stages"]
    assert stages["triage"]["status"] == "ok"
    assert stages["triage"]["duration_ms"] == 1250
    assert stages["mitre"]["status"] == "ok"
    assert stages["mitre"]["duration_ms"] == 1100
    assert stages["decision"]["status"] == "ok"
    assert stages["decision"]["duration_ms"] == 950
    assert stages["gate"]["status"] == "ok"
    assert stages["executor"]["status"] == "simulated"
    assert stages["executor"]["action"] == "soft_rate_limit"

    # Test single incident lookup
    single = reader.get_incident(inc_id)
    assert single is not None
    assert single["incident_id"] == inc_id


def test_audit_reader_halted_incident(tmp_path: Path):
    """Test incident halted early at MITRE with validation errors."""
    agent_log = tmp_path / "agent_audit.log"
    inc_id = "inc-halted-002"
    now_ts = 1791285000.0

    agent_lines = [
        {
            "ts": now_ts + 5,
            "incident_id": inc_id,
            "agent": "triage_agent",
            "model": "llama3.1:latest",
            "attempt": 1,
            "outcome": "ok",
            "latency_ms": 800,
        },
        {
            "ts": now_ts + 12,
            "incident_id": inc_id,
            "agent": "mitre_agent",
            "model": "llama3.1:latest",
            "attempt": 1,
            "outcome": "ok",
            "latency_ms": 750,
        },
        {
            "ts": now_ts + 13,
            "record": "pipeline_decision",
            "incident_id": inc_id,
            "correlation_key": ["203.0.113.88", "prod-web-server"],
            "event_count": 1,
            "halted_at": "mitre",
            "risk_score": None,
            "final_decision": "escalate",
            "proposed_action": None,
            "validation_errors": ["Unknown technique T9999", "mitre validation failed"],
            "duration_ms": 13000,
        },
    ]

    agent_log.write_text("\n".join(json.dumps(x) for x in agent_lines) + "\n")

    reader = AuditLogReader(audit_log_path=agent_log, executor_audit_path=tmp_path / "empty_exec.log")
    incidents = reader.load_incidents()
    assert len(incidents) == 1

    inc = incidents[0]
    assert inc["final_decision"] == "escalate"
    assert inc["halted_at"] == "mitre"
    assert "Unknown technique T9999" in inc["validation_errors"]

    stages = inc["stages"]
    assert stages["triage"]["status"] == "ok"
    assert stages["mitre"]["status"] == "error"
    assert stages["decision"]["status"] == "skipped"
    assert stages["gate"]["status"] == "escalated"
    assert stages["executor"]["status"] == "refused"


# --------------------------------------------------------------------------- Server Integration Tests
@pytest.fixture
def running_server(sample_targets_file: Path, tmp_path: Path):
    """Spins up a test HTTP server on an ephemeral port and stops it cleanly."""
    agent_log = tmp_path / "agent_audit.log"
    exec_log = tmp_path / "executor_audit.log"
    agent_log.write_text("")
    exec_log.write_text("")

    server = create_server(
        host="127.0.0.1",
        port=0,  # bind to available ephemeral port
        targets_path=sample_targets_file,
        audit_log_path=agent_log,
        executor_audit_path=exec_log,
        auto_start_checker=False,
    )
    port = server.server_port

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url, server, agent_log, exec_log

    server.checker.stop()
    server.shutdown()
    server.server_close()
    server_thread.join(timeout=2.0)


def test_server_html_dashboard(running_server):
    """GET / serves the dashboard HTML with both panel headers."""
    base_url, _, _, _ = running_server
    req = urllib.request.Request(f"{base_url}/")
    with urllib.request.urlopen(req, timeout=3.0) as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "Infrastructure Health" in content
        assert "Pipeline Incidents Observability" in content


def test_server_api_health(running_server):
    """GET /api/health returns configured targets."""
    base_url, server, _, _ = running_server
    req = urllib.request.Request(f"{base_url}/api/health")
    with urllib.request.urlopen(req, timeout=3.0) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "ok"
        assert len(data["targets"]) == 2
        names = [t["name"] for t in data["targets"]]
        assert "test_tcp_target" in names
        assert "test_http_target" in names


def test_server_api_incidents(running_server):
    """GET /api/incidents returns empty list initially and matches added synthetic records."""
    base_url, _, agent_log, _ = running_server

    # Initially empty
    with urllib.request.urlopen(f"{base_url}/api/incidents", timeout=3.0) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "ok"
        assert data["incidents"] == []

    # Append an incident
    inc_rec = {
        "ts": 1791284000.0,
        "record": "pipeline_decision",
        "incident_id": "inc-live-999",
        "correlation_key": ["1.2.3.4", "asset-1"],
        "event_count": 2,
        "halted_at": "gate",
        "risk_score": 0.75,
        "final_decision": "soft_contain",
        "proposed_action": "soft_rate_limit",
        "validation_errors": [],
        "duration_ms": 2500,
    }
    agent_log.write_text(json.dumps(inc_rec) + "\n")

    # Fetch all
    with urllib.request.urlopen(f"{base_url}/api/incidents", timeout=3.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert len(data["incidents"]) == 1
        assert data["incidents"][0]["incident_id"] == "inc-live-999"

    # Fetch single incident
    with urllib.request.urlopen(f"{base_url}/api/incidents/inc-live-999", timeout=3.0) as resp:
        assert resp.status == 200
        single_data = json.loads(resp.read().decode("utf-8"))
        assert single_data["status"] == "ok"
        assert single_data["incident"]["incident_id"] == "inc-live-999"

    # Fetch nonexistent incident -> 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{base_url}/api/incidents/inc-does-not-exist", timeout=3.0)
    assert exc_info.value.code == 404


def test_env_var_defaults(monkeypatch, tmp_path: Path):
    """Test custom configuration via environment variables."""
    custom_targets = tmp_path / "custom_targets.yaml"
    custom_targets.write_text("targets: []")
    custom_agent_log = tmp_path / "custom_agent.log"
    custom_exec_log = tmp_path / "custom_exec.log"

    monkeypatch.setenv("DASHBOARD_TARGETS_PATH", str(custom_targets))
    monkeypatch.setenv("AI_ENGINE_AUDIT_LOG", str(custom_agent_log))
    monkeypatch.setenv("AI_ENGINE_EXECUTOR_AUDIT_LOG", str(custom_exec_log))

    assert get_default_targets_path() == custom_targets
    assert get_default_audit_log_path() == custom_agent_log
    assert get_default_executor_audit_path() == custom_exec_log
