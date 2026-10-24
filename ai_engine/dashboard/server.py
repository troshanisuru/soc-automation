"""SOC Automation Observability Dashboard Server.

Provides:
1. Background infrastructure health checker polling named targets (TCP port, HTTP).
2. Pipeline observability panel tailing AI Engine and Executor audit logs.
3. HTTP server serving local read-only dashboard UI and REST API.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import yaml

logger = logging.getLogger("ai_engine.dashboard")


# --------------------------------------------------------------------------- Config Defaults
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_POLL_INTERVAL = 10.0
DEFAULT_PROBE_TIMEOUT = 2.5


def _get_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def get_default_targets_path() -> Path:
    override = os.environ.get("DASHBOARD_TARGETS_PATH") or os.environ.get("DASHBOARD_TARGETS_FILE")
    if override:
        return Path(override)
    targets_yaml = Path(__file__).resolve().parent / "targets.yaml"
    if targets_yaml.exists():
        return targets_yaml
    example_yaml = Path(__file__).resolve().parent / "targets.yaml.example"
    return example_yaml


def get_default_audit_log_path() -> Path:
    override = os.environ.get("AI_ENGINE_AUDIT_LOG")
    if override:
        return Path(override)
    return _get_repo_root() / "ai_engine" / "logs" / "agent_audit.log"


def get_default_executor_audit_path() -> Path:
    override = os.environ.get("AI_ENGINE_EXECUTOR_AUDIT_LOG")
    if override:
        return Path(override)
    return _get_repo_root() / "logs" / "executor_audit.log"


# --------------------------------------------------------------------------- Health Checker
class HealthChecker:
    """Polls infrastructure targets periodically and caches their status in memory."""

    def __init__(
        self,
        targets_path: Optional[str | Path] = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    ):
        self.targets_path = Path(targets_path) if targets_path else get_default_targets_path()
        self.poll_interval = float(poll_interval)
        self.probe_timeout = float(probe_timeout)
        self._lock = threading.Lock()
        self._targets: List[Dict[str, Any]] = []
        self._results: Dict[str, Dict[str, Any]] = {}
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        self.reload_targets()

    def reload_targets(self) -> None:
        """Load or reload targets from YAML file."""
        targets: List[Dict[str, Any]] = []
        if self.targets_path.exists():
            try:
                with open(self.targets_path, "r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if isinstance(content, dict) and "targets" in content:
                        targets = list(content["targets"])
                    elif isinstance(content, list):
                        targets = list(content)
            except Exception as exc:
                logger.error("Failed to load targets from %s: %s", self.targets_path, exc)

        with self._lock:
            self._targets = targets
            for t in targets:
                name = t.get("name")
                if name and name not in self._results:
                    self._results[name] = {
                        "name": name,
                        "type": t.get("type", "tcp_port"),
                        "host": t.get("host", "127.0.0.1"),
                        "port": t.get("port"),
                        "path": t.get("path"),
                        "status": "unknown",
                        "last_checked": None,
                        "latency_ms": None,
                        "error": None,
                    }

    @staticmethod
    def check_target(target: Dict[str, Any], timeout: float = DEFAULT_PROBE_TIMEOUT) -> Dict[str, Any]:
        """Perform a single health check using standard library socket or urllib."""
        name = target.get("name", "unnamed")
        target_type = target.get("type", "tcp_port")
        host = target.get("host", "127.0.0.1")
        port = target.get("port")
        path = target.get("path") or "/"

        base_res = {
            "name": name,
            "type": target_type,
            "host": host,
            "port": port,
            "path": path if target_type == "http" else None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

        if target_type == "tcp_port":
            if not port:
                return {**base_res, "status": "down", "latency_ms": None, "error": "Missing port configuration"}

            start = time.perf_counter()
            try:
                sock = socket.create_connection((host, int(port)), timeout=timeout)
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                sock.close()
                return {**base_res, "status": "up", "latency_ms": latency_ms, "error": None}
            except ConnectionRefusedError:
                return {**base_res, "status": "down", "latency_ms": None, "error": "Connection refused"}
            except (socket.timeout, TimeoutError):
                return {**base_res, "status": "down", "latency_ms": None, "error": "Connection timed out"}
            except socket.gaierror as exc:
                return {**base_res, "status": "down", "latency_ms": None, "error": f"DNS failure: {exc}"}
            except OSError as exc:
                err_str = str(exc)
                if "Connection refused" in err_str:
                    err = "Connection refused"
                elif "timed out" in err_str.lower():
                    err = "Connection timed out"
                else:
                    err = f"Connection failed: {exc}"
                return {**base_res, "status": "down", "latency_ms": None, "error": err}
            except Exception as exc:
                return {**base_res, "status": "down", "latency_ms": None, "error": f"Error: {exc}"}

        elif target_type == "http":
            p = path if path.startswith("/") else f"/{path}"
            port_part = f":{port}" if port else ""
            url = f"http://{host}{port_part}{p}"
            req = urllib.request.Request(url, headers={"User-Agent": "SOC-HealthChecker/1.0"})

            start = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    latency_ms = round((time.perf_counter() - start) * 1000, 2)
                    return {**base_res, "status": "up", "latency_ms": latency_ms, "error": None}
            except urllib.error.HTTPError as exc:
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                # HTTP error responses (e.g., 404, 500) indicate target is down or endpoint error
                return {
                    **base_res,
                    "status": "down",
                    "latency_ms": latency_ms,
                    "error": f"HTTP {exc.code}: {exc.reason}",
                }
            except urllib.error.URLError as exc:
                reason = exc.reason
                if isinstance(reason, ConnectionRefusedError) or "Connection refused" in str(reason):
                    err = "Connection refused"
                elif isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason).lower():
                    err = "Connection timed out"
                elif isinstance(reason, socket.gaierror) or "nodename" in str(reason).lower() or "servname" in str(reason).lower():
                    err = f"DNS failure: {reason}"
                else:
                    err = f"Connection failed: {reason}"
                return {**base_res, "status": "down", "latency_ms": None, "error": err}
            except (socket.timeout, TimeoutError):
                return {**base_res, "status": "down", "latency_ms": None, "error": "Connection timed out"}
            except Exception as exc:
                return {**base_res, "status": "down", "latency_ms": None, "error": f"Error: {exc}"}

        else:
            return {**base_res, "status": "down", "latency_ms": None, "error": f"Unsupported target type: {target_type}"}

    def check_all(self) -> List[Dict[str, Any]]:
        """Run health check against all configured targets in parallel."""
        with self._lock:
            targets_to_check = list(self._targets)

        if not targets_to_check:
            return []

        results: List[Dict[str, Any]] = []
        max_workers = min(10, len(targets_to_check))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_name = {
                executor.submit(self.check_target, t, self.probe_timeout): t.get("name", "unnamed")
                for t in targets_to_check
            }
            for future in concurrent.futures.as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    res = future.result()
                except Exception as exc:
                    res = {
                        "name": name,
                        "status": "down",
                        "last_checked": datetime.now(timezone.utc).isoformat(),
                        "latency_ms": None,
                        "error": f"Checker internal error: {exc}",
                    }
                results.append(res)

        with self._lock:
            for r in results:
                self._results[r["name"]] = r

        # Return in original target order
        with self._lock:
            ordered = []
            for t in self._targets:
                n = t.get("name")
                if n and n in self._results:
                    ordered.append(self._results[n])
            return ordered

    def get_status(self) -> Dict[str, Any]:
        """Return the latest cached status for all targets."""
        with self._lock:
            ordered = []
            for t in self._targets:
                n = t.get("name")
                if n and n in self._results:
                    ordered.append(dict(self._results[n]))
                else:
                    ordered.append(
                        {
                            "name": n,
                            "type": t.get("type", "tcp_port"),
                            "host": t.get("host", "127.0.0.1"),
                            "port": t.get("port"),
                            "path": t.get("path"),
                            "status": "unknown",
                            "last_checked": None,
                            "latency_ms": None,
                            "error": None,
                        }
                    )
            return {
                "status": "ok",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "targets": ordered,
            }

    def _run_loop(self) -> None:
        """Background worker loop polling every poll_interval seconds."""
        # Initial check immediately upon start
        self.check_all()
        while not self._stop_event.is_set():
            if self._stop_event.wait(self.poll_interval):
                break
            self.check_all()

    def start(self) -> None:
        """Start the background checker thread."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._stop_event.clear()
            self._worker_thread = threading.Thread(target=self._run_loop, name="HealthCheckerThread", daemon=True)
            self._worker_thread.start()

    def stop(self) -> None:
        """Stop the background checker thread."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)


# --------------------------------------------------------------------------- Audit Log Reader
class AuditLogReader:
    """Reads and correlates pipeline and executor audit logs grouped by incident_id."""

    def __init__(
        self,
        audit_log_path: Optional[str | Path] = None,
        executor_audit_path: Optional[str | Path] = None,
    ):
        self.audit_log_path = Path(audit_log_path) if audit_log_path else get_default_audit_log_path()
        self.executor_audit_path = (
            Path(executor_audit_path) if executor_audit_path else get_default_executor_audit_path()
        )

    def _read_lines(self, path: Path) -> List[Dict[str, Any]]:
        """Read and parse json lines from a file if it exists."""
        if not path.exists():
            return []
        records = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict):
                            records.append(record)
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            logger.warning("Unable to read audit log %s: %s", path, exc)
        return records

    def load_incidents(self) -> List[Dict[str, Any]]:
        """Parse audit logs, group by incident_id, and format stage timings and statuses."""
        agent_records = self._read_lines(self.audit_log_path)
        executor_records = self._read_lines(self.executor_audit_path)

        if not agent_records and not executor_records:
            return []

        # Index executor records by incident_id
        executor_by_id: Dict[str, List[Dict[str, Any]]] = {}
        for rec in executor_records:
            inc_id = rec.get("incident_id")
            if inc_id:
                executor_by_id.setdefault(inc_id, []).append(rec)

        # Separate pipeline decisions and agent llm calls
        decisions: List[Dict[str, Any]] = []
        llm_calls: List[Dict[str, Any]] = []

        for rec in agent_records:
            if rec.get("record") == "pipeline_decision":
                decisions.append(rec)
            elif rec.get("record") == "llm_call" or "agent" in rec:
                llm_calls.append(rec)

        # Map decisions to incident structures
        incidents: List[Dict[str, Any]] = []
        seen_incident_ids = set()

        for idx, dec in enumerate(decisions):
            inc_id = dec.get("incident_id", f"inc-unknown-{idx}")
            seen_incident_ids.add(inc_id)

            dec_ts = dec.get("ts", 0.0)
            duration_ms = dec.get("duration_ms", 0)
            start_ts = dec_ts - (duration_ms / 1000.0) - 2.0  # allow small 2s clock jitter

            # Associate LLM calls belonging to this incident
            # Either explicit incident_id or timestamp window between prev decision and this decision
            prev_dec_ts = decisions[idx - 1].get("ts", 0.0) if idx > 0 else 0.0
            window_start = max(start_ts, prev_dec_ts)

            matching_calls: List[Dict[str, Any]] = []
            for call in llm_calls:
                call_inc = call.get("incident_id")
                if call_inc == inc_id:
                    matching_calls.append(call)
                elif not call_inc:
                    call_ts = call.get("ts", 0.0)
                    if window_start <= call_ts <= dec_ts + 1.0:
                        matching_calls.append(call)

            # Build per-stage summary
            stages = self._build_stages(dec, matching_calls, executor_by_id.get(inc_id, []))

            dt_iso = datetime.fromtimestamp(dec_ts, tz=timezone.utc).isoformat() if dec_ts else None

            incident = {
                "incident_id": inc_id,
                "timestamp": dt_iso,
                "ts": dec_ts,
                "correlation_key": dec.get("correlation_key", []),
                "event_count": dec.get("event_count", 0),
                "halted_at": dec.get("halted_at", "gate"),
                "risk_score": dec.get("risk_score"),
                "final_decision": dec.get("final_decision", "unknown"),
                "proposed_action": dec.get("proposed_action"),
                "validation_errors": dec.get("validation_errors", []),
                "duration_ms": duration_ms,
                "stages": stages,
                "audit_records": matching_calls + [dec] + executor_by_id.get(inc_id, []),
            }
            incidents.append(incident)

        # Also capture any executor-only incidents (e.g. if testing executor in isolation)
        for inc_id, exec_recs in executor_by_id.items():
            if inc_id not in seen_incident_ids:
                latest_exec = exec_recs[-1]
                ts = latest_exec.get("ts", 0.0)
                dt_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
                incidents.append(
                    {
                        "incident_id": inc_id,
                        "timestamp": dt_iso,
                        "ts": ts,
                        "correlation_key": [],
                        "event_count": 0,
                        "halted_at": "executor",
                        "risk_score": None,
                        "final_decision": "unknown",
                        "proposed_action": latest_exec.get("action"),
                        "validation_errors": [],
                        "duration_ms": 0,
                        "stages": self._build_stages({}, [], exec_recs),
                        "audit_records": exec_recs,
                    }
                )

        # Sort incidents descending by timestamp (newest first)
        incidents.sort(key=lambda x: x.get("ts", 0.0), reverse=True)
        return incidents

    def _build_stages(
        self,
        decision_rec: Dict[str, Any],
        llm_calls: List[Dict[str, Any]],
        executor_calls: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Construct structured stage info for triage, mitre, decision, gate, and executor."""
        halted_at = decision_rec.get("halted_at", "gate")
        final_decision = decision_rec.get("final_decision", "unknown")
        validation_errors = decision_rec.get("validation_errors", [])

        # Find agent calls
        triage_call = next((c for c in llm_calls if "triage" in c.get("agent", "")), None)
        mitre_call = next((c for c in llm_calls if "mitre" in c.get("agent", "")), None)
        decision_call = next((c for c in llm_calls if "decision" in c.get("agent", "")), None)

        # 1. Triage Stage
        if triage_call:
            triage_stage = {
                "status": "ok" if triage_call.get("outcome") == "ok" else "error",
                "duration_ms": triage_call.get("latency_ms"),
                "agent": triage_call.get("agent"),
                "model": triage_call.get("model"),
                "outcome": triage_call.get("outcome"),
                "error": None if triage_call.get("outcome") == "ok" else triage_call.get("outcome"),
            }
        elif halted_at == "triage":
            triage_stage = {
                "status": "error",
                "duration_ms": None,
                "agent": "triage_agent",
                "model": None,
                "outcome": "error",
                "error": "; ".join(validation_errors) or "Triage stage failed",
            }
        else:
            triage_stage = {
                "status": "ok" if decision_rec else "not_run",
                "duration_ms": None,
                "agent": "triage_agent",
                "model": None,
                "outcome": "ok" if decision_rec else None,
                "error": None,
            }

        # 2. MITRE ATT&CK Stage
        if mitre_call:
            mitre_ok = mitre_call.get("outcome") == "ok" and halted_at != "mitre"
            mitre_stage = {
                "status": "ok" if mitre_ok else "error",
                "duration_ms": mitre_call.get("latency_ms"),
                "agent": mitre_call.get("agent"),
                "model": mitre_call.get("model"),
                "outcome": mitre_call.get("outcome"),
                "error": "; ".join(validation_errors) if halted_at == "mitre" else None,
            }
        elif halted_at == "mitre":
            mitre_stage = {
                "status": "error",
                "duration_ms": None,
                "agent": "mitre_agent",
                "model": None,
                "outcome": "error",
                "error": "; ".join(validation_errors) or "MITRE validation failed",
            }
        elif halted_at == "triage":
            mitre_stage = {
                "status": "skipped",
                "duration_ms": None,
                "agent": "mitre_agent",
                "model": None,
                "outcome": "skipped",
                "error": None,
            }
        else:
            mitre_stage = {
                "status": "ok" if decision_rec else "not_run",
                "duration_ms": None,
                "agent": "mitre_agent",
                "model": None,
                "outcome": "ok" if decision_rec else None,
                "error": None,
            }

        # 3. Decision Stage
        if decision_call:
            dec_ok = decision_call.get("outcome") == "ok" and halted_at != "decision"
            decision_stage = {
                "status": "ok" if dec_ok else "error",
                "duration_ms": decision_call.get("latency_ms"),
                "agent": decision_call.get("agent"),
                "model": decision_call.get("model"),
                "outcome": decision_call.get("outcome"),
                "proposed_action": decision_rec.get("proposed_action"),
                "error": "; ".join(validation_errors) if halted_at == "decision" else None,
            }
        elif halted_at == "decision":
            decision_stage = {
                "status": "error",
                "duration_ms": None,
                "agent": "decision_agent",
                "model": None,
                "outcome": "error",
                "proposed_action": None,
                "error": "; ".join(validation_errors) or "Decision agent failed",
            }
        elif halted_at in ("triage", "mitre"):
            decision_stage = {
                "status": "skipped",
                "duration_ms": None,
                "agent": "decision_agent",
                "model": None,
                "outcome": "skipped",
                "proposed_action": None,
                "error": None,
            }
        else:
            decision_stage = {
                "status": "ok" if decision_rec else "not_run",
                "duration_ms": None,
                "agent": "decision_agent",
                "model": None,
                "outcome": "ok" if decision_rec else None,
                "proposed_action": decision_rec.get("proposed_action"),
                "error": None,
            }

        # 4. Gate / Policy Stage
        if decision_rec:
            gate_status = "ok"
            if final_decision == "escalate":
                gate_status = "escalated"
            elif halted_at in ("gate", "policy") and validation_errors:
                gate_status = "error"
            gate_stage = {
                "status": gate_status,
                "halted_at": halted_at,
                "final_decision": final_decision,
                "risk_score": decision_rec.get("risk_score"),
                "error": "; ".join(validation_errors) if validation_errors else None,
            }
        else:
            gate_stage = {
                "status": "not_run",
                "halted_at": None,
                "final_decision": "unknown",
                "risk_score": None,
                "error": None,
            }

        # 5. Executor Stage
        if executor_calls:
            latest = executor_calls[-1]
            exec_status = latest.get("status", "unknown")
            exec_stage = {
                "status": exec_status,
                "action": latest.get("action"),
                "shadow_mode": latest.get("shadow_mode", True),
                "error": latest.get("reason") or latest.get("error"),
                "details": latest,
            }
        elif final_decision == "escalate":
            exec_stage = {
                "status": "refused",
                "action": None,
                "shadow_mode": True,
                "error": "Action refused: incident was escalated for human review",
                "details": None,
            }
        else:
            exec_stage = {
                "status": "none",
                "action": decision_rec.get("proposed_action"),
                "shadow_mode": True,
                "error": None,
                "details": None,
            }

        return {
            "triage": triage_stage,
            "mitre": mitre_stage,
            "decision": decision_stage,
            "gate": gate_stage,
            "executor": exec_stage,
        }

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single incident by its ID."""
        for inc in self.load_incidents():
            if inc.get("incident_id") == incident_id:
                return inc
        return None


# --------------------------------------------------------------------------- HTML UI Template
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Automation &bull; Health &amp; Pipeline Observability</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121826;
      --card-border: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.15);
      --up: #10b981;
      --up-bg: rgba(16, 185, 129, 0.15);
      --down: #ef4444;
      --down-bg: rgba(239, 68, 68, 0.15);
      --warn: #f59e0b;
      --warn-bg: rgba(245, 158, 11, 0.15);
      --code-bg: #0b0f19;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font);
      line-height: 1.5;
      padding: 24px;
      min-height: 100vh;
    }

    .container {
      max-width: 1300px;
      margin: 0 auto;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--card-border);
      flex-wrap: wrap;
      gap: 16px;
    }

    .title-group h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .title-group h1 span.pulse-dot {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background-color: var(--up);
      box-shadow: 0 0 10px var(--up);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }
    .title-group p {
      font-size: 0.875rem;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .btn {
      background: #1e293b;
      color: var(--text);
      border: 1px solid #334155;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .btn:hover {
      background: #334155;
      border-color: #475569;
    }
    .btn-primary {
      background: #0284c7;
      border-color: #0369a1;
    }
    .btn-primary:hover {
      background: #0369a1;
    }

    .last-refreshed {
      font-size: 0.8rem;
      color: var(--text-dim);
      font-family: var(--font-mono);
    }

    /* Panels */
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 22px;
      margin-bottom: 30px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 18px;
    }
    .panel-header h2 {
      font-size: 1.15rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .panel-header .badge-count {
      background: #1e293b;
      color: var(--text-muted);
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-family: var(--font-mono);
    }

    /* Tables */
    .table-container {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
      text-align: left;
    }
    th {
      background: rgba(15, 23, 42, 0.6);
      color: var(--text-muted);
      font-weight: 600;
      padding: 12px 14px;
      border-bottom: 1px solid var(--card-border);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }
    td {
      padding: 12px 14px;
      border-bottom: 1px solid rgba(30, 41, 59, 0.5);
      vertical-align: middle;
    }
    tr:last-child td {
      border-bottom: none;
    }
    tr.hover-row:hover td {
      background: rgba(30, 41, 59, 0.3);
    }

    /* Status Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .badge-up { background: var(--up-bg); color: var(--up); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-down { background: var(--down-bg); color: var(--down); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-warn { background: var(--warn-bg); color: var(--warn); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-unknown { background: #1e293b; color: var(--text-dim); border: 1px solid #334155; }

    .badge-autonomous { background: var(--up-bg); color: var(--up); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-soft_contain { background: var(--warn-bg); color: var(--warn); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-escalate { background: var(--down-bg); color: var(--down); border: 1px solid rgba(239, 68, 68, 0.3); }

    .mono {
      font-family: var(--font-mono);
      font-size: 0.825rem;
    }

    .error-text {
      color: #f87171;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      word-break: break-all;
    }

    .success-text {
      color: #34d399;
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }

    /* Incidents specific */
    .clickable-row {
      cursor: pointer;
    }
    .expand-icon {
      display: inline-block;
      transition: transform 0.2s;
      font-size: 0.75rem;
      color: var(--text-dim);
    }
    tr.expanded .expand-icon {
      transform: rotate(90deg);
      color: var(--accent);
    }

    .detail-row td {
      padding: 0;
      background: #0d121f;
    }
    .detail-content {
      padding: 16px 20px;
      border-top: 1px dashed var(--card-border);
      border-bottom: 1px dashed var(--card-border);
    }

    .stage-pipeline {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }
    .stage-card {
      background: #141c2e;
      border: 1px solid #233149;
      border-radius: 8px;
      padding: 12px;
    }
    .stage-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }
    .stage-name {
      font-weight: 600;
      font-size: 0.8rem;
      text-transform: uppercase;
      color: #cbd5e1;
    }
    .stage-body {
      font-size: 0.78rem;
      color: var(--text-muted);
    }
    .stage-body div {
      margin-top: 3px;
    }

    /* Empty state */
    .empty-state {
      padding: 48px 24px;
      text-align: center;
      color: var(--text-dim);
    }
    .empty-state svg {
      width: 48px;
      height: 48px;
      margin-bottom: 12px;
      stroke: var(--text-dim);
    }
    .empty-state h3 {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .empty-state p {
      font-size: 0.85rem;
    }

    /* Code block */
    pre.raw-json {
      background: var(--code-bg);
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      max-height: 220px;
      overflow-y: auto;
      color: #94a3b8;
      white-space: pre-wrap;
      word-break: break-all;
    }

    summary.json-summary {
      font-size: 0.8rem;
      color: var(--accent);
      cursor: pointer;
      margin-top: 10px;
      font-weight: 500;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-group">
        <h1><span class="pulse-dot"></span> SOC Automation Dashboard</h1>
        <p>Local Infrastructure Health &bull; AI Engine Observability</p>
      </div>
      <div class="header-actions">
        <span class="last-refreshed" id="last-refreshed-label">Updated: just now</span>
        <button class="btn" onclick="refreshAll()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
          Refresh
        </button>
      </div>
    </header>

    <!-- PART A: Infrastructure Health Panel -->
    <section class="panel">
      <div class="panel-header">
        <h2>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
          Infrastructure Health
        </h2>
        <span class="badge-count" id="health-summary">Loading...</span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Target Name</th>
              <th>Type</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>Latency</th>
              <th>Last Checked</th>
              <th>Diagnosis / Error</th>
            </tr>
          </thead>
          <tbody id="health-tbody">
            <tr>
              <td colspan="7" style="text-align:center; padding: 20px; color: var(--text-dim);">
                Probing configured infrastructure targets...
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- PART B: Pipeline Observability Panel -->
    <section class="panel">
      <div class="panel-header">
        <h2>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a855f7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
          Pipeline Incidents Observability
        </h2>
        <span class="badge-count" id="incidents-summary">0 Incidents</span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th style="width: 28px;"></th>
              <th>Incident ID</th>
              <th>Timestamp</th>
              <th>Correlation Key</th>
              <th>Events</th>
              <th>Final Decision</th>
              <th>Proposed Action</th>
              <th>Risk Score</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody id="incidents-tbody">
            <tr>
              <td colspan="9" style="text-align:center; padding: 20px; color: var(--text-dim);">
                Loading audit logs...
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    let expandedIncidents = new Set();

    async function fetchHealth() {
      try {
        const resp = await fetch('/api/health');
        if (!resp.ok) throw new Error('Health API error ' + resp.status);
        const data = await resp.json();
        renderHealth(data.targets || []);
      } catch (err) {
        console.error('Failed to fetch health:', err);
      }
    }

    function renderHealth(targets) {
      const tbody = document.getElementById('health-tbody');
      const summary = document.getElementById('health-summary');

      if (!targets || targets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim); padding:24px;">No targets configured.</td></tr>';
        summary.textContent = '0 Targets';
        return;
      }

      let upCount = 0;
      let downCount = 0;
      targets.forEach(t => {
        if (t.status === 'up') upCount++;
        else if (t.status === 'down') downCount++;
      });
      summary.textContent = `${upCount} UP / ${downCount} DOWN (${targets.length} Total)`;

      tbody.innerHTML = targets.map(t => {
        const statusBadge = t.status === 'up'
          ? '<span class="badge badge-up">UP</span>'
          : (t.status === 'down' ? '<span class="badge badge-down">DOWN</span>' : '<span class="badge badge-unknown">UNKNOWN</span>');

        const latencyText = (t.latency_ms !== null && t.latency_ms !== undefined)
          ? `<span class="mono">${t.latency_ms} ms</span>`
          : '<span style="color:var(--text-dim);">&mdash;</span>';

        const endpoint = t.type === 'http'
          ? `${t.host}:${t.port || 80}${t.path || '/'}`
          : `${t.host}:${t.port}`;

        const lastChecked = t.last_checked
          ? new Date(t.last_checked).toLocaleTimeString()
          : '&mdash;';

        const errorHtml = t.error
          ? `<span class="error-text">${escapeHtml(t.error)}</span>`
          : (t.status === 'up' ? '<span class="success-text">Reachable (OK)</span>' : '<span style="color:var(--text-dim);">&mdash;</span>');

        return `<tr class="hover-row">
          <td style="font-weight:600;">${escapeHtml(t.name)}</td>
          <td><span class="mono" style="color:var(--accent);">${escapeHtml(t.type)}</span></td>
          <td class="mono">${escapeHtml(endpoint)}</td>
          <td>${statusBadge}</td>
          <td>${latencyText}</td>
          <td class="mono" style="color:var(--text-muted);">${lastChecked}</td>
          <td>${errorHtml}</td>
        </tr>`;
      }).join('');
    }

    async function fetchIncidents() {
      try {
        const resp = await fetch('/api/incidents');
        if (!resp.ok) throw new Error('Incidents API error ' + resp.status);
        const data = await resp.json();
        renderIncidents(data.incidents || []);
      } catch (err) {
        console.error('Failed to fetch incidents:', err);
      }
    }

    function renderIncidents(incidents) {
      const tbody = document.getElementById('incidents-tbody');
      const summary = document.getElementById('incidents-summary');

      if (!incidents || incidents.length === 0) {
        summary.textContent = '0 Incidents';
        tbody.innerHTML = `<tr><td colspan="9">
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <h3>No incidents recorded yet</h3>
            <p>Audit log files are empty or not created yet in this environment.</p>
          </div>
        </td></tr>`;
        return;
      }

      summary.textContent = `${incidents.length} Incident${incidents.length > 1 ? 's' : ''}`;

      let rowsHtml = '';
      incidents.forEach(inc => {
        const isExp = expandedIncidents.has(inc.incident_id);
        const decBadgeClass = inc.final_decision === 'autonomous' ? 'badge-autonomous' : (inc.final_decision === 'soft_contain' ? 'badge-soft_contain' : 'badge-escalate');

        const keyStr = (inc.correlation_key && inc.correlation_key.length) ? inc.correlation_key.join(' / ') : '&mdash;';
        const timeStr = inc.timestamp ? new Date(inc.timestamp).toLocaleString() : '&mdash;';
        const riskStr = (inc.risk_score !== null && inc.risk_score !== undefined) ? Number(inc.risk_score).toFixed(2) : '&mdash;';
        const durStr = inc.duration_ms ? `${(inc.duration_ms / 1000).toFixed(2)}s` : '&mdash;';

        rowsHtml += `<tr class="hover-row clickable-row ${isExp ? 'expanded' : ''}" onclick="toggleIncident('${inc.incident_id}')">
          <td><span class="expand-icon">&#9654;</span></td>
          <td class="mono" style="font-weight:600; color:#38bdf8;">${escapeHtml(inc.incident_id)}</td>
          <td class="mono" style="font-size:0.8rem; color:var(--text-muted);">${timeStr}</td>
          <td class="mono">${escapeHtml(keyStr)}</td>
          <td>${inc.event_count || 0}</td>
          <td><span class="badge ${decBadgeClass}">${escapeHtml(inc.final_decision || 'unknown')}</span></td>
          <td class="mono" style="color:#e2e8f0;">${escapeHtml(inc.proposed_action || '&mdash;')}</td>
          <td class="mono">${riskStr}</td>
          <td class="mono">${durStr}</td>
        </tr>`;

        if (isExp) {
          rowsHtml += `<tr class="detail-row">
            <td colspan="9">
              <div class="detail-content">
                <div class="stage-pipeline">
                  ${renderStageCard('1. Triage', inc.stages ? inc.stages.triage : null)}
                  ${renderStageCard('2. MITRE ATT&CK', inc.stages ? inc.stages.mitre : null)}
                  ${renderStageCard('3. Decision Agent', inc.stages ? inc.stages.decision : null)}
                  ${renderStageCard('4. Gate & Policy', inc.stages ? inc.stages.gate : null)}
                  ${renderStageCard('5. Executor', inc.stages ? inc.stages.executor : null)}
                </div>
                ${inc.validation_errors && inc.validation_errors.length ? `
                  <div style="margin-top:10px; padding:10px; background:rgba(239,68,68,0.1); border-left:3px solid var(--down); border-radius:4px; font-size:0.8rem;">
                    <strong>Validation Errors:</strong>
                    <ul style="margin-left: 20px; margin-top: 4px;">
                      ${inc.validation_errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
                    </ul>
                  </div>
                ` : ''}
                <details>
                  <summary class="json-summary">View Raw Audit Records (${(inc.audit_records || []).length} lines)</summary>
                  <pre class="raw-json">${escapeHtml(JSON.stringify(inc.audit_records || [], null, 2))}</pre>
                </details>
              </div>
            </td>
          </tr>`;
        }
      });

      tbody.innerHTML = rowsHtml;
    }

    function renderStageCard(title, stage) {
      if (!stage) {
        return `<div class="stage-card">
          <div class="stage-card-header"><span class="stage-name">${title}</span><span class="badge badge-unknown">N/A</span></div>
          <div class="stage-body">No data recorded</div>
        </div>`;
      }

      const st = stage.status || 'unknown';
      let badgeClass = 'badge-unknown';
      if (st === 'ok' || st === 'simulated' || st === 'executed') badgeClass = 'badge-up';
      else if (st === 'error' || st === 'escalated') badgeClass = 'badge-down';
      else if (st === 'refused' || st === 'skipped') badgeClass = 'badge-warn';

      let bodyHtml = '';
      if (stage.duration_ms) bodyHtml += `<div>Timing: <span class="mono">${stage.duration_ms} ms</span></div>`;
      if (stage.model) bodyHtml += `<div>Model: <span class="mono">${escapeHtml(stage.model)}</span></div>`;
      if (stage.proposed_action) bodyHtml += `<div>Proposed: <span class="mono">${escapeHtml(stage.proposed_action)}</span></div>`;
      if (stage.final_decision) bodyHtml += `<div>Decision: <span class="mono">${escapeHtml(stage.final_decision)}</span></div>`;
      if (stage.risk_score !== undefined && stage.risk_score !== null) bodyHtml += `<div>Risk Score: <span class="mono">${stage.risk_score}</span></div>`;
      if (stage.action) bodyHtml += `<div>Action: <span class="mono">${escapeHtml(stage.action)}</span></div>`;
      if (stage.error) bodyHtml += `<div class="error-text" style="margin-top:4px;">${escapeHtml(stage.error)}</div>`;

      return `<div class="stage-card">
        <div class="stage-card-header">
          <span class="stage-name">${title}</span>
          <span class="badge ${badgeClass}">${escapeHtml(st)}</span>
        </div>
        <div class="stage-body">
          ${bodyHtml || '<span style="color:var(--text-dim);">Completed</span>'}
        </div>
      </div>`;
    }

    function toggleIncident(id) {
      if (expandedIncidents.has(id)) {
        expandedIncidents.delete(id);
      } else {
        expandedIncidents.add(id);
      }
      fetchIncidents();
    }

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    async function refreshAll() {
      document.getElementById('last-refreshed-label').textContent = 'Updating...';
      await Promise.all([fetchHealth(), fetchIncidents()]);
      document.getElementById('last-refreshed-label').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    }

    // Auto-refresh every 8 seconds
    refreshAll();
    setInterval(refreshAll, 8000);
  </script>
</body>
</html>
"""


# --------------------------------------------------------------------------- HTTP Request Handler
class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard HTML and JSON API endpoints."""

    checker: HealthChecker
    log_reader: AuditLogReader

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "" or path == "/index.html":
            self._send_html(HTML_PAGE)
        elif path == "/api/health":
            self._send_json(self.checker.get_status())
        elif path == "/api/incidents":
            incidents = self.log_reader.load_incidents()
            self._send_json({"status": "ok", "incidents": incidents})
        elif path.startswith("/api/incidents/"):
            inc_id = path[len("/api/incidents/") :]
            inc = self.log_reader.get_incident(inc_id)
            if inc is not None:
                self._send_json({"status": "ok", "incident": inc})
            else:
                self._send_json({"status": "error", "message": f"Incident '{inc_id}' not found"}, status=404)
        else:
            self._send_json({"status": "error", "message": "Not Found"}, status=404)

    def _send_html(self, content: str, status: int = 200) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        data = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        # Override to keep test output and terminal clean unless debugging
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)


# --------------------------------------------------------------------------- Server Factory
def create_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    targets_path: Optional[str | Path] = None,
    audit_log_path: Optional[str | Path] = None,
    executor_audit_path: Optional[str | Path] = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    auto_start_checker: bool = True,
) -> ThreadingHTTPServer:
    """Create and configure the ThreadingHTTPServer instance."""
    checker = HealthChecker(
        targets_path=targets_path,
        poll_interval=poll_interval,
        probe_timeout=probe_timeout,
    )
    log_reader = AuditLogReader(
        audit_log_path=audit_log_path,
        executor_audit_path=executor_audit_path,
    )

    class BoundHandler(DashboardHandler):
        pass

    BoundHandler.checker = checker
    BoundHandler.log_reader = log_reader

    server = ThreadingHTTPServer((host, port), BoundHandler)
    # Store references on server for lifecycle access
    server.checker = checker  # type: ignore[attr-defined]
    server.log_reader = log_reader  # type: ignore[attr-defined]

    if auto_start_checker:
        checker.start()

    return server


def main() -> None:
    """Entry point for running the dashboard server directly."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    host = os.environ.get("DASHBOARD_HOST", DEFAULT_HOST)
    port = int(os.environ.get("DASHBOARD_PORT", DEFAULT_PORT))
    targets_path = os.environ.get("DASHBOARD_TARGETS_PATH") or os.environ.get("DASHBOARD_TARGETS_FILE")
    audit_log_path = os.environ.get("AI_ENGINE_AUDIT_LOG")
    executor_audit_path = os.environ.get("AI_ENGINE_EXECUTOR_AUDIT_LOG")
    poll_interval = float(os.environ.get("DASHBOARD_POLL_INTERVAL", DEFAULT_POLL_INTERVAL))
    probe_timeout = float(os.environ.get("DASHBOARD_PROBE_TIMEOUT", DEFAULT_PROBE_TIMEOUT))

    server = create_server(
        host=host,
        port=port,
        targets_path=targets_path,
        audit_log_path=audit_log_path,
        executor_audit_path=executor_audit_path,
        poll_interval=poll_interval,
        probe_timeout=probe_timeout,
        auto_start_checker=True,
    )

    actual_port = server.server_port
    print(f"[*] SOC Automation Dashboard running on http://{host}:{actual_port}/")
    print(f"[*] Health targets: {server.checker.targets_path}")  # type: ignore[attr-defined]
    print(f"[*] Agent audit log: {server.log_reader.audit_log_path}")  # type: ignore[attr-defined]
    print(f"[*] Executor audit log: {server.log_reader.executor_audit_path}")  # type: ignore[attr-defined]
    print("[*] Press Ctrl+C to terminate.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down dashboard...")
    finally:
        server.checker.stop()  # type: ignore[attr-defined]
        server.server_close()


if __name__ == "__main__":
    main()
