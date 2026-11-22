"""Autonomous SOC Automation Platform — Observability & Case Management Server.

Industry-grade, vendor-neutral Autonomous SOC / SOAR platform server:
1. Connector & Monitored Infrastructure Health Checker polling external client
   networks, SIEM endpoints, and AI reasoning engines (TCP / HTTP).
2. Real-time AI Triage Pipeline Observability correlating Triage, MITRE ATT&CK,
   Decision, Deterministic Risk Gate, Auth Policy, and Cloud Executor logs.
3. Human-in-the-Loop (HITL) Case Management API for escalated incidents
   (Acknowledge, Approve Containment, Mark False Positive, Analyst Notes).
4. Threat Intelligence (MITRE ATT&CK + Offending IOC IP Reputation) & Governance
   Policy introspection loaded directly from live YAML/JSON configuration.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
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


def get_default_case_store_path() -> Path:
    override = os.environ.get("SOC_CASE_STATE_PATH")
    if override:
        return Path(override)
    return _get_repo_root() / "ai_engine" / "data" / "case_state.json"


def _load_html_template() -> str:
    html_path = Path(__file__).resolve().parent / "static" / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return "<html><body><h1>Infrastructure Health</h1><h2>Pipeline Incidents Observability</h2></body></html>"


HTML_PAGE = _load_html_template()


# --------------------------------------------------------------------------- Case State Store (HITL)
class CaseStore:
    """Thread-safe JSON persistence for SOC Analyst case triage & HITL decisions."""

    def __init__(self, store_path: Optional[str | Path] = None):
        self.store_path = Path(store_path) if store_path else get_default_case_store_path()
        self._lock = threading.Lock()

    def _load_all(self) -> Dict[str, Dict[str, Any]]:
        if not self.store_path.exists():
            return {}
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.warning("Unable to read case store %s: %s", self.store_path, exc)
            return {}

    def _save_all(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return self._load_all()

    def update_case(
        self,
        incident_id: str,
        action: str,
        note: str = "",
        analyst: str = "soc-analyst",
    ) -> Dict[str, Any]:
        valid_actions = {"acknowledge", "approve_containment", "false_positive", "reopen", "add_note"}
        if action not in valid_actions:
            raise ValueError(f"Unsupported case action: {action}")

        status_map = {
            "acknowledge": "acknowledged",
            "approve_containment": "contained",
            "false_positive": "false_positive",
            "reopen": "open",
        }
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            all_cases = self._load_all()
            case = all_cases.get(
                incident_id,
                {
                    "incident_id": incident_id,
                    "case_status": "open",
                    "assignee": analyst,
                    "notes": [],
                    "updated_at": now_iso,
                },
            )
            if action in status_map:
                case["case_status"] = status_map[action]
            case["assignee"] = analyst
            case["updated_at"] = now_iso

            entry_text = note.strip() or f"Analyst executed action: {action}"
            case.setdefault("notes", []).append(
                {
                    "ts": now_iso,
                    "analyst": analyst,
                    "action": action,
                    "note": entry_text,
                }
            )
            all_cases[incident_id] = case
            self._save_all(all_cases)
            return dict(case)


# --------------------------------------------------------------------------- Health Checker
class HealthChecker:
    """Polls connected infrastructure & SIEM/AI endpoints periodically and caches status."""

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
        self.check_all()
        while not self._stop_event.is_set():
            if self._stop_event.wait(self.poll_interval):
                break
            self.check_all()

    def start(self) -> None:
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._stop_event.clear()
            self._worker_thread = threading.Thread(target=self._run_loop, name="HealthCheckerThread", daemon=True)
            self._worker_thread.start()

    def stop(self) -> None:
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
        case_store: Optional[CaseStore] = None,
    ):
        self.audit_log_path = Path(audit_log_path) if audit_log_path else get_default_audit_log_path()
        self.executor_audit_path = (
            Path(executor_audit_path) if executor_audit_path else get_default_executor_audit_path()
        )
        self.case_store = case_store

    def _read_lines(self, path: Path) -> List[Dict[str, Any]]:
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

    @staticmethod
    def _extract_agent_outputs(
        matching_calls: List[Dict[str, Any]],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        triage_out = None
        mitre_out = None
        decision_out = None
        for call in matching_calls:
            raw = call.get("raw_response")
            if not isinstance(raw, str) or not raw.strip():
                continue
            try:
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    continue
            except json.JSONDecodeError:
                continue
            agent = call.get("agent", "")
            if "triage" in agent:
                triage_out = parsed
            elif "mitre" in agent:
                mitre_out = parsed
            elif "decision" in agent:
                decision_out = parsed
        return triage_out, mitre_out, decision_out

    def load_incidents(self) -> List[Dict[str, Any]]:
        agent_records = self._read_lines(self.audit_log_path)
        executor_records = self._read_lines(self.executor_audit_path)
        saved_cases = self.case_store.get_all() if self.case_store else {}

        if not agent_records and not executor_records:
            return []

        executor_by_id: Dict[str, List[Dict[str, Any]]] = {}
        for rec in executor_records:
            inc_id = rec.get("incident_id")
            if inc_id:
                executor_by_id.setdefault(inc_id, []).append(rec)

        decisions: List[Dict[str, Any]] = []
        llm_calls: List[Dict[str, Any]] = []

        for rec in agent_records:
            if rec.get("record") == "pipeline_decision":
                decisions.append(rec)
            elif rec.get("record") == "llm_call" or "agent" in rec:
                llm_calls.append(rec)

        incidents: List[Dict[str, Any]] = []
        seen_incident_ids = set()

        for idx, dec in enumerate(decisions):
            inc_id = dec.get("incident_id", f"inc-unknown-{idx}")
            seen_incident_ids.add(inc_id)

            dec_ts = dec.get("ts", 0.0)
            duration_ms = dec.get("duration_ms", 0)
            start_ts = dec_ts - (duration_ms / 1000.0) - 2.0

            prev_dec_ts = decisions[idx - 1].get("ts", 0.0) if idx > 0 else 0.0
            window_start = max(start_ts, prev_dec_ts)

            matching_calls: List[Dict[str, Any]] = []
            for call in llm_calls:
                call_inc = call.get("incident_id")
                if call_inc == inc_id:
                    matching_calls.append(call)
                elif not call_inc:
                    call_ts = call.get("ts", 0.0)
                    if (idx == 0 and window_start <= call_ts <= dec_ts) or (
                        idx > 0 and prev_dec_ts < call_ts <= dec_ts
                    ):
                        matching_calls.append(call)

            stages = self._build_stages(dec, matching_calls, executor_by_id.get(inc_id, []))
            triage_out, mitre_out, decision_out = self._extract_agent_outputs(matching_calls)

            dt_iso = datetime.fromtimestamp(dec_ts, tz=timezone.utc).isoformat() if dec_ts else None
            default_case_status = (
                "contained" if dec.get("final_decision") in ("autonomous", "soft_contain") else "open"
            )
            case_meta = saved_cases.get(inc_id) or {
                "case_status": default_case_status,
                "assignee": "autonomous-engine" if default_case_status == "contained" else "unassigned",
                "notes": [],
                "updated_at": dt_iso,
            }

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
                "triage_output": triage_out,
                "mitre_output": mitre_out,
                "decision_output": decision_out,
                "case": case_meta,
                "audit_records": matching_calls + [dec] + executor_by_id.get(inc_id, []),
            }
            incidents.append(incident)

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
                        "triage_output": None,
                        "mitre_output": None,
                        "decision_output": None,
                        "case": saved_cases.get(
                            inc_id,
                            {"case_status": "contained", "assignee": "autonomous-engine", "notes": [], "updated_at": dt_iso},
                        ),
                        "audit_records": exec_recs,
                    }
                )

        incidents.sort(key=lambda x: x.get("ts", 0.0), reverse=True)
        return incidents

    def _build_stages(
        self,
        decision_rec: Dict[str, Any],
        llm_calls: List[Dict[str, Any]],
        executor_calls: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        halted_at = decision_rec.get("halted_at", "gate")
        final_decision = decision_rec.get("final_decision", "unknown")
        validation_errors = decision_rec.get("validation_errors", [])

        triage_call = next((c for c in llm_calls if "triage" in c.get("agent", "")), None)
        mitre_call = next((c for c in llm_calls if "mitre" in c.get("agent", "")), None)
        decision_call = next((c for c in llm_calls if "decision" in c.get("agent", "")), None)

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
                "error": "Action refused: incident was escalated for human analyst review",
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
        for inc in self.load_incidents():
            if inc.get("incident_id") == incident_id:
                return inc
        return None


# --------------------------------------------------------------------------- Intelligence & Governance Loaders
def _load_yaml_if_exists(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _build_threat_intel(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate MITRE ATT&CK techniques AND offending source IP IOC profiles."""
    repo_root = _get_repo_root()
    ref_map: Dict[str, Dict[str, Any]] = {}
    ref_path = repo_root / "ai_engine" / "reference" / "mitre_attack.json"
    if ref_path.exists():
        try:
            ref_data = json.loads(ref_path.read_text(encoding="utf-8"))
            for item in ref_data.get("techniques", []):
                if "id" in item:
                    ref_map[item["id"]] = item
        except Exception:
            pass

    thresh_data = _load_yaml_if_exists(repo_root / "ai_engine" / "config" / "thresholds.yaml")
    tactic_weights = dict(thresh_data.get("tactic_weights", {}))

    mitre_counts: Dict[str, Dict[str, Any]] = {}
    ioc_map: Dict[str, Dict[str, Any]] = {}

    for inc in incidents:
        mitre_out = inc.get("mitre_output") or {}
        techniques = mitre_out.get("techniques") or []
        justifications = mitre_out.get("justification") or {}

        for tid in techniques:
            if tid not in mitre_counts:
                meta = ref_map.get(tid, {})
                tactic = meta.get("tactic", "Unknown")
                mitre_counts[tid] = {
                    "id": tid,
                    "name": meta.get("name", tid),
                    "tactic": tactic,
                    "tactic_weight": tactic_weights.get(tactic),
                    "hits": 0,
                    "sample_justification": justifications.get(tid, ""),
                }
            mitre_counts[tid]["hits"] += 1
            if not mitre_counts[tid]["sample_justification"] and justifications.get(tid):
                mitre_counts[tid]["sample_justification"] = justifications[tid]

        corr = inc.get("correlation_key") or []
        src_ip = corr[0] if len(corr) >= 1 else None
        asset = corr[1] if len(corr) >= 2 else "unknown"
        if src_ip:
            entry = ioc_map.setdefault(
                src_ip,
                {
                    "ip": src_ip,
                    "incident_count": 0,
                    "max_risk_score": 0.0,
                    "targeted_assets": set(),
                    "techniques": set(),
                    "latest_decision": inc.get("final_decision", "unknown"),
                    "latest_action": inc.get("proposed_action") or "none",
                    "last_seen": inc.get("timestamp"),
                },
            )
            entry["incident_count"] += 1
            rs = inc.get("risk_score")
            if isinstance(rs, (int, float)) and rs > entry["max_risk_score"]:
                entry["max_risk_score"] = round(float(rs), 4)
            entry["targeted_assets"].add(asset)
            for tid in techniques:
                entry["techniques"].add(tid)

    iocs = []
    for entry in ioc_map.values():
        iocs.append(
            {
                **entry,
                "targeted_assets": sorted(entry["targeted_assets"]),
                "techniques": sorted(entry["techniques"]),
            }
        )
    iocs.sort(key=lambda x: (-x["max_risk_score"], -x["incident_count"], x["ip"]))

    sorted_mitre = sorted(
        mitre_counts.values(),
        key=lambda x: (-x["hits"], -(x["tactic_weight"] or 0.0), x["id"]),
    )
    return {"techniques": sorted_mitre, "iocs": iocs}


def _load_governance_policy() -> Dict[str, Any]:
    repo_root = _get_repo_root()
    thresholds = _load_yaml_if_exists(repo_root / "ai_engine" / "config" / "thresholds.yaml")
    models = _load_yaml_if_exists(repo_root / "ai_engine" / "config" / "models.yaml")
    return {
        "status": "ok",
        "shadow_mode": os.environ.get("SHADOW_MODE", "true").lower() == "true",
        "protected_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
        "thresholds": thresholds,
        "models": models,
        "auth_policy_rules": [
            {"id": "R0", "name": "Non-Auth Passthrough", "effect": "Maintain gate verdict when no auth failure telemetry is present"},
            {"id": "R4", "name": "Compromise Indicator (Success After Failure)", "effect": "High-priority preservation of autonomous/containment verdict"},
            {"id": "R1", "name": "Multi-Source Corroboration", "effect": "Maintain verdict when corroborated across >1 telemetry source (SIEM + WAF + Flow)"},
            {"id": "R2", "name": "High-Diversity Credential Spray", "effect": "Maintain containment when >=3 distinct users or >50% invalid accounts"},
            {"id": "R3", "name": "Known-Pair Stale Credential Guard", "effect": "Downgrade to human escalation for known user/IP slow retries (>=30s gap)"},
            {"id": "R5", "name": "High-Velocity Burst Guard", "effect": "Maintain containment for unknown pair bursts (<5s median interval)"},
            {"id": "CAP", "name": "Single-Source Autonomy Cap", "effect": "Single-source auth telemetry is capped at soft_contain (never autonomous block)"},
        ],
    }


def _load_telemetry_feed(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a read-only SIEM & WAF telemetry stream from ingested events & WAF logs."""
    repo_root = _get_repo_root()
    waf_json = _load_json_if_exists(repo_root / "evidence" / "waf_attack_test_report.json")
    waf_logs = (waf_json or {}).get("remote_waf_log_sample") or []

    events: List[Dict[str, Any]] = []
    for inc in incidents:
        triage = inc.get("triage_output") or {}
        timeline = triage.get("timeline") or []
        corr = inc.get("correlation_key") or ["unknown", "unknown"]
        for step in timeline:
            events.append(
                {
                    "timestamp": inc.get("timestamp"),
                    "incident_id": inc.get("incident_id"),
                    "source_ip": corr[0] if len(corr) > 0 else "unknown",
                    "asset": corr[1] if len(corr) > 1 else "unknown",
                    "summary": step,
                    "verdict": inc.get("final_decision"),
                }
            )

    return {
        "status": "ok",
        "ingested_events": events[:100],
        "waf_audit_logs": waf_logs,
        "waf_summary": {
            "blocked_total": (waf_json or {}).get("attacks_blocked", 0),
            "inspected_total": (waf_json or {}).get("total_tests", 0),
            "last_ingested": (waf_json or {}).get("timestamp_utc"),
        },
    }


def _record_analyst_containment_audit(executor_audit_path: Path, incident: Dict[str, Any], analyst: str, note: str) -> None:
    """Append an analyst-approved containment audit record to executor_audit.log."""
    record = {
        "ts": time.time(),
        "incident_id": incident.get("incident_id"),
        "action": incident.get("proposed_action") or "analyst_approved_containment",
        "status": "simulated" if os.environ.get("SHADOW_MODE", "true").lower() == "true" else "executed",
        "shadow_mode": os.environ.get("SHADOW_MODE", "true").lower() == "true",
        "approved_by": analyst,
        "details": f"HITL analyst approval ({analyst}): {note or 'Approved proposed containment action'}",
    }
    try:
        executor_audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(executor_audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True) + "\n")
    except OSError as exc:
        logger.warning("Failed writing analyst containment audit record: %s", exc)


def _ingest_siem_payload(payload: Any, case_store: CaseStore) -> Dict[str, Any]:
    """Ingest raw SIEM JSON alert(s), execute AI analysis, and escalate/contain cases."""
    from collections import defaultdict
    from ai_engine.ingest.wazuh_poller import dispatch_execution, get_baseline_store, parse_wazuh_alert
    from ai_engine.main import run_incident

    if isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        raw_alerts = payload["alerts"]
    elif isinstance(payload, list):
        raw_alerts = payload
    elif isinstance(payload, dict):
        raw_alerts = [payload]
    else:
        raise ValueError("SIEM payload must be a JSON alert object, list of alerts, or {'alerts': [...]}")

    if not raw_alerts:
        raise ValueError("No SIEM alerts supplied")

    store = get_baseline_store()
    events_by_key: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
    all_events = []
    ips_with_failures = set()

    for alert in raw_alerts:
        if not isinstance(alert, dict):
            continue
        event = parse_wazuh_alert(alert)
        all_events.append(event)
        if event.auth_outcome == "failure":
            ips_with_failures.add(event.source_ip)
        events_by_key[(event.source_ip, event.asset_tag)].append(event)

    if not all_events:
        raise ValueError("No valid SIEM alert objects found in payload")

    for event in all_events:
        if event.auth_outcome == "success" and event.source_ip not in ips_with_failures and event.username:
            store.record_success(event.username, event.source_ip, event.timestamp)

    analyzed = []
    for key, events in events_by_key.items():
        state = run_incident(events, baseline=store)
        exec_res = dispatch_execution(state)
        escalated = state.final_decision == "escalate"
        if escalated:
            reason = "; ".join(state.validation_errors) if state.validation_errors else (
                f"Escalated by deterministic risk gate (score={state.risk_score})"
            )
            case_store.update_case(
                state.incident_id,
                action="reopen",
                note=f"Automated SIEM escalation: {reason}",
                analyst="siem-ingestion-engine",
            )
        analyzed.append(
            {
                "incident_id": state.incident_id,
                "correlation_key": list(state.correlation_key),
                "event_count": len(events),
                "risk_score": state.risk_score,
                "final_decision": state.final_decision,
                "escalated": escalated,
                "proposed_action": state.decision.proposed_action if state.decision else None,
                "validation_errors": list(state.validation_errors),
                "execution": exec_res.model_dump() if exec_res else None,
            }
        )

    return {
        "status": "ok",
        "ingested_alerts": len(all_events),
        "incidents_analyzed": analyzed,
    }


# --------------------------------------------------------------------------- HTTP Request Handler
class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the Wazuh-themed Autonomous SOC Platform UI and REST APIs."""

    checker: HealthChecker
    log_reader: AuditLogReader
    case_store: CaseStore

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "" or path == "/index.html":
            self._send_html(_load_html_template())
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
        elif path == "/api/mitre":
            incidents = self.log_reader.load_incidents()
            intel = _build_threat_intel(incidents)
            self._send_json({"status": "ok", **intel})
        elif path == "/api/telemetry":
            incidents = self.log_reader.load_incidents()
            self._send_json(_load_telemetry_feed(incidents))
        elif path == "/api/policy":
            self._send_json(_load_governance_policy())
        elif path == "/api/system-info":
            self._send_json(
                {
                    "status": "ok",
                    "platform": "Autonomous SOC & SOAR Engine",
                    "deployment_model": "Vendor-Neutral Multi-Network Monitor",
                    "shadow_mode": os.environ.get("SHADOW_MODE", "true").lower() == "true",
                    "region": os.environ.get("OCI_REGION", "ap-mumbai-1"),
                }
            )
        else:
            self._send_json({"status": "error", "message": "Not Found"}, status=404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/health/refresh":
            self.checker.check_all()
            self._send_json(self.checker.get_status())
            return

        if path == "/api/siem/ingest":
            content_len = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_len) if content_len > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                self._send_json({"status": "error", "message": "Invalid JSON body"}, status=400)
                return

            try:
                result = _ingest_siem_payload(body, self.case_store)
                self._send_json(result)
            except ValueError as exc:
                self._send_json({"status": "error", "message": str(exc)}, status=400)
            except Exception as exc:
                logger.exception("SIEM ingestion failed")
                self._send_json({"status": "error", "message": str(exc)}, status=500)
            return

        if path.startswith("/api/incidents/") and path.endswith("/case"):
            inc_id = path[len("/api/incidents/") : -len("/case")].strip("/")
            inc = self.log_reader.get_incident(inc_id)
            if inc is None:
                self._send_json({"status": "error", "message": f"Incident '{inc_id}' not found"}, status=404)
                return

            content_len = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_len) if content_len > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                self._send_json({"status": "error", "message": "Invalid JSON body"}, status=400)
                return

            action = str(body.get("action", "")).strip()
            note = str(body.get("note", "")).strip()
            analyst = str(body.get("analyst", "soc-analyst")).strip() or "soc-analyst"

            try:
                updated_case = self.case_store.update_case(inc_id, action=action, note=note, analyst=analyst)
                if action == "approve_containment":
                    _record_analyst_containment_audit(self.log_reader.executor_audit_path, inc, analyst, note)
                self._send_json({"status": "ok", "case": updated_case})
            except ValueError as exc:
                self._send_json({"status": "error", "message": str(exc)}, status=400)
            return

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
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)


# --------------------------------------------------------------------------- Server Factory
def create_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    targets_path: Optional[str | Path] = None,
    audit_log_path: Optional[str | Path] = None,
    executor_audit_path: Optional[str | Path] = None,
    case_store_path: Optional[str | Path] = None,
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
    case_store = CaseStore(store_path=case_store_path)
    log_reader = AuditLogReader(
        audit_log_path=audit_log_path,
        executor_audit_path=executor_audit_path,
        case_store=case_store,
    )

    class BoundHandler(DashboardHandler):
        pass

    BoundHandler.checker = checker
    BoundHandler.log_reader = log_reader
    BoundHandler.case_store = case_store

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((host, port), BoundHandler)
    server.checker = checker  # type: ignore[attr-defined]
    server.log_reader = log_reader  # type: ignore[attr-defined]
    server.case_store = case_store  # type: ignore[attr-defined]

    if auto_start_checker:
        checker.start()

    return server


def main() -> None:
    """Entry point for running the Autonomous SOC Platform server directly."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    host = os.environ.get("DASHBOARD_HOST", DEFAULT_HOST)
    port = int(os.environ.get("DASHBOARD_PORT", DEFAULT_PORT))
    targets_path = os.environ.get("DASHBOARD_TARGETS_PATH") or os.environ.get("DASHBOARD_TARGETS_FILE")
    audit_log_path = os.environ.get("AI_ENGINE_AUDIT_LOG")
    executor_audit_path = os.environ.get("AI_ENGINE_EXECUTOR_AUDIT_LOG")
    case_store_path = os.environ.get("SOC_CASE_STATE_PATH")
    poll_interval = float(os.environ.get("DASHBOARD_POLL_INTERVAL", DEFAULT_POLL_INTERVAL))
    probe_timeout = float(os.environ.get("DASHBOARD_PROBE_TIMEOUT", DEFAULT_PROBE_TIMEOUT))

    server = create_server(
        host=host,
        port=port,
        targets_path=targets_path,
        audit_log_path=audit_log_path,
        executor_audit_path=executor_audit_path,
        case_store_path=case_store_path,
        poll_interval=poll_interval,
        probe_timeout=probe_timeout,
        auto_start_checker=True,
    )

    actual_port = server.server_port
    print(f"[*] Autonomous SOC Operations Platform running on http://{host}:{actual_port}/")
    print(f"[*] Monitored connectors: {server.checker.targets_path}")  # type: ignore[attr-defined]
    print(f"[*] AI Engine audit log:  {server.log_reader.audit_log_path}")  # type: ignore[attr-defined]
    print(f"[*] Executor audit log:   {server.log_reader.executor_audit_path}")  # type: ignore[attr-defined]
    print("[*] Press Ctrl+C to terminate.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down SOC platform...")
    finally:
        server.checker.stop()  # type: ignore[attr-defined]
        server.server_close()


if __name__ == "__main__":
    main()
