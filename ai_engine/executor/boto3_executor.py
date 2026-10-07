import ipaddress
import json
import logging
import os
import threading
import time
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Literal, Optional

import boto3
from pydantic import BaseModel, ConfigDict
from botocore.exceptions import BotoCoreError, ClientError

from ai_engine.schemas.models import IncidentState

logger = logging.getLogger("ai_engine.executor")


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    status: Literal["simulated", "executed", "refused", "error"]
    details: Dict[str, Any]


_audit_lock = threading.Lock()
_audit_logger: Optional[logging.Logger] = None


def _audit_path() -> Path:
    override = os.environ.get("AI_ENGINE_EXECUTOR_AUDIT_LOG")
    return Path(override) if override else Path(__file__).resolve().parent.parent.parent / "logs" / "executor_audit.log"


def _get_audit_logger() -> Optional[logging.Logger]:
    global _audit_logger
    with _audit_lock:
        if _audit_logger is None:
            audit = logging.getLogger("ai_engine.executor_audit")
            audit.setLevel(logging.INFO)
            audit.propagate = False
            try:
                path = _audit_path()
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
                audit.addHandler(RotatingFileHandler(path, maxBytes=10_000_000, backupCount=5, encoding="utf-8"))
            except OSError as exc:
                logger.error("audit log unavailable (%s): calls will NOT be audited", exc)
                return None
            _audit_logger = audit
        return _audit_logger


def _audit(record: Dict[str, Any]) -> None:
    audit = _get_audit_logger()
    if audit is not None:
        audit.info(json.dumps(record, ensure_ascii=True, default=str))


def _is_shadow_mode() -> bool:
    return os.environ.get("SHADOW_MODE", "true").lower() == "true"


def _is_protected_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True  # Malformed IPs are refused

    protected_cidrs = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    ]
    env_cidrs = os.environ.get("PROTECTED_CIDRS", "")
    if env_cidrs:
        protected_cidrs.extend(c.strip() for c in env_cidrs.split(",") if c.strip())

    for cidr in protected_cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue

    return False


def _check_authorization(state: IncidentState, requested_action: str) -> Optional[ExecutionResult]:
    """Check if the final_decision authorizes this action. Return ExecutionResult on refusal."""
    ip = state.correlation_key[0]
    if _is_protected_ip(ip):
        err_msg = f"action {requested_action} refused: IP {ip} is protected or malformed"
        logger.error(err_msg)
        _audit({
            "ts": time.time(),
            "incident_id": state.incident_id,
            "action": requested_action,
            "status": "refused",
            "reason": err_msg
        })
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})

    fd = state.final_decision
    if fd == "escalate":
        err_msg = f"escalate decision refuses automated action {requested_action}"
        logger.error(err_msg)
        _audit({
            "ts": time.time(),
            "incident_id": state.incident_id,
            "action": requested_action,
            "status": "refused",
            "reason": err_msg
        })
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})
    
    if fd == "soft_contain" and requested_action not in ["soft_rate_limit", "no_action"]:
        err_msg = f"soft_contain decision refuses action {requested_action}"
        logger.error(err_msg)
        _audit({
            "ts": time.time(),
            "incident_id": state.incident_id,
            "action": requested_action,
            "status": "refused",
            "reason": err_msg
        })
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})
        
    if fd not in ["autonomous", "soft_contain"]:
        err_msg = f"invalid or missing final_decision: {fd}"
        logger.error(err_msg)
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})
        
    return None


def _execute_or_simulate(
    state: IncidentState, 
    action_name: str, 
    client_name: str, 
    method_name: str, 
    kwargs: Dict[str, Any],
    region_name: str
) -> ExecutionResult:
    call_record = {
        "ts": time.time(),
        "incident_id": state.incident_id,
        "action": action_name,
        "boto3_client": client_name,
        "boto3_method": method_name,
        "kwargs": kwargs,
        "shadow_mode": _is_shadow_mode()
    }
    
    if _is_shadow_mode():
        call_record["status"] = "simulated"
        _audit(call_record)
        return ExecutionResult(action=action_name, status="simulated", details={"simulated_call": kwargs})
        
    try:
        client = boto3.client(client_name, region_name=region_name)
        method = getattr(client, method_name)
        response = method(**kwargs)
        
        # Responses can include datetime objects which are not JSON serializable by default
        call_record["status"] = "executed"
        call_record["response"] = str(response)
        _audit(call_record)
        return ExecutionResult(action=action_name, status="executed", details={"response": str(response)})
    except (BotoCoreError, ClientError) as exc:
        call_record["status"] = "error"
        call_record["error"] = str(exc)
        logger.error("boto3 execution failed for %s: %s", action_name, exc)
        _audit(call_record)
        return ExecutionResult(action=action_name, status="error", details={"error": str(exc)})


def execute_block_ip_waf(state: IncidentState) -> ExecutionResult:
    action = "block_ip_waf"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal
    
    ip = state.correlation_key[0]
    ip_set_name = os.environ.get("WAF_BLOCK_IP_SET_NAME", "SOC-Block-Set")
    ip_set_id = os.environ.get("WAF_BLOCK_IP_SET_ID", "dummy-id")
    scope = os.environ.get("WAF_SCOPE", "REGIONAL")
    region = os.environ.get("AWS_REGION", "ap-southeast-1")
    
    if not _is_shadow_mode():
        try:
            client = boto3.client("wafv2", region_name=region)
            get_resp = client.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
            lock_token = get_resp["LockToken"]
            addresses = get_resp["IPSet"]["Addresses"]
            if f"{ip}/32" not in addresses:
                addresses.append(f"{ip}/32")
        except Exception as exc:
            return ExecutionResult(action=action, status="error", details={"error": f"get_ip_set failed: {exc}"})
    else:
        lock_token = "shadow-lock-token"
        addresses = [f"{ip}/32"]
        
    kwargs = {
        "Name": ip_set_name,
        "Scope": scope,
        "Id": ip_set_id,
        "Addresses": addresses,
        "LockToken": lock_token
    }
    
    return _execute_or_simulate(state, action, "wafv2", "update_ip_set", kwargs, region_name=region)


def execute_soft_rate_limit(state: IncidentState) -> ExecutionResult:
    action = "soft_rate_limit"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal
    
    ip = state.correlation_key[0]
    ip_set_name = os.environ.get("WAF_RATELIMIT_IP_SET_NAME", "SOC-RateLimit-Set")
    ip_set_id = os.environ.get("WAF_RATELIMIT_IP_SET_ID", "dummy-id")
    scope = os.environ.get("WAF_SCOPE", "REGIONAL")
    region = os.environ.get("AWS_REGION", "ap-southeast-1")
    
    if not _is_shadow_mode():
        try:
            client = boto3.client("wafv2", region_name=region)
            get_resp = client.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
            lock_token = get_resp["LockToken"]
            addresses = get_resp["IPSet"]["Addresses"]
            if f"{ip}/32" not in addresses:
                addresses.append(f"{ip}/32")
        except Exception as exc:
            return ExecutionResult(action=action, status="error", details={"error": f"get_ip_set failed: {exc}"})
    else:
        lock_token = "shadow-lock-token"
        addresses = [f"{ip}/32"]
        
    kwargs = {
        "Name": ip_set_name,
        "Scope": scope,
        "Id": ip_set_id,
        "Addresses": addresses,
        "LockToken": lock_token
    }
    
    return _execute_or_simulate(state, action, "wafv2", "update_ip_set", kwargs, region_name=region)


def execute_isolate_sg(state: IncidentState) -> ExecutionResult:
    action = "isolate_sg"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal
    
    # isolation requires a human-approval path that does not exist yet.
    # The audit record describes what a quarantine would do (replace the instance's 
    # security groups with a quarantine SG that allows only the Wazuh manager and admin IP) 
    # but never calls it.
    call_record = {
        "ts": time.time(),
        "incident_id": state.incident_id,
        "action": action,
        "status": "simulated",
        "shadow_mode": True,
        "details": "simulated quarantine: replace instance SG with quarantine SG (allowing only Wazuh mgr and admin IP)"
    }
    _audit(call_record)
    return ExecutionResult(action=action, status="simulated", details={"simulated_call": call_record["details"]})


def execute_no_action(state: IncidentState) -> ExecutionResult:
    action = "no_action"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal
    
    call_record = {
        "ts": time.time(),
        "incident_id": state.incident_id,
        "action": action,
        "status": "executed",
        "details": "no action required"
    }
    _audit(call_record)
    return ExecutionResult(action=action, status="executed", details={"message": "no action taken"})
