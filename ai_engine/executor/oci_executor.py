import ipaddress
import json
import logging
import os
import threading
import time
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict

try:
    import oci
    from oci.exceptions import ServiceError, ClientError as OciClientError
except ImportError:  # pragma: no cover - allows simulation/tests when oci SDK is not yet installed
    oci = None  # type: ignore

    class ServiceError(Exception):  # type: ignore
        pass

    class OciClientError(Exception):  # type: ignore
        pass

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
        "127.0.0.0/8",
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
            "reason": err_msg,
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
            "reason": err_msg,
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
            "reason": err_msg,
        })
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})

    if fd not in ["autonomous", "soft_contain"]:
        err_msg = f"invalid or missing final_decision: {fd}"
        logger.error(err_msg)
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})

    events = getattr(state, "events", None) or []
    if (
        requested_action == "block_ip_waf"
        and events
        and all(getattr(e, "source", None) == "wazuh" and getattr(e, "auth_outcome", None) is not None for e in events)
    ):
        err_msg = "action block_ip_waf refused: HTTP WAF block cannot contain pure host SSH authentication incident"
        logger.error(err_msg)
        _audit({
            "ts": time.time(),
            "incident_id": state.incident_id,
            "action": requested_action,
            "status": "refused",
            "reason": err_msg,
        })
        return ExecutionResult(action=requested_action, status="refused", details={"error": err_msg})

    return None


def get_oci_client(client_type: str, region_name: str) -> Any:
    """Create an OCI service client using either Dynamic Group Instance Principals or ~/.oci/config."""
    if oci is None:
        raise RuntimeError("OCI Python SDK ('oci') is not installed.")

    auth_mode = os.environ.get("OCI_AUTH_MODE", "config_file")
    if auth_mode == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        config = {"region": region_name}
        if client_type == "waf":
            return oci.waf.WafClient(config, signer=signer)
        if client_type == "network":
            return oci.core.VirtualNetworkClient(config, signer=signer)
    else:
        profile = os.environ.get("OCI_CLI_PROFILE", "soc-project")
        config_path = os.environ.get("OCI_CONFIG_FILE", os.path.expanduser("~/.oci/config"))
        config = oci.config.from_file(file_location=config_path, profile_name=profile)
        config["region"] = region_name
        if client_type == "waf":
            return oci.waf.WafClient(config)
        if client_type == "network":
            return oci.core.VirtualNetworkClient(config)

    raise ValueError(f"Unsupported OCI client_type: {client_type}")


def _execute_or_simulate(
    state: IncidentState,
    action_name: str,
    client_name: str,
    method_name: str,
    kwargs: Dict[str, Any],
    region_name: str,
) -> ExecutionResult:
    call_record = {
        "ts": time.time(),
        "incident_id": state.incident_id,
        "action": action_name,
        "oci_client": client_name,
        "oci_method": method_name,
        "kwargs": kwargs,
        "shadow_mode": _is_shadow_mode(),
    }

    if _is_shadow_mode():
        call_record["status"] = "simulated"
        _audit(call_record)
        return ExecutionResult(action=action_name, status="simulated", details={"simulated_call": kwargs})

    try:
        client = get_oci_client(client_name, region_name=region_name)
        method = getattr(client, method_name)
        response = method(**kwargs)

        call_record["status"] = "executed"
        call_record["response"] = str(getattr(response, "data", response))
        _audit(call_record)
        return ExecutionResult(action=action_name, status="executed", details={"response": call_record["response"]})
    except (ServiceError, OciClientError, Exception) as exc:
        call_record["status"] = "error"
        call_record["error"] = str(exc)
        logger.error("OCI SDK execution failed for %s: %s", action_name, exc)
        _audit(call_record)
        return ExecutionResult(action=action_name, status="error", details={"error": str(exc)})


def _execute_waf_address_list_add(
    state: IncidentState,
    action_name: str,
    address_list_id: str,
    address_list_name: str,
    ip: str,
    region_name: str,
) -> ExecutionResult:
    """Add ``ip/32`` to an OCI WAF network address list idempotently, preserving existing entries."""
    target_cidr = f"{ip}/32"
    if _is_shadow_mode():
        kwargs = {
            "network_address_list_id": address_list_id,
            "display_name": address_list_name,
            "addresses": [target_cidr],
        }
        return _execute_or_simulate(state, action_name, "waf", "update_network_address_list", kwargs, region_name=region_name)

    call_record: Dict[str, Any] = {
        "ts": time.time(),
        "incident_id": state.incident_id,
        "action": action_name,
        "oci_client": "waf",
        "oci_method": "update_network_address_list",
        "network_address_list_id": address_list_id,
        "target_cidr": target_cidr,
        "shadow_mode": False,
    }
    try:
        client = get_oci_client("waf", region_name=region_name)
        existing = client.get_network_address_list(address_list_id)
        existing_addresses = list(getattr(getattr(existing, "data", None), "addresses", None) or [])
        headers = getattr(existing, "headers", None) or {}
        etag = headers.get("etag") or headers.get("ETag") or getattr(existing, "etag", None)

        if target_cidr in existing_addresses:
            call_record["status"] = "executed"
            call_record["already_present"] = True
            call_record["addresses"] = existing_addresses
            _audit(call_record)
            return ExecutionResult(
                action=action_name,
                status="executed",
                details={"already_present": True, "addresses": existing_addresses},
            )

        merged = existing_addresses + [target_cidr]
        details = oci.waf.models.UpdateNetworkAddressListAddressesDetails(
            display_name=address_list_name,
            addresses=merged,
        )
        response = client.update_network_address_list(
            network_address_list_id=address_list_id,
            update_network_address_list_details=details,
            if_match=etag,
        )
        call_record["status"] = "executed"
        call_record["addresses"] = merged
        call_record["response"] = str(getattr(response, "data", response))
        _audit(call_record)
        return ExecutionResult(
            action=action_name,
            status="executed",
            details={"response": call_record["response"], "addresses": merged},
        )
    except (ServiceError, OciClientError, Exception) as exc:
        call_record["status"] = "error"
        call_record["error"] = str(exc)
        logger.error("OCI SDK execution failed for %s: %s", action_name, exc)
        _audit(call_record)
        return ExecutionResult(action=action_name, status="error", details={"error": str(exc)})


def execute_block_ip_waf(state: IncidentState) -> ExecutionResult:
    action = "block_ip_waf"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal

    ip = state.correlation_key[0]
    address_list_name = os.environ.get("OCI_WAF_BLOCK_LIST_NAME", "SOC-OCI-Block-List")
    address_list_id = os.environ.get("OCI_WAF_BLOCK_LIST_OCID", "ocid1.wafnetworkaddresslist.oc1..dummy-block")
    region = os.environ.get("OCI_REGION", "ap-singapore-1")

    return _execute_waf_address_list_add(state, action, address_list_id, address_list_name, ip, region)


def execute_soft_rate_limit(state: IncidentState) -> ExecutionResult:
    action = "soft_rate_limit"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal

    ip = state.correlation_key[0]
    address_list_name = os.environ.get("OCI_WAF_RATELIMIT_LIST_NAME", "SOC-OCI-RateLimit-List")
    address_list_id = os.environ.get("OCI_WAF_RATELIMIT_LIST_OCID", "ocid1.wafnetworkaddresslist.oc1..dummy-ratelimit")
    region = os.environ.get("OCI_REGION", "ap-singapore-1")

    return _execute_waf_address_list_add(state, action, address_list_id, address_list_name, ip, region)


def execute_isolate_sg(state: IncidentState) -> ExecutionResult:
    action = "isolate_sg"
    refusal = _check_authorization(state, action)
    if refusal:
        return refusal

    # Isolation requires a human-approval path that does not exist yet.
    # The audit record describes what an OCI NSG quarantine would do (replace the instance VNIC's
    # NSGs with soc-automation-quarantine-nsg allowing only the Wazuh manager and admin IP).
    call_record = {
        "ts": time.time(),
        "incident_id": state.incident_id,
        "action": action,
        "status": "simulated",
        "shadow_mode": True,
        "details": "simulated quarantine: replace instance VNIC NSG with quarantine NSG (allowing only Wazuh mgr and admin IP)",
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
        "details": "no action required",
    }
    _audit(call_record)
    return ExecutionResult(action=action, status="executed", details={"message": "no action taken"})
