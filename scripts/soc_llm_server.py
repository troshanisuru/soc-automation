#!/usr/bin/env python3
"""
Ollama-Compatible Local SOC LLM Server
======================================
Provides a lightweight, zero-GPU Ollama-compatible REST API on port 11434 so the
AI Engine agents (triage_agent, mitre_agent, decision_agent) and the SOC
Observability Dashboard can execute and test end-to-end without waiting for
remote GPU/A1 capacity.

If SOC_LLM_UPSTREAM_URL and SOC_LLM_API_KEY are exported, requests are forwarded
to an OpenAI-compatible chat completions endpoint; otherwise, the built-in
deterministic SOC reasoning engine evaluates the <untrusted_log> evidence and
returns strict schema-valid JSON matching TriageOutput, MitreOutput, and
DecisionOutput.

Usage:
    python3 scripts/soc_llm_server.py
    python3 scripts/soc_llm_server.py --host 127.0.0.1 --port 11434
"""

import argparse
import datetime
import html
import json
import logging
import os
import re
import signal
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("soc_llm_server")

EVENT_LINE_RE = re.compile(
    r"event_id=(?P<id>[A-Za-z0-9._:\-]+)\s+"
    r"source=(?P<src>\S+)\s+"
    r"time=(?P<ts>\S+)\s+"
    r"src_ip=(?P<ip>\S+)\s+"
    r"asset=(?P<asset>\S+)\s+"
    r"severity=(?P<sev>\d+)\s+"
    r"indicator=(?P<ind>.+)"
)

MITRE_RULES: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"sql\s*injection|sqli|union\s+select|xss|<script|onerror|path\s+traversal|\.\./|942100|941100|930100|931130|exploit", re.I),
        "T1190",
        "Exploit Public-Facing Application: Web exploitation payload detected against HTTP service",
    ),
    (
        re.compile(r"command\s+injection|os\s+command|\brce\b|/bin/sh|/bin/bash|shellshock|whoami|cat\s+/etc/passwd|process spawned|web\s*shell.*php|cmd\.php|932100|932160", re.I),
        "T1059",
        "Command and Scripting Interpreter: OS command execution or shell invocation attempt",
    ),
    (
        re.compile(r"web\s*shell\s*file\s*created|new\s+cron\s+entry|persistence|crontab", re.I),
        "T1505",
        "Server Software Component: Persistent web shell or scheduled task creation",
    ),
    (
        re.compile(r"sshd|failed\s+password|invalid\s+user|brute\s*force|password\s+spray|authentication\s+fail", re.I),
        "T1110",
        "Brute Force: Repeated authentication failures or credential guessing observed",
    ),
    (
        re.compile(r"outbound\s+beacon|periodic\s+outbound|outbound\s+connection.*:443|\bc2\b|command.and.control", re.I),
        "T1071",
        "Application Layer Protocol: Outbound command-and-control beaconing over application layer",
    ),
    (
        re.compile(r"wget\s+http|curl\s+http|tool\s+transfer|ingress", re.I),
        "T1105",
        "Ingress Tool Transfer: External payload or tool download attempt",
    ),
    (
        re.compile(r"internal\s+connection|->\s*db|5432|3306|lateral", re.I),
        "T1021",
        "Remote Services: Lateral movement attempt toward internal service tier",
    ),
    (
        re.compile(r"sudo\s+fail|privilege\s+escalation|suid|root\s+escalat", re.I),
        "T1068",
        "Exploitation for Privilege Escalation: Unauthorized privilege elevation attempt",
    ),
    (
        re.compile(r"/etc/passwd|/etc/shadow|local\s+file|credential\s+read", re.I),
        "T1005",
        "Data from Local System: Attempt to access sensitive local system files",
    ),
    (
        re.compile(r"port\s+scan|distinct\s+ports\s+probed|service\s+discovery", re.I),
        "T1046",
        "Network Service Discovery: Multi-port probing across target host",
    ),
    (
        re.compile(r"sqlmap|nikto|scanner|vulnerability\s+scan|913100|probing", re.I),
        "T1595",
        "Active Scanning: Automated vulnerability scanner reconnaissance fingerprint",
    ),
]


def _unwrap_untrusted(payload: str) -> str:
    """Strip <untrusted_log> boundary wrapper and unescape &lt;/&gt; for analysis."""
    text = payload.strip()
    if text.startswith("<untrusted_log>"):
        text = text[len("<untrusted_log>"):]
    if text.endswith("</untrusted_log>"):
        text = text[:-len("</untrusted_log>")]
    return html.unescape(text).strip()


def _parse_events(text: str) -> List[Dict[str, Any]]:
    """Extract structured event dictionaries from formatted prompt lines."""
    events: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = EVENT_LINE_RE.search(line)
        if not m:
            continue
        raw_ind = m.group("ind").strip()
        try:
            indicator = str(json.loads(raw_ind))
        except Exception:
            indicator = raw_ind
        events.append(
            {
                "event_id": m.group("id"),
                "source": m.group("src"),
                "time": m.group("ts"),
                "src_ip": m.group("ip"),
                "asset": m.group("asset"),
                "severity": int(m.group("sev")),
                "indicator": indicator,
            }
        )
    return events


def _load_valid_mitre_ids() -> Optional[set]:
    ref_path = Path(__file__).resolve().parent.parent / "ai_engine" / "reference" / "mitre_attack.json"
    if not ref_path.exists():
        return None
    try:
        data = json.loads(ref_path.read_text(encoding="utf-8"))
        return {t["id"] for t in data.get("techniques", []) if "id" in t}
    except Exception:
        return None


def _reason_triage(user_text: str) -> Dict[str, Any]:
    events = _parse_events(user_text)
    events_sorted = sorted(events, key=lambda e: e["time"])

    timeline: List[str] = []
    ips: List[str] = []
    assets: List[str] = []
    cited: List[str] = []

    for ev in events_sorted:
        if ev["src_ip"] not in ips:
            ips.append(ev["src_ip"])
        if ev["asset"] not in assets:
            assets.append(ev["asset"])
        if ev["event_id"] not in cited:
            cited.append(ev["event_id"])
        if len(timeline) < 25:
            step = (
                f"[{ev['source'].upper()} sev={ev['severity']}] "
                f"{ev['src_ip']} -> {ev['asset']}: {ev['indicator']}"
            )
            timeline.append(step[:300])

    if not timeline:
        timeline.append("No structured telemetry events found in log payload")

    return {
        "timeline": timeline[:25],
        "entities": {
            "ips": ips[:10],
            "assets": assets[:10],
        },
        "cited_event_ids": cited[:200],
    }


def _reason_mitre(user_text: str) -> Dict[str, Any]:
    events = _parse_events(user_text)
    cited = list(dict.fromkeys(e["event_id"] for e in events))[:200]
    if not cited:
        cited = list(dict.fromkeys(re.findall(r"event_id=([A-Za-z0-9._:\-]+)", user_text)))[:200]

    combined_text = user_text + "\n" + urllib.parse.unquote_plus(user_text)
    valid_ids = _load_valid_mitre_ids()

    techniques: List[str] = []
    justification: Dict[str, str] = {}

    for pattern, tid, reason in MITRE_RULES:
        if valid_ids is not None and tid not in valid_ids:
            continue
        if pattern.search(combined_text):
            if tid not in techniques:
                techniques.append(tid)
                justification[tid] = reason[:300]
        if len(techniques) >= 10:
            break

    max_sev = max((e["severity"] for e in events), default=0)
    if not techniques and max_sev > 2:
        fallback = "T1190"
        if valid_ids is None or fallback in valid_ids:
            techniques.append(fallback)
            justification[fallback] = "Exploit Public-Facing Application: High-severity anomalous activity on exposed service"

    return {
        "techniques": techniques[:10],
        "justification": justification,
        "cited_event_ids": cited,
    }


def _reason_decision(user_text: str) -> Dict[str, Any]:
    ev_match = re.search(r"Available evidence event IDs:\s*(\[[^\]]*\])", user_text)
    cited: List[str] = []
    if ev_match:
        try:
            cited = [str(x) for x in json.loads(ev_match.group(1))]
        except Exception:
            cited = []

    tech_match = re.search(r"MITRE techniques:\s*(\[[^\]]*\])", user_text)
    techniques: List[str] = []
    if tech_match:
        try:
            techniques = [str(x) for x in json.loads(tech_match.group(1))]
        except Exception:
            techniques = []

    tech_set = set(techniques)
    lower_text = user_text.lower()

    if tech_set & {"T1021", "T1071", "T1505", "T1068"}:
        proposed = "isolate_sg"
        just = (
            f"Detected post-exploitation, persistence, C2, or lateral movement indicators "
            f"({', '.join(sorted(tech_set))}); host network quarantine via NSG isolation is proportionate."
        )
    elif tech_set & {"T1190", "T1059", "T1005"} or (
        not tech_set
        and re.search(r"\b(sql\s*injection|sqli|xss|\brce\b|command\s+injection|traversal|942100|949110)\b", lower_text)
    ):
        proposed = "block_ip_waf"
        just = (
            f"Confirmed active web application exploitation attempts ({', '.join(sorted(tech_set)) or 'T1190'}); "
            "blocking the offending source IP at the WAF prevents further attack progression."
        )
    elif tech_set & {"T1595", "T1046", "T1110"}:
        proposed = "soft_rate_limit"
        just = (
            f"Observed reconnaissance scanning or brute-force probing ({', '.join(sorted(tech_set))}); "
            "applying temporary WAF rate limiting mitigates impact while minimizing false-positive risk."
        )
    else:
        proposed = "no_action"
        just = "No confirmed malicious MITRE ATT&CK indicators require automated containment."

    if proposed != "no_action" and not cited:
        cited = ["unknown"]

    return {
        "proposed_action": proposed,
        "justification": just[:600],
        "cited_event_ids": cited[:200],
    }


def _detect_agent_role(system_prompt: str, fmt: Any) -> str:
    if isinstance(fmt, dict):
        props = fmt.get("properties", {})
        if "timeline" in props and "entities" in props:
            return "triage"
        if "techniques" in props and "justification" in props:
            return "mitre"
        if "proposed_action" in props:
            return "decision"

    sys_lower = system_prompt.lower()
    if "triage agent" in sys_lower:
        return "triage"
    if "mitre" in sys_lower:
        return "mitre"
    if "decision agent" in sys_lower:
        return "decision"
    return "unknown"


def _forward_upstream(
    upstream_url: str,
    api_key: str,
    upstream_model: str,
    messages: List[Dict[str, str]],
    fmt: Any,
) -> Optional[str]:
    """Optional pass-through to an OpenAI-compatible cloud endpoint when configured."""
    body: Dict[str, Any] = {
        "model": upstream_model,
        "messages": messages,
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }
    if fmt and isinstance(fmt, dict):
        schema_hint = json.dumps(fmt)
        body["messages"][0]["content"] += f"\n\nJSON Schema Requirement:\n{schema_hint}"

    req = urllib.request.Request(
        upstream_url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


class OllamaCompatibleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path in ("/", "/api/tags"):
            self._send_json(
                200,
                {
                    "models": [
                        {
                            "name": "llama3.1:latest",
                            "model": "llama3.1:latest",
                            "modified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "size": 4661224676,
                            "details": {
                                "format": "gguf",
                                "family": "llama",
                                "parameter_size": "8.0B",
                                "quantization_level": "Q4_0",
                            },
                        }
                    ]
                },
            )
            return

        if self.path == "/api/version":
            self._send_json(200, {"version": "0.5.7-soc-compatible"})
            return

        self._send_json(404, {"error": f"Unknown endpoint: {self.path}"})

    def do_POST(self) -> None:
        if self.path != "/api/chat":
            self._send_json(404, {"error": f"Unsupported POST endpoint: {self.path}"})
            return

        content_len = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            req_data = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"Invalid JSON: {exc}"})
            return

        model_name = req_data.get("model", "llama3.1:latest")
        messages = req_data.get("messages", [])
        fmt = req_data.get("format")

        system_prompt = ""
        user_payload = ""
        for msg in messages:
            if msg.get("role") == "system":
                system_prompt = msg.get("content", "")
            elif msg.get("role") == "user":
                user_payload = msg.get("content", "")

        upstream_url = os.environ.get("SOC_LLM_UPSTREAM_URL", "").strip()
        upstream_key = os.environ.get("SOC_LLM_API_KEY", "").strip()
        upstream_model = os.environ.get("SOC_LLM_UPSTREAM_MODEL", "gpt-4o-mini").strip()

        content_str: Optional[str] = None
        if upstream_url and upstream_key:
            try:
                content_str = _forward_upstream(upstream_url, upstream_key, upstream_model, messages, fmt)
            except Exception as exc:
                logger.warning("Upstream LLM forwarding failed (%s); falling back to local SOC reasoner", exc)

        if content_str is None:
            unwrapped = _unwrap_untrusted(user_payload)
            role = _detect_agent_role(system_prompt, fmt)
            if role == "triage":
                result_obj = _reason_triage(unwrapped)
            elif role == "mitre":
                result_obj = _reason_mitre(unwrapped)
            elif role == "decision":
                result_obj = _reason_decision(unwrapped)
            else:
                result_obj = {"error": f"Unrecognized agent role for schema: {role}"}
            content_str = json.dumps(result_obj)
            logger.info("Processed %s agent request -> %d bytes JSON", role, len(content_str))

        self._send_json(
            200,
            {
                "model": model_name,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "message": {
                    "role": "assistant",
                    "content": content_str,
                },
                "done": True,
                "done_reason": "stop",
            },
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Ollama-Compatible Local SOC LLM Server")
    parser.add_argument("--host", default=os.environ.get("SOC_LLM_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SOC_LLM_PORT", "11434")))
    args = parser.parse_args()

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), OllamaCompatibleHandler)

    def _shutdown(signum: int, frame: Any) -> None:
        logger.info("Received signal %s, shutting down...", signum)
        threading_stop = lambda: server.shutdown()
        import threading
        threading.Thread(target=threading_stop, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("SOC LLM Server (Ollama API compatible) listening on http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
