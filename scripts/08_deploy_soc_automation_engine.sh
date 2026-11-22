#!/usr/bin/env bash
#
# scripts/08_deploy_soc_automation_engine.sh
#
# Deploys the Autonomous SOC Automation Engine (ai_engine) directly onto the
# OCI wazuh-manager server (129.154.227.212 / 172.16.1.10) as two production
# systemd services:
#   1. soc-wazuh-poller.service       -> Tails /var/ossec/logs/alerts/alerts.json,
#                                        calls real Ollama (172.16.1.20:11434) for
#                                        Triage -> MITRE -> Decision -> Risk Gate -> OCI Executor
#   2. soc-platform-dashboard.service -> Serves the Wazuh-themed Autonomous SOC
#                                        Operations Platform on port 8080
#
# Usage:
#   bash scripts/08_deploy_soc_automation_engine.sh <wazuh-manager-public-ip>

set -euo pipefail

MANAGER_PUB_IP="${1:-129.154.227.212}"
OLLAMA_PRIV_URL="${OLLAMA_PRIV_URL:-http://172.16.1.20:11434}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o ServerAliveInterval=20)

echo "=================================================================="
echo "  1. Packaging & Syncing ai_engine to wazuh-manager (${MANAGER_PUB_IP})"
echo "=================================================================="
TMP_PKG="$(mktemp /tmp/soc-ai-engine.XXXXXX.tar.gz)"
trap 'rm -f "$TMP_PKG"' EXIT

tar -czf "$TMP_PKG" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='ai_engine/logs/*' \
    --exclude='ai_engine/data/*' \
    -C "$REPO_ROOT" \
    ai_engine requirements.txt

scp "${SSH_OPTS[@]}" "$TMP_PKG" "ubuntu@${MANAGER_PUB_IP}:/tmp/soc-ai-engine.tar.gz"

echo "=================================================================="
echo "  2. Installing Python Venv & Systemd Services on wazuh-manager"
echo "=================================================================="
ssh "${SSH_OPTS[@]}" "ubuntu@${MANAGER_PUB_IP}" "sudo bash -s" -- "$OLLAMA_PRIV_URL" <<'EOF'
set -euo pipefail
OLLAMA_URL="$1"
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y python3-venv python3-pip iptables-persistent

mkdir -p /opt/soc-automation/logs /opt/soc-automation/ai_engine/logs /opt/soc-automation/ai_engine/data
tar -xzf /tmp/soc-ai-engine.tar.gz -C /opt/soc-automation
rm -f /tmp/soc-ai-engine.tar.gz

if [[ ! -d /opt/soc-automation/.venv ]]; then
    python3 -m venv /opt/soc-automation/.venv
fi
/opt/soc-automation/.venv/bin/pip install --upgrade pip -q
/opt/soc-automation/.venv/bin/pip install -r /opt/soc-automation/requirements.txt -q

# Write private VCN targets.yaml for live cloud monitoring from inside security-vcn
cat >/opt/soc-automation/ai_engine/dashboard/targets.yaml <<'TGT'
targets:
  - name: web_server_http
    type: tcp_port
    host: 10.0.1.224
    port: 80

  - name: wazuh_manager_1514
    type: tcp_port
    host: 127.0.0.1
    port: 1514

  - name: wazuh_indexer_9200
    type: tcp_port
    host: 172.16.1.11
    port: 9200

  - name: wazuh_dashboard_443
    type: tcp_port
    host: 172.16.1.11
    port: 443

  - name: ollama_llm_11434
    type: http
    host: 172.16.1.20
    port: 11434
    path: /api/tags
TGT

# Open port 8080 in host iptables (OCI security-nsg restricts access strictly to admin /32)
if ! iptables -C INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport 8080 -j ACCEPT
fi
netfilter-persistent save || true

# 1. Systemd Service: Autonomous Wazuh Alert Poller -> Real Ollama AI Engine -> OCI Executor
cat >/etc/systemd/system/soc-wazuh-poller.service <<SVC1
[Unit]
Description=Autonomous SOC Wazuh Alert Poller & AI Triage Pipeline
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/soc-automation
Environment=PYTHONPATH=/opt/soc-automation
Environment=OLLAMA_BASE_URL=${OLLAMA_URL}
Environment=WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
Environment=WAZUH_POLL_INTERVAL=10
Environment=WAZUH_MIN_ALERT_LEVEL=7
Environment=WAZUH_REQUIRE_SRCIP=true
Environment=WAZUH_START_FROM_END=true
Environment=SHADOW_MODE=true
Environment=OCI_REGION=ap-mumbai-1
ExecStart=/opt/soc-automation/.venv/bin/python3 -m ai_engine.ingest.wazuh_poller
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC1

# 2. Systemd Service: Wazuh-Themed Autonomous SOC Operations Dashboard
cat >/etc/systemd/system/soc-platform-dashboard.service <<SVC2
[Unit]
Description=Autonomous SOC Operations Platform Dashboard (Wazuh EUI)
After=network-online.target soc-wazuh-poller.service

[Service]
Type=simple
WorkingDirectory=/opt/soc-automation
Environment=PYTHONPATH=/opt/soc-automation
Environment=OLLAMA_BASE_URL=${OLLAMA_URL}
Environment=DASHBOARD_HOST=0.0.0.0
Environment=DASHBOARD_PORT=8080
Environment=SHADOW_MODE=true
Environment=OCI_REGION=ap-mumbai-1
ExecStart=/opt/soc-automation/.venv/bin/python3 -m ai_engine.dashboard.server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC2

systemctl daemon-reload
systemctl enable --now soc-wazuh-poller.service soc-platform-dashboard.service
systemctl restart soc-wazuh-poller.service soc-platform-dashboard.service
sleep 3
echo "soc-wazuh-poller:       $(systemctl is-active soc-wazuh-poller.service)"
echo "soc-platform-dashboard: $(systemctl is-active soc-platform-dashboard.service)"
EOF
