#!/usr/bin/env bash
#
# scripts/03_setup_web_and_wazuh_agent.sh
#
# Configures Nginx + Wazuh Agent on web-server (in isolated prod-vcn 10.0.1.0/24),
# connects it across the Local Peering Gateway (LPG) to wazuh-manager (in security-vcn 172.16.1.0/24),
# verifies active agent registration and real-time log ingestion on wazuh-manager,
# and confirms the Wazuh Dashboard HTTPS server is live on port 443.
#
# Usage:
#   bash scripts/03_setup_web_and_wazuh_agent.sh <web-public-ip> <wazuh-public-ip> <wazuh-private-ip>

set -euo pipefail

WEB_PUB_IP="${1:-}"
WAZUH_PUB_IP="${2:-}"
WAZUH_PRIV_IP="${3:-}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"

if [[ -z "$WEB_PUB_IP" || -z "$WAZUH_PUB_IP" || -z "$WAZUH_PRIV_IP" ]]; then
    echo "Usage: $0 <web-public-ip> <wazuh-public-ip> <wazuh-private-ip>" >&2
    exit 1
fi

ssh_web() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "ubuntu@${WEB_PUB_IP}" "$@"
}

ssh_wazuh() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "ubuntu@${WAZUH_PUB_IP}" "$@"
}

echo "=================================================================="
echo "  1. Configuring Nginx & Wazuh Agent on web-server (${WEB_PUB_IP})"
echo "=================================================================="
ssh_web "sudo bash -s" -- "$WAZUH_PRIV_IP" <<'EOF'
set -euo pipefail
WAZUH_MANAGER_IP="$1"

export DEBIAN_FRONTEND=noninteractive
hostnamectl set-hostname web-server || true

apt-get update -y
apt-get install -y curl gnupg apt-transport-https nginx iptables-persistent

# Open HTTP (80) and HTTPS (443) in OCI Ubuntu host iptables
for port in 80 443; do
    if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
    fi
done
netfilter-persistent save || true

systemctl enable --now nginx

# Install Wazuh GPG key and APT repository
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

apt-get update -y
WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_NAME="web-server" apt-get install -y wazuh-agent

# Ensure Nginx access/error logs are monitored by Wazuh Agent
if ! grep -q "/var/log/nginx/access.log" /var/ossec/etc/ossec.conf; then
    sed -i '/<\/ossec_config>/i \
  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/access.log</location>\n  </localfile>\n  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/error.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf
fi

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent
systemctl is-active wazuh-agent
EOF

echo "=================================================================="
echo "  2. Verifying Agent Connection & Log Ingestion on wazuh-manager"
echo "=================================================================="
sleep 8
ssh_wazuh "sudo /var/ossec/bin/agent_control -l"

echo "=== Triggering test authentication & HTTP events on web-server ==="
ssh_web "logger -p auth.warning 'sshd[99999]: Failed password for invalid user attacker_test from 198.51.100.99 port 54321 ssh2'"
curl -fsS "http://${WEB_PUB_IP}/?id=1%27%20OR%20%271%27=%271" >/dev/null || true
sleep 5

echo "=== Recent Alerts Received on wazuh-manager (/var/ossec/logs/alerts/alerts.json) ==="
ssh_wazuh "sudo tail -n 5 /var/ossec/logs/alerts/alerts.json"

echo "=================================================================="
echo "  3. Confirming Wazuh Dashboard HTTPS Hosting (https://${WAZUH_PUB_IP})"
echo "=================================================================="
ssh_wazuh "sudo systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard && curl -skI https://127.0.0.1:443 | head -n 5"
