#!/usr/bin/env bash
#
# scripts/06_install_ollama_server.sh
#
# Installs Ollama on the OCI ollama-server instance, configures systemd to listen
# on 0.0.0.0:11434, opens port 11434 in host iptables, pulls llama3.2:3b (optimal
# for 8 GB RAM hosts), and aliases it as llama3.1:latest for ai_engine/config/models.yaml.
#
# Usage:
#   bash scripts/06_install_ollama_server.sh <ollama-public-ip>

set -euo pipefail

OLLAMA_PUB_IP="${1:-132.226.188.209}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"

echo "=================================================================="
echo "  Installing Ollama + LLM Model on ollama-server (${OLLAMA_PUB_IP})"
echo "=================================================================="

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${OLLAMA_PUB_IP}" "sudo bash -s" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

hostnamectl set-hostname ollama-server || true
apt-get update -y
apt-get install -y curl zstd iptables-persistent

# Open port 11434 in OCI Ubuntu host iptables
if ! iptables -C INPUT -p tcp --dport 11434 -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport 11434 -j ACCEPT
fi
netfilter-persistent save || true

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Configure Ollama to listen on 0.0.0.0:11434 (protected by OCI security-nsg)
mkdir -p /etc/systemd/system/ollama.service.d
cat >/etc/systemd/system/ollama.service.d/override.conf <<'OVR'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
OVR

systemctl daemon-reload
systemctl enable --now ollama
systemctl restart ollama

# Wait for Ollama API readiness
for i in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# Pull llama3.2:3b (~2.0 GB, fits comfortably in 8 GB RAM) and alias as llama3.1:latest
ollama pull llama3.2:3b
ollama cp llama3.2:3b llama3.1:latest
ollama list
echo "[+] Ollama Server setup complete!"
EOF
