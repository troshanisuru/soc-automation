#!/usr/bin/env bash
#
# scripts/07_install_wazuh_distributed.sh
#
# Official Distributed (Multi-Node) Wazuh 4.x Deployment across two separate OCI servers:
#   - Node 1: wazuh-indexer (172.16.1.11) -> Wazuh Indexer + Wazuh Dashboard (HTTPS :443)
#   - Node 2: wazuh-manager (172.16.1.10) -> Wazuh Server (Manager + Filebeat) + Custom OCI/SSH/ModSecurity Rules
#
# Usage:
#   bash scripts/07_install_wazuh_distributed.sh <indexer-public-ip> <manager-public-ip>

set -euo pipefail

INDEXER_PUB_IP="${1:-}"
MANAGER_PUB_IP="${2:-}"
INDEXER_PRIV_IP="172.16.1.11"
MANAGER_PRIV_IP="172.16.1.10"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o ServerAliveInterval=20 -o ServerAliveCountMax=30)

if [[ -z "$INDEXER_PUB_IP" || -z "$MANAGER_PUB_IP" ]]; then
    echo "Usage: $0 <indexer-public-ip> <manager-public-ip>" >&2
    exit 1
fi

ssh_idx() { ssh "${SSH_OPTS[@]}" "ubuntu@${INDEXER_PUB_IP}" "$@"; }
ssh_mgr() { ssh "${SSH_OPTS[@]}" "ubuntu@${MANAGER_PUB_IP}" "$@"; }

echo "=================================================================="
echo "  1. Waiting for SSH readiness on both distributed Wazuh nodes"
echo "=================================================================="
for ip in "$INDEXER_PUB_IP" "$MANAGER_PUB_IP"; do
    for i in $(seq 1 25); do
        if ssh "${SSH_OPTS[@]}" "ubuntu@${ip}" "echo OK" >/dev/null 2>&1; then
            echo "[+] SSH ready on ${ip}"
            break
        fi
        sleep 5
    done
done

echo "=================================================================="
echo "  2. Preparing OS, Firewall (iptables) & Certificates on wazuh-indexer (${INDEXER_PUB_IP})"
echo "=================================================================="
ssh_idx "sudo bash -s" <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
hostnamectl set-hostname wazuh-indexer || true

cat >/etc/sysctl.d/99-wazuh-indexer.conf <<'SYS'
vm.max_map_count=262144
SYS
sysctl --system >/dev/null 2>&1 || true

apt-get update -y
apt-get install -y curl tar libcap2-bin iptables-persistent jq

for port in 443 9200 9300; do
    if ! iptables -C INPUT -p tcp --dport "\$port" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 1 -p tcp --dport "\$port" -j ACCEPT
    fi
done
netfilter-persistent save || true

cd /tmp
curl -fsSLO https://packages.wazuh.com/4.14/wazuh-install.sh
chmod +x /tmp/wazuh-install.sh

cat >/tmp/config.yml <<'CFG'
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "${INDEXER_PRIV_IP}"
  server:
    - name: wazuh-manager
      ip: "${MANAGER_PRIV_IP}"
  dashboard:
    - name: wazuh-indexer
      ip: "${INDEXER_PRIV_IP}"
CFG

rm -f /tmp/wazuh-install-files.tar
bash /tmp/wazuh-install.sh --generate-config-files -i
chmod 644 /tmp/wazuh-install-files.tar
EOF

echo "=================================================================="
echo "  3. Copying shared TLS bundle & Custom Rules to wazuh-manager (${MANAGER_PUB_IP})"
echo "=================================================================="
TMP_TAR="$(mktemp /tmp/wazuh-install-files.XXXXXX.tar)"
trap 'rm -f "$TMP_TAR"' EXIT

scp "${SSH_OPTS[@]}" "ubuntu@${INDEXER_PUB_IP}:/tmp/wazuh-install-files.tar" "$TMP_TAR"
scp "${SSH_OPTS[@]}" \
    "$TMP_TAR" \
    "${REPO_ROOT}/wazuh/rules/custom_oci_rules.xml" \
    "${REPO_ROOT}/wazuh/rules/custom_ssh_rules.xml" \
    "${REPO_ROOT}/wazuh/rules/custom_modsecurity_rules.xml" \
    "${REPO_ROOT}/wazuh/decoders/custom_modsecurity_decoders.xml" \
    "ubuntu@${MANAGER_PUB_IP}:/tmp/"
ssh_mgr "sudo mv /tmp/$(basename "$TMP_TAR") /tmp/wazuh-install-files.tar && sudo chmod 600 /tmp/wazuh-install-files.tar"

echo "=================================================================="
echo "  4. Installing Wazuh Indexer & Initializing Cluster on wazuh-indexer (${INDEXER_PUB_IP})"
echo "=================================================================="
ssh_idx "sudo bash -s" <<'EOF'
set -euo pipefail
cd /tmp
bash /tmp/wazuh-install.sh --wazuh-indexer wazuh-indexer -i -o
if [[ -f /etc/wazuh-indexer/jvm.options ]]; then
    sed -i 's/^-Xms.*/-Xms3g/' /etc/wazuh-indexer/jvm.options
    sed -i 's/^-Xmx.*/-Xmx3g/' /etc/wazuh-indexer/jvm.options
    systemctl restart wazuh-indexer
    sleep 10
fi
bash /tmp/wazuh-install.sh --start-cluster -i
systemctl is-active wazuh-indexer
EOF

echo "=================================================================="
echo "  5. Installing Wazuh Server (Manager + Filebeat) & Custom Rules on wazuh-manager (${MANAGER_PUB_IP})"
echo "=================================================================="
ssh_mgr "sudo bash -s" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
hostnamectl set-hostname wazuh-manager || true
apt-get update -y
apt-get install -y curl tar libcap2-bin iptables-persistent jq

for port in 1514 1515 55000; do
    if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
    fi
done
netfilter-persistent save || true

cd /tmp
curl -fsSLO https://packages.wazuh.com/4.14/wazuh-install.sh
chmod +x /tmp/wazuh-install.sh
bash /tmp/wazuh-install.sh --wazuh-server wazuh-manager -i -o

echo "[*] Deploying Custom OCI, SSH & ModSecurity Decoders and Rules..."
for rule_file in custom_oci_rules.xml custom_ssh_rules.xml custom_modsecurity_rules.xml; do
    if [[ -f "/tmp/${rule_file}" ]]; then
        cp "/tmp/${rule_file}" "/var/ossec/etc/rules/${rule_file}"
        chown root:wazuh "/var/ossec/etc/rules/${rule_file}"
        chmod 640 "/var/ossec/etc/rules/${rule_file}"
    fi
done

if [[ -f /tmp/custom_modsecurity_decoders.xml ]]; then
    cp /tmp/custom_modsecurity_decoders.xml /var/ossec/etc/decoders/custom_modsecurity_decoders.xml
    chown root:wazuh /var/ossec/etc/decoders/custom_modsecurity_decoders.xml
    chmod 640 /var/ossec/etc/decoders/custom_modsecurity_decoders.xml
fi

/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
systemctl is-active wazuh-manager
systemctl is-active filebeat
EOF

echo "=================================================================="
echo "  6. Installing Wazuh Dashboard on wazuh-indexer (${INDEXER_PUB_IP})"
echo "=================================================================="
ssh_idx "sudo bash -s" <<'EOF'
set -euo pipefail
cd /tmp
bash /tmp/wazuh-install.sh --wazuh-dashboard wazuh-indexer -i -o
systemctl is-active wazuh-dashboard

tar -axf /tmp/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > /root/wazuh-passwords.txt
chmod 600 /root/wazuh-passwords.txt
echo "[+] Wazuh Dashboard Credentials (admin):"
grep -A 2 "indexer_username: 'admin'" /root/wazuh-passwords.txt || grep -A 2 "admin" /root/wazuh-passwords.txt | head -n 6
EOF

echo "=================================================================="
echo "  DISTRIBUTED WAZUH DEPLOYMENT COMPLETE!"
echo "  - Wazuh Indexer + Dashboard : https://${INDEXER_PUB_IP} (Private ${INDEXER_PRIV_IP})"
echo "  - Wazuh Manager + Filebeat  : ${MANAGER_PUB_IP} (Private ${MANAGER_PRIV_IP})"
echo "=================================================================="
