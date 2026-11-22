#!/usr/bin/env bash
#
# scripts/02_install_wazuh_stack.sh
#
# Automated All-in-One installer for Wazuh Indexer + Wazuh Manager + Wazuh Dashboard
# on the Oracle Cloud Always Free Ampere A1 instance (VM.Standard.A1.Flex, 2 OCPUs / 12 GB RAM,
# Canonical Ubuntu 24.04 aarch64).
#
# Usage from local PC once wazuh-manager (VM.Standard.A1.Flex) is RUNNING:
#   bash scripts/02_install_wazuh_stack.sh --remote <wazuh-a1-public-ip>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"

if [[ "${1:-}" == "--remote" ]]; then
    REMOTE_IP="${2:-}"
    if [[ -z "$REMOTE_IP" ]]; then
        echo "ERROR: Usage: $0 --remote <wazuh-a1-public-ip>" >&2
        exit 1
    fi
    echo "=== Copying Wazuh All-in-One setup script and custom rules to ubuntu@${REMOTE_IP} ==="
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$0" \
        "${REPO_ROOT}/wazuh/rules/custom_oci_rules.xml" \
        "${REPO_ROOT}/wazuh/rules/custom_ssh_rules.xml" \
        "${REPO_ROOT}/wazuh/rules/custom_modsecurity_rules.xml" \
        "${REPO_ROOT}/wazuh/decoders/custom_modsecurity_decoders.xml" \
        "${REPO_ROOT}/wazuh/config/wazuh_ossec_oci.xml" \
        "ubuntu@${REMOTE_IP}:/tmp/"

    echo "=== Executing Wazuh Indexer + Manager + Dashboard installation on ${REMOTE_IP} ==="
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${REMOTE_IP}" \
        "sudo bash /tmp/02_install_wazuh_stack.sh --local"
    exit 0
fi

exec > >(tee -a /var/log/wazuh-soc-setup.log) 2>&1

echo "=================================================================="
echo "  WAZUH INDEXER + MANAGER + DASHBOARD SETUP (8GB+ RAM Host)"
echo "=================================================================="

MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
echo "Detected physical RAM: ${MEM_MB} MB"
if [[ "$MEM_MB" -lt 7000 ]]; then
    echo "ERROR: Expected at least an 8 GB RAM host, but detected only ${MEM_MB} MB RAM. Refusing to install on undersized host." >&2
    exit 1
fi

hostnamectl set-hostname wazuh-manager || true

echo "=== 1. Configuring Kernel Parameters & OCI Host Firewall (iptables) ==="
cat >/etc/sysctl.d/99-wazuh-indexer.conf <<'EOF'
vm.max_map_count=262144
EOF
sysctl --system >/dev/null 2>&1 || true

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl tar libcap2-bin iptables-persistent jq

for port in 443 1514 1515 55000; do
    if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
    fi
done
netfilter-persistent save || true

echo "=== 2. Downloading Official Wazuh All-in-One Installer (ARM64 / Ubuntu 24.04) ==="
cd /tmp
for ver in "4.14" "4.11" "4.9"; do
    if curl -fsSLO "https://packages.wazuh.com/${ver}/wazuh-install.sh"; then
        echo "Downloaded Wazuh installer version ${ver}"
        break
    fi
done
chmod +x /tmp/wazuh-install.sh

echo "=== 3. Installing Wazuh Indexer, Wazuh Server (Manager + Filebeat), and Wazuh Dashboard ==="
bash /tmp/wazuh-install.sh -a -i -o

HEAP_GB="3g"
if [[ "$MEM_MB" -ge 10000 ]]; then
    HEAP_GB="4g"
fi
echo "=== 4. Tuning Wazuh Indexer JVM Heap (-Xms${HEAP_GB} -Xmx${HEAP_GB}) ==="
if [[ -f /etc/wazuh-indexer/jvm.options ]]; then
    sed -i "s/^-Xms.*/-Xms${HEAP_GB}/" /etc/wazuh-indexer/jvm.options
    sed -i "s/^-Xmx.*/-Xmx${HEAP_GB}/" /etc/wazuh-indexer/jvm.options
    systemctl restart wazuh-indexer
fi

echo "=== 5. Deploying Custom OCI, SSH & ModSecurity WAF Decoders and Rules ==="
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

echo "=== 6. Verifying Wazuh Indexer, Manager & Dashboard Services ==="
systemctl is-active wazuh-indexer
systemctl is-active wazuh-manager
systemctl is-active wazuh-dashboard

if [[ -f /tmp/wazuh-install-files.tar ]]; then
    tar -axf /tmp/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > /root/wazuh-passwords.txt
    chmod 600 /root/wazuh-passwords.txt
    echo "Saved generated credentials to /root/wazuh-passwords.txt"
fi

echo "=================================================================="
echo "  WAZUH ALL-IN-ONE (INDEXER + MANAGER + DASHBOARD) SETUP COMPLETE"
echo "=================================================================="
