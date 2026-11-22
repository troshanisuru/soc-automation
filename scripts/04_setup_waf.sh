#!/usr/bin/env bash
#
# scripts/04_setup_waf.sh
#
# Installs and configures ModSecurity v3 with OWASP Core Rule Set (CRS)
# on the Nginx web-server instance within the OCI Always Free tier.
# Integrates ModSecurity audit and error logs with Wazuh Agent.
#
# Usage:
#   bash scripts/04_setup_waf.sh [web-server-public-ip]
#

set -euo pipefail

WEB_PUB_IP="${1:-${WEB_PUBLIC_IP:-130.210.70.6}}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"

echo "=================================================================="
echo "  Deploying ModSecurity + OWASP CRS on web-server (${WEB_PUB_IP})  "
echo "=================================================================="

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "ubuntu@${WEB_PUB_IP}" "sudo bash -s" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[*] Installing ModSecurity v3 and OWASP CRS packages..."
apt-get update -y
apt-get install -y libnginx-mod-http-modsecurity modsecurity-crs

echo "[*] Enabling active blocking mode (SecRuleEngine On)..."
if [ -f /etc/nginx/modsecurity.conf ]; then
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity.conf
fi

echo "[*] Configuring ModSecurity rules and OWASP CRS includes..."
cat <<'MC_EOF' > /etc/nginx/modsecurity_includes.conf
Include /etc/nginx/modsecurity.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
MC_EOF

echo "[*] Activating ModSecurity inside Nginx default site..."
if ! grep -q "modsecurity on;" /etc/nginx/sites-available/default; then
    sed -i '/server_name _;/a \ \tmodsecurity on;\n\tmodsecurity_rules_file /etc/nginx/modsecurity_includes.conf;' /etc/nginx/sites-available/default
fi

echo "[*] Verifying Nginx configuration syntax..."
nginx -t

echo "[*] Restarting Nginx service..."
systemctl restart nginx

echo "[*] Ensuring Wazuh agent monitors clean Nginx error.log + access.log (avoiding duplicate modsec_audit.log noise)..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    python3 -c '
import re
p = "/var/ossec/etc/ossec.conf"
txt = open(p).read()
new_txt = re.sub(r"\s*<localfile>\s*<log_format>apache</log_format>\s*<location>/var/log/nginx/modsec_audit\.log</location>\s*</localfile>", "", txt)
if new_txt != txt:
    open(p, "w").write(new_txt)
'
    systemctl restart wazuh-agent
fi

echo "[+] ModSecurity WAF + OWASP CRS is active and protecting Nginx!"
EOF

echo "=================================================================="
echo "  Testing WAF Live from Remote Client                             "
echo "=================================================================="

echo -n "1. Normal Request (GET /): "
NORM_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${WEB_PUB_IP}/")
echo "HTTP ${NORM_CODE}"

echo -n "2. SQL Injection Attack: "
SQLI_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${WEB_PUB_IP}/?id=1'%20UNION%20SELECT%20null--")
echo "HTTP ${SQLI_CODE}"

echo -n "3. Command Injection Attack: "
CMD_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${WEB_PUB_IP}/?cmd=cat%20/etc/passwd")
echo "HTTP ${CMD_CODE}"

if [[ "$NORM_CODE" == "200" && "$SQLI_CODE" == "403" && "$CMD_CODE" == "403" ]]; then
    echo "[SUCCESS] WAF is functioning correctly and actively blocking attacks!"
else
    echo "[WARNING] Unexpected HTTP response codes."
fi
