#!/usr/bin/env bash
#
# User-data for soc-automation-web (OCI Ubuntu instance).
# Installs Nginx, opens HTTP/HTTPS in OCI Ubuntu host iptables, and keeps
# SSH authentication logs available for Wazuh agent ingestion.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

hostnamectl set-hostname soc-automation-web

install -d -m 0755 /opt/soc-automation
cat >/opt/soc-automation/role.env <<'EOF'
SOC_AUTOMATION_CLOUD=oci
SOC_AUTOMATION_ROLE=web
SOC_AUTOMATION_LOG_SOURCE=/var/log/auth.log
EOF

apt-get update
apt-get install -y nginx iptables-persistent

# OCI Ubuntu images have a default REJECT rule in INPUT chain; allow 80 and 443 before REJECT
iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT || true
iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT || true
netfilter-persistent save || true

systemctl enable --now nginx

touch /var/log/auth.log
chmod 0640 /var/log/auth.log || true

cat >/etc/logrotate.d/soc-auth-log-preserve <<'EOF'
/var/log/auth.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF

cat >/var/www/html/index.nginx-debian.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SOC Automation Web Target (OCI)</title>
</head>
<body>
  <h1>SOC Automation Web Target (Oracle Cloud Infrastructure)</h1>
  <p>This host is the controlled web and SSH brute-force target for the academic SOC lab on OCI.</p>
</body>
</html>
EOF
