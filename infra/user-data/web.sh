#!/usr/bin/env bash
#
# User-data for soc-automation-web.
# Installs Nginx and keeps SSH authentication logs available for Wazuh ingestion.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

hostnamectl set-hostname soc-automation-web

install -d -m 0755 /opt/soc-automation
cat >/opt/soc-automation/role.env <<'EOF'
SOC_AUTOMATION_ROLE=web
SOC_AUTOMATION_LOG_SOURCE=/var/log/auth.log
EOF

apt-get update
apt-get install -y nginx
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
  <title>SOC Automation Web Target</title>
</head>
<body>
  <h1>SOC Automation Web Target</h1>
  <p>This host is the controlled web and SSH brute-force target for the academic SOC lab.</p>
</body>
</html>
EOF
