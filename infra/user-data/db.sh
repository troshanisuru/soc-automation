#!/usr/bin/env bash
#
# User-data for soc-automation-db.
# The private subnet has no NAT gateway, so this script intentionally avoids
# apt update, package downloads, PostgreSQL installation, and password creation.

set -euo pipefail

hostnamectl set-hostname soc-automation-db

install -d -m 0755 /opt/soc-automation
cat >/opt/soc-automation/role.env <<'EOF'
SOC_AUTOMATION_ROLE=db
SOC_AUTOMATION_POSTGRESQL_INSTALL=deferred
SOC_AUTOMATION_NO_NAT=true
EOF

cat >/etc/motd <<'EOF'
SOC Automation DB Host
PostgreSQL installation is deferred because this private subnet has no NAT gateway.
Do not place database passwords or credentials in user-data.
EOF
