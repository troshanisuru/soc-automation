#!/usr/bin/env bash
#
# User-data for soc-automation-db (OCI Private Subnet Ubuntu instance).
# The private subnet has no NAT gateway, so this script intentionally avoids
# apt update, package downloads, PostgreSQL installation, and password creation.

set -euo pipefail

hostnamectl set-hostname soc-automation-db

install -d -m 0755 /opt/soc-automation
cat >/opt/soc-automation/role.env <<'EOF'
SOC_AUTOMATION_CLOUD=oci
SOC_AUTOMATION_ROLE=db
SOC_AUTOMATION_POSTGRESQL_INSTALL=deferred
SOC_AUTOMATION_NO_NAT=true
EOF

# Allow PostgreSQL port 5432 in local OCI Ubuntu iptables for when DB service is enabled
iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5432 -j ACCEPT || true

cat >/etc/motd <<'EOF'
SOC Automation DB Host (Oracle Cloud Infrastructure)
PostgreSQL installation is deferred because this private subnet has no NAT gateway.
Do not place database passwords or credentials in user-data.
EOF
