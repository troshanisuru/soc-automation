#!/usr/bin/env bash
#
# User-data for soc-automation-wazuh (OCI Ampere A1.Flex Ubuntu instance).
# Performs safe base preparation and opens Wazuh ports in OCI Ubuntu host iptables.

set -euo pipefail

hostnamectl set-hostname soc-automation-wazuh

install -d -m 0755 /opt/soc-automation
install -d -m 0755 /var/log/soc-automation

cat >/opt/soc-automation/role.env <<'EOF'
SOC_AUTOMATION_CLOUD=oci
SOC_AUTOMATION_ROLE=wazuh
SOC_AUTOMATION_WAZUH_INSTALL=deferred
SOC_AUTOMATION_MIDDLEWARE_DYNAMIC_GROUP=enabled
EOF

cat >/etc/sysctl.d/99-soc-automation-wazuh-base.conf <<'EOF'
vm.max_map_count=262144
EOF

sysctl --system >/dev/null 2>&1 || true

# Open Wazuh Dashboard (443), Agent Events (1514), Enrollment (1515), and API (55000) in OCI host iptables
for port in 443 1514 1515 55000; do
    iptables -I INPUT 6 -m state --state NEW -p tcp --dport "$port" -j ACCEPT || true
done

cat >/etc/motd <<'EOF'
SOC Automation Wazuh/Middleware Host (Oracle Cloud Infrastructure - Ampere A1.Flex)
Wazuh is not installed by this user-data script.
This instance authenticates to OCI APIs via Dynamic Group Instance Principals for active response.
EOF
