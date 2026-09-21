#!/usr/bin/env bash
#
# User-data for soc-automation-wazuh.
# Performs only safe base preparation. Wazuh installation is a later controlled task.

set -euo pipefail

hostnamectl set-hostname soc-automation-wazuh

install -d -m 0755 /opt/soc-automation
install -d -m 0755 /var/log/soc-automation

cat >/opt/soc-automation/role.env <<'EOF'
SOC_AUTOMATION_ROLE=wazuh
SOC_AUTOMATION_WAZUH_INSTALL=deferred
SOC_AUTOMATION_MIDDLEWARE_ROLE=enabled
EOF

cat >/etc/sysctl.d/99-soc-automation-wazuh-base.conf <<'EOF'
vm.max_map_count=262144
EOF

sysctl --system >/dev/null 2>&1 || true

cat >/etc/motd <<'EOF'
SOC Automation Wazuh/Middleware Host
Wazuh is not installed by this user-data script.
The attached IAM role is for the documented middleware architecture only.
Security Groups are allow-only; per-attacker-IP active response remains a separate TODO.
EOF
