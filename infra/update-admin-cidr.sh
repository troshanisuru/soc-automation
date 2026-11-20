#!/usr/bin/env bash
#
# infra/update-admin-cidr.sh
#
# Rotate the admin /32 CIDR on existing soc-automation OCI Network Security Groups (NSGs).
# Adds the new /32 admin CIDR rules first, verifies them, and then removes the old /32 rules.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
EXPECTED_OCI_TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"

OLD_ADMIN_IP_CIDR="${OLD_ADMIN_IP_CIDR:-}"
NEW_ADMIN_IP_CIDR="${NEW_ADMIN_IP_CIDR:-}"

PROJECT="soc-automation"
WEB_NSG_NAME="${PROJECT}-prod-web-nsg"
MGMT_NSG_NAME="${PROJECT}-security-mgmt-nsg"

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

validate_cidr() {
    local name="$1"
    local value="$2"
    [[ -n "$value" ]] || fatal "${name} must be set."
    [[ "$value" != "0.0.0.0/0" ]] || fatal "${name} must not be 0.0.0.0/0."
    python3 -c "
import ipaddress, sys
name, val = sys.argv[1], sys.argv[2]
net = ipaddress.ip_network(val, strict=True)
if net.version != 4 or net.prefixlen != 32 or not net.network_address.is_global:
    raise SystemExit(f'{name} must be a public IPv4 /32 CIDR.')
" "$name" "$value"
}

find_nsg_by_name() {
    local name="$1"
    local list_json
    list_json=$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$name" --output json)
    printf '%s' "$list_json" | python3 -c "
import sys, json
for item in json.load(sys.stdin).get('data', []):
    if item.get('display-name') == sys.argv[1] and item.get('lifecycle-state') == 'AVAILABLE':
        print(item['id'])
        sys.exit(0)
" "$name"
}

add_cidr_rule_if_missing() {
    local nsg_id="$1"
    local cidr="$2"
    local port="$3"
    local desc="$4"
    local rules_json
    rules_json=$(oci_cmd network nsg rules list --nsg-id "$nsg_id" --all --output json)
    local exists
    exists=$(printf '%s' "$rules_json" | python3 -c "
import sys, json
cidr, port = sys.argv[1], int(sys.argv[2])
for r in json.load(sys.stdin).get('data', []):
    if r.get('direction') == 'INGRESS' and str(r.get('protocol')) == '6' and r.get('source') == cidr:
        rng = (r.get('tcp-options') or {}).get('destination-port-range') or {}
        if rng.get('min') == port and rng.get('max') == port:
            print('yes')
            sys.exit(0)
print('no')
" "$cidr" "$port")
    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS  ${desc}"
        return
    fi
    local rule_payload="[{\"direction\":\"INGRESS\",\"protocol\":\"6\",\"source\":\"${cidr}\",\"sourceType\":\"CIDR_BLOCK\",\"isStateless\":false,\"description\":\"${desc}\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":${port},\"max\":${port}}}}]"
    oci_cmd network nsg rules add --nsg-id "$nsg_id" --security-rules "$rule_payload" >/dev/null
    echo "ADDED   ${desc}"
}

remove_old_cidr_rules() {
    local nsg_id="$1"
    local old_cidr="$2"
    local label="$3"
    local rules_json
    rules_json=$(oci_cmd network nsg rules list --nsg-id "$nsg_id" --all --output json)
    local rule_ids_json
    rule_ids_json=$(printf '%s' "$rules_json" | python3 -c "
import sys, json
old_cidr = sys.argv[1]
ids = [
    r['id'] for r in json.load(sys.stdin).get('data', [])
    if r.get('direction') == 'INGRESS' and r.get('source') == old_cidr
]
print(json.dumps(ids))
" "$old_cidr")

    if [[ "$rule_ids_json" != "[]" ]]; then
        oci_cmd network nsg rules remove --nsg-id "$nsg_id" --security-rule-ids "$rule_ids_json" >/dev/null
        echo "REMOVED old admin CIDR (${old_cidr}) rules from ${label}: ${rule_ids_json}"
    else
        echo "ABSENT  old admin CIDR (${old_cidr}) on ${label}"
    fi
}

validate_cidr "OLD_ADMIN_IP_CIDR" "$OLD_ADMIN_IP_CIDR"
validate_cidr "NEW_ADMIN_IP_CIDR" "$NEW_ADMIN_IP_CIDR"
[[ "$OLD_ADMIN_IP_CIDR" != "$NEW_ADMIN_IP_CIDR" ]] || fatal "OLD_ADMIN_IP_CIDR and NEW_ADMIN_IP_CIDR must differ."
[[ -n "$EXPECTED_OCI_TENANCY_OCID" && -n "$OCI_COMPARTMENT_OCID" ]] || fatal "Set EXPECTED_OCI_TENANCY_OCID and OCI_COMPARTMENT_OCID."

WEB_NSG_ID=$(find_nsg_by_name "$WEB_NSG_NAME")
MGMT_NSG_ID=$(find_nsg_by_name "$MGMT_NSG_NAME")
[[ -n "$WEB_NSG_ID" && -n "$MGMT_NSG_ID" ]] || fatal "Could not resolve project NSGs."

echo "=== 1. Adding new admin CIDR (${NEW_ADMIN_IP_CIDR}) rules ==="
add_cidr_rule_if_missing "$WEB_NSG_ID" "$NEW_ADMIN_IP_CIDR" 22 "prod-web-nsg: SSH 22 from ${NEW_ADMIN_IP_CIDR}"
add_cidr_rule_if_missing "$MGMT_NSG_ID" "$NEW_ADMIN_IP_CIDR" 22 "security-mgmt-nsg: SSH 22 from ${NEW_ADMIN_IP_CIDR}"
add_cidr_rule_if_missing "$MGMT_NSG_ID" "$NEW_ADMIN_IP_CIDR" 443 "security-mgmt-nsg: Wazuh Dashboard 443 from ${NEW_ADMIN_IP_CIDR}"
add_cidr_rule_if_missing "$MGMT_NSG_ID" "$NEW_ADMIN_IP_CIDR" 55000 "security-mgmt-nsg: Wazuh API 55000 from ${NEW_ADMIN_IP_CIDR}"

echo "=== 2. Removing old admin CIDR (${OLD_ADMIN_IP_CIDR}) rules ==="
remove_old_cidr_rules "$WEB_NSG_ID" "$OLD_ADMIN_IP_CIDR" "$WEB_NSG_NAME"
remove_old_cidr_rules "$MGMT_NSG_ID" "$OLD_ADMIN_IP_CIDR" "$MGMT_NSG_NAME"

echo "OCI NSG Admin CIDR rotation complete."
