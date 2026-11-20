#!/usr/bin/env bash
#
# infra/security.sh
#
# Idempotent Oracle Cloud Infrastructure (OCI) security provisioning script:
#   1. Four Network Security Groups (NSGs):
#      - soc-automation-prod-web-nsg
#      - soc-automation-prod-db-nsg
#      - soc-automation-security-mgmt-nsg
#      - soc-automation-quarantine-nsg
#   2. OCI Dynamic Group: soc-automation-middleware-dg (for Instance Principals)
#   3. OCI IAM Policy: soc-automation-middleware-policy (compartment-scoped least privilege)
#
# Must be run AFTER infra/provision.sh.
#
# Usage:
#   ADMIN_IP_CIDR="203.0.113.10/32" \
#   EXPECTED_OCI_TENANCY_OCID="ocid1.tenancy.oc1..xxx" \
#   OCI_COMPARTMENT_OCID="ocid1.compartment.oc1..xxx" \
#   ./infra/security.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
EXPECTED_OCI_TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
ADMIN_IP_CIDR="${ADMIN_IP_CIDR:-}"

PROJECT="soc-automation"
FREEFORM_TAGS="{\"Project\":\"${PROJECT}\",\"Environment\":\"lab\"}"

PROD_VCN_CIDR="10.0.0.0/16"
SECURITY_MGMT_CIDR="172.16.1.0/24"

PROD_VCN_NAME="${PROJECT}-prod-vcn"
SECURITY_VCN_NAME="${PROJECT}-security-vcn"

WEB_NSG_NAME="${PROJECT}-prod-web-nsg"
DB_NSG_NAME="${PROJECT}-prod-db-nsg"
MGMT_NSG_NAME="${PROJECT}-security-mgmt-nsg"
QUARANTINE_NSG_NAME="${PROJECT}-quarantine-nsg"

DYNAMIC_GROUP_NAME="${PROJECT}-middleware-dg"
IAM_POLICY_NAME="${PROJECT}-middleware-policy"

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

require_admin_cidr() {
    if [[ -z "$ADMIN_IP_CIDR" ]]; then
        fatal "Set ADMIN_IP_CIDR to your admin IP range, e.g. 203.0.113.10/32."
    fi
    if [[ "$ADMIN_IP_CIDR" == "0.0.0.0/0" ]]; then
        fatal "ADMIN_IP_CIDR must not be 0.0.0.0/0."
    fi

    local cidr_ok
    cidr_ok=$(python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    print('yes' if net.version == 4 else 'no')
except ValueError:
    print('no')
" "$ADMIN_IP_CIDR")

    if [[ "$cidr_ok" != "yes" ]]; then
        fatal "ADMIN_IP_CIDR must be a valid IPv4 CIDR, got '${ADMIN_IP_CIDR}'."
    fi
}

require_oci_context() {
    echo "=== Pre-flight: verifying OCI identity and compartment guard ==="
    command -v oci >/dev/null 2>&1 || fatal "OCI CLI ('oci') is not installed."
    [[ -n "$EXPECTED_OCI_TENANCY_OCID" ]] || fatal "Set EXPECTED_OCI_TENANCY_OCID."
    [[ -n "$OCI_COMPARTMENT_OCID" ]] || fatal "Set OCI_COMPARTMENT_OCID."

    local tenancy_id
    tenancy_id=$(oci_cmd iam tenancy get --tenancy-id "$EXPECTED_OCI_TENANCY_OCID" --query "data.id" --raw-output)
    [[ "$tenancy_id" == "$EXPECTED_OCI_TENANCY_OCID" ]] || fatal "Tenancy OCID mismatch."
    echo "Tenancy OCID:     $tenancy_id"
    echo "Compartment OCID: $OCI_COMPARTMENT_OCID"
    echo "Admin CIDR:       $ADMIN_IP_CIDR"
    echo ""
}

find_resource_by_name() {
    local json_input="$1"
    local display_name="$2"
    printf '%s' "$json_input" | python3 -c "
import sys, json
target = sys.argv[1]
doc = json.load(sys.stdin)
items = doc.get('data', [])
matches = [
    item['id'] for item in items
    if (item.get('display-name') == target or item.get('name') == target)
    and item.get('lifecycle-state') not in ('TERMINATED', 'TERMINATING', 'DELETED')
]
if len(matches) > 1:
    print('ERROR: Multiple resources match ' + target, file=sys.stderr)
    sys.exit(2)
if matches:
    print(matches[0])
" "$display_name"
}

ensure_nsg() {
    local name="$1"
    local vcn_id="$2"
    local result_var="$3"
    local list_json
    local nsg_id

    list_json=$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$vcn_id" --display-name "$name" --output json 2>/dev/null || echo '{"data":[]}')
    nsg_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -z "$nsg_id" ]]; then
        nsg_id=$(oci_cmd network nsg create \
            --compartment-id "$OCI_COMPARTMENT_OCID" \
            --vcn-id "$vcn_id" \
            --display-name "$name" \
            --freeform-tags "$FREEFORM_TAGS" \
            --wait-for-state AVAILABLE \
            --query "data.id" \
            --raw-output)
        echo "CREATED  NSG ${name}: ${nsg_id}"
    else
        echo "EXISTS   NSG ${name}: ${nsg_id}"
    fi

    printf -v "$result_var" '%s' "$nsg_id"
}

ensure_nsg_tcp_ingress() {
    local nsg_id="$1"
    local source="$2"
    local source_type="$3"
    local port="$4"
    local description="$5"
    local existing_rules
    local exists

    existing_rules=$(oci_cmd network nsg rules list --nsg-id "$nsg_id" --all --output json 2>/dev/null || echo '{"data":[]}')
    exists=$(printf '%s' "$existing_rules" | python3 -c "
import sys, json
source, source_type, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
doc = json.load(sys.stdin)
for rule in doc.get('data', []):
    if rule.get('direction') != 'INGRESS' or str(rule.get('protocol')) != '6':
        continue
    if rule.get('source') != source or rule.get('source-type') != source_type:
        continue
    tcp_opts = (rule.get('tcp-options') or {}).get('destination-port-range') or {}
    if tcp_opts.get('min') == port and tcp_opts.get('max') == port:
        print('yes')
        sys.exit(0)
print('no')
" "$source" "$source_type" "$port")

    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS   rule ${description}"
        return
    fi

    local rule_json
    rule_json="[{\"direction\":\"INGRESS\",\"protocol\":\"6\",\"source\":\"${source}\",\"sourceType\":\"${source_type}\",\"isStateless\":false,\"description\":\"${description}\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":${port},\"max\":${port}}}}]"
    oci_cmd network nsg rules add --nsg-id "$nsg_id" --security-rules "$rule_json" >/dev/null
    echo "CREATED  rule ${description}"
}

ensure_nsg_all_egress() {
    local nsg_id="$1"
    local description="$2"
    local existing_rules
    local exists

    existing_rules=$(oci_cmd network nsg rules list --nsg-id "$nsg_id" --all --output json 2>/dev/null || echo '{"data":[]}')
    exists=$(printf '%s' "$existing_rules" | python3 -c "
import sys, json
doc = json.load(sys.stdin)
for rule in doc.get('data', []):
    if rule.get('direction') == 'EGRESS' and rule.get('destination') == '0.0.0.0/0' and rule.get('protocol') == 'all':
        print('yes')
        sys.exit(0)
print('no')
")

    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS   egress ${description}"
        return
    fi

    local rule_json
    rule_json="[{\"direction\":\"EGRESS\",\"protocol\":\"all\",\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"isStateless\":false,\"description\":\"${description}\"}]"
    oci_cmd network nsg rules add --nsg-id "$nsg_id" --security-rules "$rule_json" >/dev/null
    echo "CREATED  egress ${description}"
}

require_admin_cidr
require_oci_context

PROD_VCN_LIST=$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$PROD_VCN_NAME" --output json)
PROD_VCN_ID=$(find_resource_by_name "$PROD_VCN_LIST" "$PROD_VCN_NAME")
[[ -n "$PROD_VCN_ID" ]] || fatal "Production VCN ${PROD_VCN_NAME} not found. Run infra/provision.sh first."

SEC_VCN_LIST=$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$SECURITY_VCN_NAME" --output json)
SECURITY_VCN_ID=$(find_resource_by_name "$SEC_VCN_LIST" "$SECURITY_VCN_NAME")
[[ -n "$SECURITY_VCN_ID" ]] || fatal "Security VCN ${SECURITY_VCN_NAME} not found. Run infra/provision.sh first."

echo "=== 1. Creating OCI Network Security Groups (NSGs) ==="
ensure_nsg "$WEB_NSG_NAME" "$PROD_VCN_ID" WEB_NSG_ID
ensure_nsg_tcp_ingress "$WEB_NSG_ID" "$ADMIN_IP_CIDR" "CIDR_BLOCK" 22 "prod-web-nsg: SSH 22 from admin CIDR"
ensure_nsg_tcp_ingress "$WEB_NSG_ID" "0.0.0.0/0" "CIDR_BLOCK" 80 "prod-web-nsg: HTTP 80 from internet"
ensure_nsg_tcp_ingress "$WEB_NSG_ID" "0.0.0.0/0" "CIDR_BLOCK" 443 "prod-web-nsg: HTTPS 443 from internet"
ensure_nsg_all_egress "$WEB_NSG_ID" "prod-web-nsg: Allow all outbound"
echo ""

ensure_nsg "$MGMT_NSG_NAME" "$SECURITY_VCN_ID" MGMT_NSG_ID
ensure_nsg_tcp_ingress "$MGMT_NSG_ID" "$ADMIN_IP_CIDR" "CIDR_BLOCK" 22 "security-mgmt-nsg: SSH 22 from admin CIDR"
ensure_nsg_tcp_ingress "$MGMT_NSG_ID" "$ADMIN_IP_CIDR" "CIDR_BLOCK" 443 "security-mgmt-nsg: Wazuh Dashboard 443 from admin CIDR"
ensure_nsg_tcp_ingress "$MGMT_NSG_ID" "$PROD_VCN_CIDR" "CIDR_BLOCK" 1514 "security-mgmt-nsg: Wazuh agent 1514 from Production VCN"
ensure_nsg_tcp_ingress "$MGMT_NSG_ID" "$PROD_VCN_CIDR" "CIDR_BLOCK" 1515 "security-mgmt-nsg: Wazuh enrollment 1515 from Production VCN"
ensure_nsg_tcp_ingress "$MGMT_NSG_ID" "$ADMIN_IP_CIDR" "CIDR_BLOCK" 55000 "security-mgmt-nsg: Wazuh API 55000 from admin CIDR"
ensure_nsg_tcp_ingress "$MGMT_NSG_ID" "$SECURITY_MGMT_CIDR" "CIDR_BLOCK" 55000 "security-mgmt-nsg: Wazuh API 55000 from security subnet"
ensure_nsg_all_egress "$MGMT_NSG_ID" "security-mgmt-nsg: Allow all outbound"
echo ""

ensure_nsg "$DB_NSG_NAME" "$PROD_VCN_ID" DB_NSG_ID
ensure_nsg_tcp_ingress "$DB_NSG_ID" "$WEB_NSG_ID" "NETWORK_SECURITY_GROUP" 5432 "prod-db-nsg: PostgreSQL 5432 from prod-web-nsg"
ensure_nsg_tcp_ingress "$DB_NSG_ID" "$SECURITY_MGMT_CIDR" "CIDR_BLOCK" 22 "prod-db-nsg: SSH 22 from security-mgmt subnet via LPG"
ensure_nsg_all_egress "$DB_NSG_ID" "prod-db-nsg: Allow all outbound"
echo ""

ensure_nsg "$QUARANTINE_NSG_NAME" "$PROD_VCN_ID" QUARANTINE_NSG_ID
ensure_nsg_tcp_ingress "$QUARANTINE_NSG_ID" "$SECURITY_MGMT_CIDR" "CIDR_BLOCK" 22 "quarantine-nsg: SSH 22 from security-mgmt subnet only"
ensure_nsg_tcp_ingress "$QUARANTINE_NSG_ID" "$SECURITY_MGMT_CIDR" "CIDR_BLOCK" 1514 "quarantine-nsg: Wazuh telemetry 1514 to security-mgmt only"
echo ""

echo "=== 2. Creating OCI Dynamic Group & Least-Privilege IAM Policy ==="
MATCHING_RULE="ANY { instance.compartment.id = '${OCI_COMPARTMENT_OCID}' }"
DG_LIST=$(oci_cmd iam dynamic-group list --compartment-id "$EXPECTED_OCI_TENANCY_OCID" --name "$DYNAMIC_GROUP_NAME" --output json 2>/dev/null || echo '{"data":[]}')
DG_ID=$(find_resource_by_name "$DG_LIST" "$DYNAMIC_GROUP_NAME")

if [[ -z "$DG_ID" ]]; then
    DG_ID=$(oci_cmd iam dynamic-group create \
        --compartment-id "$EXPECTED_OCI_TENANCY_OCID" \
        --name "$DYNAMIC_GROUP_NAME" \
        --description "Dynamic group for SOC automation Wazuh and AI middleware instance principals" \
        --matching-rule "$MATCHING_RULE" \
        --query "data.id" \
        --raw-output)
    echo "CREATED  Dynamic Group ${DYNAMIC_GROUP_NAME}: ${DG_ID}"
else
    echo "EXISTS   Dynamic Group ${DYNAMIC_GROUP_NAME}: ${DG_ID}"
fi

POLICY_STATEMENTS="[\"Allow dynamic-group ${DYNAMIC_GROUP_NAME} to use virtual-network-family in compartment id ${OCI_COMPARTMENT_OCID}\",\"Allow dynamic-group ${DYNAMIC_GROUP_NAME} to manage waf-family in compartment id ${OCI_COMPARTMENT_OCID}\",\"Allow dynamic-group ${DYNAMIC_GROUP_NAME} to read object-family in compartment id ${OCI_COMPARTMENT_OCID}\"]"
POL_LIST=$(oci_cmd iam policy list --compartment-id "$OCI_COMPARTMENT_OCID" --name "$IAM_POLICY_NAME" --output json 2>/dev/null || echo '{"data":[]}')
POL_ID=$(find_resource_by_name "$POL_LIST" "$IAM_POLICY_NAME")

if [[ -z "$POL_ID" ]]; then
    POL_ID=$(oci_cmd iam policy create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --name "$IAM_POLICY_NAME" \
        --description "Least-privilege OCI policy for SOC middleware active response" \
        --statements "$POLICY_STATEMENTS" \
        --query "data.id" \
        --raw-output)
    echo "CREATED  IAM Policy ${IAM_POLICY_NAME}: ${POL_ID}"
else
    echo "EXISTS   IAM Policy ${IAM_POLICY_NAME}: ${POL_ID}"
fi

echo ""
echo "================================================="
echo "  OCI Security & IAM Provisioning Complete"
echo "================================================="
echo "  prod-web-nsg:         $WEB_NSG_ID"
echo "  prod-db-nsg:          $DB_NSG_ID"
echo "  security-mgmt-nsg:    $MGMT_NSG_ID"
echo "  quarantine-nsg:       $QUARANTINE_NSG_ID"
echo "  Dynamic Group:        $DYNAMIC_GROUP_NAME ($DG_ID)"
echo "  IAM Policy:           $IAM_POLICY_NAME ($POL_ID)"
echo "================================================="
