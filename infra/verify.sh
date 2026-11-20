#!/usr/bin/env bash
#
# infra/verify.sh
#
# Read-only verification for the Oracle Cloud Infrastructure (OCI) Dual-VCN,
# Local Peering Gateway (LPG), Network Security Group (NSG), Dynamic Group,
# and Compute topology.
#
# Usage:
#   ADMIN_IP_CIDR="203.0.113.10/32" \
#   EXPECTED_OCI_TENANCY_OCID="ocid1.tenancy.oc1..xxx" \
#   OCI_COMPARTMENT_OCID="ocid1.compartment.oc1..xxx" \
#   ./infra/verify.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
EXPECTED_OCI_TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
ADMIN_IP_CIDR="${ADMIN_IP_CIDR:-}"

PROJECT="soc-automation"

PROD_VCN_NAME="${PROJECT}-prod-vcn"
SECURITY_VCN_NAME="${PROJECT}-security-vcn"
PROD_PUB_SUBNET_NAME="${PROJECT}-prod-public"
PROD_PRIV_SUBNET_NAME="${PROJECT}-prod-private"
SECURITY_MGMT_SUBNET_NAME="${PROJECT}-security-mgmt"
PROD_IGW_NAME="${PROJECT}-prod-igw"
SECURITY_IGW_NAME="${PROJECT}-security-igw"
PROD_LPG_NAME="${PROJECT}-prod-lpg"
SECURITY_LPG_NAME="${PROJECT}-security-lpg"
WEB_NSG_NAME="${PROJECT}-prod-web-nsg"
DB_NSG_NAME="${PROJECT}-prod-db-nsg"
MGMT_NSG_NAME="${PROJECT}-security-mgmt-nsg"
QUARANTINE_NSG_NAME="${PROJECT}-quarantine-nsg"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS  $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  FAIL  $1"
    echo "        $2"
}

warn() {
    WARN_COUNT=$((WARN_COUNT + 1))
    echo "  WARN  $1"
}

section() {
    echo ""
    echo "==========================================="
    echo "  $1"
    echo "==========================================="
}

find_resource_by_name() {
    local json_input="$1"
    local display_name="$2"
    printf '%s' "$json_input" | python3 -c "
import sys, json
target = sys.argv[1]
doc = json.load(sys.stdin)
for item in doc.get('data', []):
    if (item.get('display-name') == target or item.get('name') == target) and item.get('lifecycle-state') not in ('TERMINATED', 'TERMINATING', 'DELETED'):
        print(item['id'])
        sys.exit(0)
" "$display_name"
}

section "1. OCI Identity and Compartment Guard"
if [[ -z "$EXPECTED_OCI_TENANCY_OCID" || -z "$OCI_COMPARTMENT_OCID" ]]; then
    echo "FATAL: Set EXPECTED_OCI_TENANCY_OCID and OCI_COMPARTMENT_OCID before running verify.sh" >&2
    exit 1
fi

TENANCY_ID=$(oci_cmd iam tenancy get --tenancy-id "$EXPECTED_OCI_TENANCY_OCID" --query "data.id" --raw-output)
if [[ "$TENANCY_ID" == "$EXPECTED_OCI_TENANCY_OCID" ]]; then
    pass "Tenancy guard matches EXPECTED_OCI_TENANCY_OCID ($TENANCY_ID)"
else
    fail "Tenancy OCID mismatch" "Expected $EXPECTED_OCI_TENANCY_OCID, got $TENANCY_ID"
fi

section "2. Virtual Cloud Networks (VCNs)"
VCN_LIST=$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --output json)
PROD_VCN_ID=$(find_resource_by_name "$VCN_LIST" "$PROD_VCN_NAME")
SECURITY_VCN_ID=$(find_resource_by_name "$VCN_LIST" "$SECURITY_VCN_NAME")

[[ -n "$PROD_VCN_ID" ]] && pass "Production VCN exists: $PROD_VCN_ID" || fail "Production VCN missing" "$PROD_VCN_NAME"
[[ -n "$SECURITY_VCN_ID" ]] && pass "Security VCN exists: $SECURITY_VCN_ID" || fail "Security VCN missing" "$SECURITY_VCN_NAME"

section "3. Regional Subnets"
SUBNET_LIST=$(oci_cmd network subnet list --compartment-id "$OCI_COMPARTMENT_OCID" --output json)
for sname in "$PROD_PUB_SUBNET_NAME" "$PROD_PRIV_SUBNET_NAME" "$SECURITY_MGMT_SUBNET_NAME"; do
    sid=$(find_resource_by_name "$SUBNET_LIST" "$sname")
    [[ -n "$sid" ]] && pass "Subnet ${sname} exists: ${sid}" || fail "Subnet ${sname} missing" "Run infra/provision.sh"
done

section "4. Internet Gateways & Local Peering Gateways (LPGs)"
if [[ -n "$PROD_VCN_ID" && -n "$SECURITY_VCN_ID" ]]; then
    PROD_IGW_ID=$(find_resource_by_name "$(oci_cmd network internet-gateway list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$PROD_VCN_ID" --output json)" "$PROD_IGW_NAME")
    SEC_IGW_ID=$(find_resource_by_name "$(oci_cmd network internet-gateway list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$SECURITY_VCN_ID" --output json)" "$SECURITY_IGW_NAME")
    [[ -n "$PROD_IGW_ID" ]] && pass "Production IGW exists: $PROD_IGW_ID" || fail "Production IGW missing" "$PROD_IGW_NAME"
    [[ -n "$SEC_IGW_ID" ]] && pass "Security IGW exists: $SEC_IGW_ID" || fail "Security IGW missing" "$SECURITY_IGW_NAME"

    PROD_LPG_ID=$(find_resource_by_name "$(oci_cmd network local-peering-gateway list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$PROD_VCN_ID" --output json)" "$PROD_LPG_NAME")
    if [[ -n "$PROD_LPG_ID" ]]; then
        LPG_STATUS=$(oci_cmd network local-peering-gateway get --local-peering-gateway-id "$PROD_LPG_ID" --query "data.\"peering-status\"" --raw-output)
        [[ "$LPG_STATUS" == "PEERED" ]] && pass "Local Peering Gateway ($PROD_LPG_ID) is PEERED" || fail "LPG not peered" "Status: $LPG_STATUS"
    else
        fail "Local Peering Gateway missing" "$PROD_LPG_NAME"
    fi
fi

section "5. Network Security Groups (NSGs)"
NSG_LIST=$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --output json)
for nname in "$WEB_NSG_NAME" "$DB_NSG_NAME" "$MGMT_NSG_NAME" "$QUARANTINE_NSG_NAME"; do
    nid=$(find_resource_by_name "$NSG_LIST" "$nname")
    [[ -n "$nid" ]] && pass "NSG ${nname} exists: ${nid}" || fail "NSG ${nname} missing" "Run infra/security.sh"
done

section "6. Compute Instances (Always Free Tier)"
INST_LIST=$(oci_cmd compute instance list --compartment-id "$OCI_COMPARTMENT_OCID" --output json)
for iname in "${PROJECT}-web" "${PROJECT}-db" "${PROJECT}-wazuh"; do
    iid=$(find_resource_by_name "$INST_LIST" "$iname")
    if [[ -n "$iid" ]]; then
        pass "Compute instance ${iname} exists: ${iid}"
    else
        warn "Compute instance ${iname} not provisioned yet (run infra/instances.sh when ready)"
    fi
done

echo ""
echo "==========================================="
echo "  OCI Verification Summary: ${PASS_COUNT} PASS, ${WARN_COUNT} WARN, ${FAIL_COUNT} FAIL"
echo "==========================================="
[[ "$FAIL_COUNT" -eq 0 ]]
