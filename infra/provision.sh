#!/usr/bin/env bash
#
# infra/provision.sh
#
# Idempotent Oracle Cloud Infrastructure (OCI) provisioning script for the
# Dual-VCN network topology.
# Creates:
#   1. Two VCNs: soc-automation-prod-vcn (10.0.0.0/16) & soc-automation-security-vcn (172.16.0.0/16)
#   2. Two Internet Gateways: prod-igw & security-igw
#   3. Two Local Peering Gateways (LPGs) and establishes active cross-VCN peering
#   4. Three Route Tables with Internet Gateway & LPG peering routes
#   5. Three Regional Subnets: prod-public (10.0.1.0/24), prod-private (10.0.2.0/24), security-mgmt (172.16.1.0/24)
#
# Usage:
#   chmod +x infra/provision.sh
#   OCI_CLI_PROFILE=soc-project \
#   OCI_REGION=ap-singapore-1 \
#   EXPECTED_OCI_TENANCY_OCID="ocid1.tenancy.oc1..xxx" \
#   OCI_COMPARTMENT_OCID="ocid1.compartment.oc1..xxx" \
#   ./infra/provision.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
EXPECTED_OCI_TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"

PROJECT="soc-automation"
FREEFORM_TAGS="{\"Project\":\"${PROJECT}\",\"Environment\":\"lab\"}"

PROD_VCN_CIDR="10.0.0.0/16"
PROD_PUBLIC_CIDR="10.0.1.0/24"
PROD_PRIVATE_CIDR="10.0.2.0/24"

SECURITY_VCN_CIDR="172.16.0.0/16"
SECURITY_MGMT_CIDR="172.16.1.0/24"

PROD_VCN_NAME="${PROJECT}-prod-vcn"
SECURITY_VCN_NAME="${PROJECT}-security-vcn"

PROD_IGW_NAME="${PROJECT}-prod-igw"
SECURITY_IGW_NAME="${PROJECT}-security-igw"

PROD_LPG_NAME="${PROJECT}-prod-lpg"
SECURITY_LPG_NAME="${PROJECT}-security-lpg"

PROD_PUB_RT_NAME="${PROJECT}-prod-public-rt"
PROD_PRIV_RT_NAME="${PROJECT}-prod-private-rt"
SECURITY_MGMT_RT_NAME="${PROJECT}-security-mgmt-rt"

PROD_PUB_SUBNET_NAME="${PROJECT}-prod-public"
PROD_PRIV_SUBNET_NAME="${PROJECT}-prod-private"
SECURITY_MGMT_SUBNET_NAME="${PROJECT}-security-mgmt"

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

require_oci_context() {
    echo "=== Pre-flight: verifying OCI identity and compartment guard ==="

    command -v oci >/dev/null 2>&1 || fatal "OCI CLI ('oci') is not installed. Run 'bash infra/bind-local-pc.sh' first."
    [[ -n "$EXPECTED_OCI_TENANCY_OCID" ]] || fatal "Set EXPECTED_OCI_TENANCY_OCID before running provision.sh."
    [[ -n "$OCI_COMPARTMENT_OCID" ]] || fatal "Set OCI_COMPARTMENT_OCID before running provision.sh."

    local tenancy_json
    tenancy_json=$(oci_cmd iam tenancy get --tenancy-id "$EXPECTED_OCI_TENANCY_OCID" --output json)
    local tenancy_id
    local tenancy_name
    tenancy_id=$(printf '%s' "$tenancy_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")
    tenancy_name=$(printf '%s' "$tenancy_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['name'])")

    if [[ "$tenancy_id" != "$EXPECTED_OCI_TENANCY_OCID" ]]; then
        fatal "Authenticated tenancy ${tenancy_id} does not match EXPECTED_OCI_TENANCY_OCID ${EXPECTED_OCI_TENANCY_OCID}."
    fi

    echo "Tenancy Name:     $tenancy_name"
    echo "Tenancy OCID:     $tenancy_id"
    echo "Compartment OCID: $OCI_COMPARTMENT_OCID"
    echo "Profile:          $OCI_CLI_PROFILE"
    echo "Region:           $OCI_REGION"
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
    if item.get('display-name') == target
    and item.get('lifecycle-state') not in ('TERMINATED', 'TERMINATING')
]
if len(matches) > 1:
    print('ERROR: Multiple resources match ' + target, file=sys.stderr)
    sys.exit(2)
if matches:
    print(matches[0])
" "$display_name"
}

ensure_vcn() {
    local name="$1"
    local cidr="$2"
    local dns_label="$3"
    local result_var="$4"
    local list_json
    local vcn_id

    list_json=$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$name" --output json 2>/dev/null || echo '{"data":[]}')
    vcn_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -z "$vcn_id" ]]; then
        vcn_id=$(oci_cmd network vcn create \
            --compartment-id "$OCI_COMPARTMENT_OCID" \
            --display-name "$name" \
            --cidr-blocks "[\"${cidr}\"]" \
            --dns-label "$dns_label" \
            --freeform-tags "$FREEFORM_TAGS" \
            --wait-for-state AVAILABLE \
            --query "data.id" \
            --raw-output)
        echo "CREATED  VCN ${name}: ${vcn_id} (${cidr})"
    else
        echo "EXISTS   VCN ${name}: ${vcn_id} (${cidr})"
    fi

    printf -v "$result_var" '%s' "$vcn_id"
}

ensure_igw() {
    local name="$1"
    local vcn_id="$2"
    local result_var="$3"
    local list_json
    local igw_id

    list_json=$(oci_cmd network internet-gateway list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$vcn_id" --display-name "$name" --output json 2>/dev/null || echo '{"data":[]}')
    igw_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -z "$igw_id" ]]; then
        igw_id=$(oci_cmd network internet-gateway create \
            --compartment-id "$OCI_COMPARTMENT_OCID" \
            --vcn-id "$vcn_id" \
            --display-name "$name" \
            --is-enabled true \
            --freeform-tags "$FREEFORM_TAGS" \
            --wait-for-state AVAILABLE \
            --query "data.id" \
            --raw-output)
        echo "CREATED  IGW ${name}: ${igw_id}"
    else
        echo "EXISTS   IGW ${name}: ${igw_id}"
    fi

    printf -v "$result_var" '%s' "$igw_id"
}

ensure_lpg() {
    local name="$1"
    local vcn_id="$2"
    local result_var="$3"
    local list_json
    local lpg_id

    list_json=$(oci_cmd network local-peering-gateway list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$vcn_id" --output json 2>/dev/null || echo '{"data":[]}')
    lpg_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -z "$lpg_id" ]]; then
        lpg_id=$(oci_cmd network local-peering-gateway create \
            --compartment-id "$OCI_COMPARTMENT_OCID" \
            --vcn-id "$vcn_id" \
            --display-name "$name" \
            --freeform-tags "$FREEFORM_TAGS" \
            --wait-for-state AVAILABLE \
            --query "data.id" \
            --raw-output)
        echo "CREATED  LPG ${name}: ${lpg_id}"
    else
        echo "EXISTS   LPG ${name}: ${lpg_id}"
    fi

    printf -v "$result_var" '%s' "$lpg_id"
}

ensure_lpg_peering() {
    local prod_lpg_id="$1"
    local sec_lpg_id="$2"
    local peering_status

    peering_status=$(oci_cmd network local-peering-gateway get --local-peering-gateway-id "$prod_lpg_id" --query "data.\"peering-status\"" --raw-output)

    if [[ "$peering_status" == "PEERED" ]]; then
        echo "EXISTS   LPG Peering is active (PEERED): ${prod_lpg_id} <-> ${sec_lpg_id}"
    else
        oci_cmd network local-peering-gateway connect \
            --local-peering-gateway-id "$prod_lpg_id" \
            --peer-id "$sec_lpg_id" >/dev/null
        echo "CONNECTED LPG Peering: ${prod_lpg_id} <-> ${sec_lpg_id}"
    fi
}

ensure_route_table() {
    local name="$1"
    local vcn_id="$2"
    local route_rules_json="$3"
    local result_var="$4"
    local list_json
    local rtb_id

    list_json=$(oci_cmd network route-table list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$vcn_id" --display-name "$name" --output json 2>/dev/null || echo '{"data":[]}')
    rtb_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -z "$rtb_id" ]]; then
        rtb_id=$(oci_cmd network route-table create \
            --compartment-id "$OCI_COMPARTMENT_OCID" \
            --vcn-id "$vcn_id" \
            --display-name "$name" \
            --route-rules "$route_rules_json" \
            --freeform-tags "$FREEFORM_TAGS" \
            --wait-for-state AVAILABLE \
            --query "data.id" \
            --raw-output)
        echo "CREATED  Route Table ${name}: ${rtb_id}"
    else
        oci_cmd network route-table update \
            --rt-id "$rtb_id" \
            --route-rules "$route_rules_json" \
            --force >/dev/null
        echo "EXISTS   Route Table ${name}: ${rtb_id} (routes verified)"
    fi

    printf -v "$result_var" '%s' "$rtb_id"
}

ensure_subnet() {
    local name="$1"
    local vcn_id="$2"
    local cidr="$3"
    local dns_label="$4"
    local rtb_id="$5"
    local prohibit_public_ip="$6"
    local result_var="$7"
    local list_json
    local subnet_id

    list_json=$(oci_cmd network subnet list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$vcn_id" --display-name "$name" --output json 2>/dev/null || echo '{"data":[]}')
    subnet_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -z "$subnet_id" ]]; then
        subnet_id=$(oci_cmd network subnet create \
            --compartment-id "$OCI_COMPARTMENT_OCID" \
            --vcn-id "$vcn_id" \
            --display-name "$name" \
            --cidr-block "$cidr" \
            --dns-label "$dns_label" \
            --route-table-id "$rtb_id" \
            --prohibit-public-ip-on-vnic "$prohibit_public_ip" \
            --freeform-tags "$FREEFORM_TAGS" \
            --wait-for-state AVAILABLE \
            --query "data.id" \
            --raw-output)
        echo "CREATED  Subnet ${name}: ${subnet_id} (${cidr})"
    else
        oci_cmd network subnet update \
            --subnet-id "$subnet_id" \
            --route-table-id "$rtb_id" >/dev/null
        echo "EXISTS   Subnet ${name}: ${subnet_id} (${cidr})"
    fi

    printf -v "$result_var" '%s' "$subnet_id"
}

require_oci_context

echo "=== 1. Creating OCI Virtual Cloud Networks (VCNs) ==="
ensure_vcn "$PROD_VCN_NAME" "$PROD_VCN_CIDR" "socprod" PROD_VCN_ID
ensure_vcn "$SECURITY_VCN_NAME" "$SECURITY_VCN_CIDR" "socsec" SECURITY_VCN_ID
echo ""

echo "=== 2. Creating Internet Gateways ==="
ensure_igw "$PROD_IGW_NAME" "$PROD_VCN_ID" PROD_IGW_ID
ensure_igw "$SECURITY_IGW_NAME" "$SECURITY_VCN_ID" SECURITY_IGW_ID
echo ""

echo "=== 3. Creating & Connecting Local Peering Gateways (LPGs) ==="
ensure_lpg "$PROD_LPG_NAME" "$PROD_VCN_ID" PROD_LPG_ID
ensure_lpg "$SECURITY_LPG_NAME" "$SECURITY_VCN_ID" SECURITY_LPG_ID
ensure_lpg_peering "$PROD_LPG_ID" "$SECURITY_LPG_ID"
echo ""

echo "=== 4. Creating Route Tables ==="
PROD_PUB_ROUTES="[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"${PROD_IGW_ID}\"},{\"destination\":\"${SECURITY_VCN_CIDR}\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"${PROD_LPG_ID}\"}]"
PROD_PRIV_ROUTES="[{\"destination\":\"${SECURITY_VCN_CIDR}\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"${PROD_LPG_ID}\"}]"
SEC_MGMT_ROUTES="[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"${SECURITY_IGW_ID}\"},{\"destination\":\"${PROD_VCN_CIDR}\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"${SECURITY_LPG_ID}\"}]"

ensure_route_table "$PROD_PUB_RT_NAME" "$PROD_VCN_ID" "$PROD_PUB_ROUTES" PROD_PUB_RTB_ID
ensure_route_table "$PROD_PRIV_RT_NAME" "$PROD_VCN_ID" "$PROD_PRIV_ROUTES" PROD_PRIV_RTB_ID
ensure_route_table "$SECURITY_MGMT_RT_NAME" "$SECURITY_VCN_ID" "$SEC_MGMT_ROUTES" SECURITY_MGMT_RTB_ID
echo ""

echo "=== 5. Creating Regional Subnets ==="
ensure_subnet "$PROD_PUB_SUBNET_NAME" "$PROD_VCN_ID" "$PROD_PUBLIC_CIDR" "prodpub" "$PROD_PUB_RTB_ID" "false" PROD_PUB_SUBNET_ID
ensure_subnet "$PROD_PRIV_SUBNET_NAME" "$PROD_VCN_ID" "$PROD_PRIVATE_CIDR" "prodpriv" "$PROD_PRIV_RTB_ID" "true" PROD_PRIV_SUBNET_ID
ensure_subnet "$SECURITY_MGMT_SUBNET_NAME" "$SECURITY_VCN_ID" "$SECURITY_MGMT_CIDR" "secmgmt" "$SECURITY_MGMT_RTB_ID" "false" SECURITY_MGMT_SUBNET_ID
echo ""

echo "================================================="
echo "  OCI Dual-VCN Network Provisioning Complete"
echo "================================================="
echo "  Tenancy OCID:     $EXPECTED_OCI_TENANCY_OCID"
echo "  Compartment OCID: $OCI_COMPARTMENT_OCID"
echo "  Region:           $OCI_REGION"
echo ""
echo "  Production VCN:   $PROD_VCN_ID ($PROD_VCN_CIDR)"
echo "    Public Subnet:  $PROD_PUB_SUBNET_ID ($PROD_PUBLIC_CIDR)"
echo "    Private Subnet: $PROD_PRIV_SUBNET_ID ($PROD_PRIVATE_CIDR)"
echo "    IGW:            $PROD_IGW_ID"
echo "    LPG:            $PROD_LPG_ID"
echo ""
echo "  Security VCN:     $SECURITY_VCN_ID ($SECURITY_VCN_CIDR)"
echo "    Mgmt Subnet:    $SECURITY_MGMT_SUBNET_ID ($SECURITY_MGMT_CIDR)"
echo "    IGW:            $SECURITY_IGW_ID"
echo "    LPG:            $SECURITY_LPG_ID"
echo "================================================="
