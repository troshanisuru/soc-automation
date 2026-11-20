#!/usr/bin/env bash
#
# infra/provision.sh
#
# Phase 1 Oracle Cloud Infrastructure (OCI) provisioning script for the
# Security VCN topology:
#   - VCN: security-vcn (172.16.0.0/16)
#   - Internet Gateway: security-igw
#   - Route Table: security-mgmt-rt (0.0.0.0/0 -> security-igw)
#   - Public Subnet: security-mgmt-subnet (172.16.1.0/24)
#   - NSG: security-nsg
#     * TCP 22 from ADMIN_IP_CIDR (/32 only)
#     * TCP 11434 from 172.16.0.0/16 only
#     * TCP 1514 from 0.0.0.0/0
#     * TCP 1515 from 0.0.0.0/0
#     * TCP 443 from ADMIN_IP_CIDR (/32 only)
#     * Egress: all protocols to 0.0.0.0/0

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

SECURITY_VCN_NAME="security-vcn"
SECURITY_VCN_CIDR="172.16.0.0/16"
SECURITY_IGW_NAME="security-igw"
SECURITY_RT_NAME="security-mgmt-rt"
SECURITY_SUBNET_NAME="security-mgmt-subnet"
SECURITY_SUBNET_CIDR="172.16.1.0/24"
SECURITY_NSG_NAME="security-nsg"

EVIDENCE_DIR="${REPO_ROOT}/evidence/oci-phase1-security-network"
mkdir -p "$EVIDENCE_DIR"

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

if [[ -z "$ADMIN_IP_CIDR" ]]; then
    PUB_IP=$(python3 -c "import urllib.request; print(urllib.request.urlopen('https://checkip.amazonaws.com', timeout=10).read().decode().strip())")
    ADMIN_IP_CIDR="${PUB_IP}/32"
fi

if [[ "$ADMIN_IP_CIDR" == "0.0.0.0/0" ]]; then
    fatal "ADMIN_IP_CIDR must not be 0.0.0.0/0"
fi

find_by_name() {
    local json_input="$1"
    local display_name="$2"
    printf '%s' "$json_input" | python3 -c "
import sys, json
target = sys.argv[1]
raw = sys.stdin.read().strip()
doc = json.loads(raw) if raw else {}
for item in (doc.get('data') or []):
    if item.get('display-name') == target and item.get('lifecycle-state') not in ('TERMINATED', 'TERMINATING'):
        print(item['id'])
        sys.exit(0)
" "$display_name"
}

echo "=== 1. Creating/Reusing VCN: ${SECURITY_VCN_NAME} (${SECURITY_VCN_CIDR}) ==="
VCN_LIST=$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$SECURITY_VCN_NAME" --output json 2>/dev/null || echo '{"data":[]}')
VCN_ID=$(find_by_name "$VCN_LIST" "$SECURITY_VCN_NAME")
if [[ -z "$VCN_ID" ]]; then
    VCN_ID=$(oci_cmd network vcn create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --display-name "$SECURITY_VCN_NAME" \
        --cidr-blocks "[\"${SECURITY_VCN_CIDR}\"]" \
        --dns-label "securityvcn" \
        --freeform-tags "$FREEFORM_TAGS" \
        --wait-for-state AVAILABLE \
        --query "data.id" \
        --raw-output)
    echo "CREATED VCN ${SECURITY_VCN_NAME}: ${VCN_ID}"
else
    echo "EXISTS  VCN ${SECURITY_VCN_NAME}: ${VCN_ID}"
fi

echo "=== 1b. Clearing VCN Default Security List so only security-nsg enforces rules ==="
DEFAULT_SL_ID=$(oci_cmd network vcn get --vcn-id "$VCN_ID" --query "data.\"default-security-list-id\"" --raw-output)
oci_cmd network security-list update \
    --security-list-id "$DEFAULT_SL_ID" \
    --ingress-security-rules '[]' \
    --egress-security-rules '[]' \
    --force >/dev/null
echo "CLEARED VCN Default Security List: ${DEFAULT_SL_ID}"

echo "=== 2. Creating/Reusing Internet Gateway: ${SECURITY_IGW_NAME} ==="
IGW_LIST=$(oci_cmd network internet-gateway list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$VCN_ID" --display-name "$SECURITY_IGW_NAME" --output json 2>/dev/null || echo '{"data":[]}')
IGW_ID=$(find_by_name "$IGW_LIST" "$SECURITY_IGW_NAME")
if [[ -z "$IGW_ID" ]]; then
    IGW_ID=$(oci_cmd network internet-gateway create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --vcn-id "$VCN_ID" \
        --display-name "$SECURITY_IGW_NAME" \
        --is-enabled true \
        --freeform-tags "$FREEFORM_TAGS" \
        --wait-for-state AVAILABLE \
        --query "data.id" \
        --raw-output)
    echo "CREATED IGW ${SECURITY_IGW_NAME}: ${IGW_ID}"
else
    echo "EXISTS  IGW ${SECURITY_IGW_NAME}: ${IGW_ID}"
fi

echo "=== 3. Configuring Route Table for 0.0.0.0/0 -> ${IGW_ID} ==="
ROUTE_RULES="[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"${IGW_ID}\"}]"
RT_LIST=$(oci_cmd network route-table list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$VCN_ID" --display-name "$SECURITY_RT_NAME" --output json 2>/dev/null || echo '{"data":[]}')
RT_ID=$(find_by_name "$RT_LIST" "$SECURITY_RT_NAME")
if [[ -z "$RT_ID" ]]; then
    RT_ID=$(oci_cmd network route-table create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --vcn-id "$VCN_ID" \
        --display-name "$SECURITY_RT_NAME" \
        --route-rules "$ROUTE_RULES" \
        --freeform-tags "$FREEFORM_TAGS" \
        --wait-for-state AVAILABLE \
        --query "data.id" \
        --raw-output)
    echo "CREATED Route Table ${SECURITY_RT_NAME}: ${RT_ID}"
else
    oci_cmd network route-table update --rt-id "$RT_ID" --route-rules "$ROUTE_RULES" --force >/dev/null
    echo "UPDATED Route Table ${SECURITY_RT_NAME}: ${RT_ID}"
fi

echo "=== 4. Creating/Reusing Public Subnet: ${SECURITY_SUBNET_NAME} (${SECURITY_SUBNET_CIDR}) ==="
SUBNET_LIST=$(oci_cmd network subnet list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$VCN_ID" --display-name "$SECURITY_SUBNET_NAME" --output json 2>/dev/null || echo '{"data":[]}')
SUBNET_ID=$(find_by_name "$SUBNET_LIST" "$SECURITY_SUBNET_NAME")
if [[ -z "$SUBNET_ID" ]]; then
    SUBNET_ID=$(oci_cmd network subnet create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --vcn-id "$VCN_ID" \
        --display-name "$SECURITY_SUBNET_NAME" \
        --cidr-block "$SECURITY_SUBNET_CIDR" \
        --dns-label "secmgmt" \
        --route-table-id "$RT_ID" \
        --prohibit-public-ip-on-vnic false \
        --freeform-tags "$FREEFORM_TAGS" \
        --wait-for-state AVAILABLE \
        --query "data.id" \
        --raw-output)
    echo "CREATED Subnet ${SECURITY_SUBNET_NAME}: ${SUBNET_ID}"
else
    echo "EXISTS  Subnet ${SECURITY_SUBNET_NAME}: ${SUBNET_ID}"
fi

echo "=== 5. Creating/Reusing NSG: ${SECURITY_NSG_NAME} (Admin CIDR: ${ADMIN_IP_CIDR}) ==="
NSG_LIST=$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$VCN_ID" --display-name "$SECURITY_NSG_NAME" --output json 2>/dev/null || echo '{"data":[]}')
NSG_ID=$(find_by_name "$NSG_LIST" "$SECURITY_NSG_NAME")
if [[ -z "$NSG_ID" ]]; then
    NSG_ID=$(oci_cmd network nsg create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --vcn-id "$VCN_ID" \
        --display-name "$SECURITY_NSG_NAME" \
        --freeform-tags "$FREEFORM_TAGS" \
        --wait-for-state AVAILABLE \
        --query "data.id" \
        --raw-output)
    echo "CREATED NSG ${SECURITY_NSG_NAME}: ${NSG_ID}"
else
    echo "EXISTS  NSG ${SECURITY_NSG_NAME}: ${NSG_ID}"
fi

# Remove any stale /32 ingress rules on ports 22 or 443 that do not match current ADMIN_IP_CIDR
EXISTING_RULES=$(oci_cmd network nsg rules list --nsg-id "$NSG_ID" --all --output json 2>/dev/null || echo '{"data":[]}')
STALE_IDS=$(printf '%s' "$EXISTING_RULES" | python3 -c "
import sys, json
admin_cidr = sys.argv[1]
raw = sys.stdin.read().strip()
doc = json.loads(raw) if raw else {}
stale = []
for r in (doc.get('data') or []):
    if r.get('direction') == 'INGRESS' and str(r.get('protocol')) == '6':
        rng = (r.get('tcp-options') or {}).get('destination-port-range') or {}
        if rng.get('min') in (22, 443) and r.get('source') != admin_cidr:
            stale.append(r['id'])
print(json.dumps(stale))
" "$ADMIN_IP_CIDR")
if [[ "$STALE_IDS" != "[]" ]]; then
    oci_cmd network nsg rules remove --nsg-id "$NSG_ID" --security-rule-ids "$STALE_IDS" >/dev/null
    echo "REMOVED stale NSG /32 rule IDs: ${STALE_IDS}"
fi

add_nsg_ingress_if_missing() {
    local source="$1"
    local port="$2"
    local desc="$3"
    local rules_json
    rules_json=$(oci_cmd network nsg rules list --nsg-id "$NSG_ID" --all --output json 2>/dev/null || echo '{"data":[]}')
    local exists
    exists=$(printf '%s' "$rules_json" | python3 -c "
import sys, json
source, port = sys.argv[1], int(sys.argv[2])
raw = sys.stdin.read().strip()
doc = json.loads(raw) if raw else {}
for r in (doc.get('data') or []):
    if r.get('direction') == 'INGRESS' and str(r.get('protocol')) == '6' and r.get('source') == source:
        rng = (r.get('tcp-options') or {}).get('destination-port-range') or {}
        if rng.get('min') == port and rng.get('max') == port:
            print('yes')
            sys.exit(0)
print('no')
" "$source" "$port")
    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS  NSG rule: ${desc}"
        return
    fi
    local payload="[{\"direction\":\"INGRESS\",\"protocol\":\"6\",\"source\":\"${source}\",\"sourceType\":\"CIDR_BLOCK\",\"isStateless\":false,\"description\":\"${desc}\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":${port},\"max\":${port}}}}]"
    oci_cmd network nsg rules add --nsg-id "$NSG_ID" --security-rules "$payload" >/dev/null
    echo "ADDED   NSG rule: ${desc}"
}

add_nsg_egress_if_missing() {
    local rules_json
    rules_json=$(oci_cmd network nsg rules list --nsg-id "$NSG_ID" --all --output json 2>/dev/null || echo '{"data":[]}')
    local exists
    exists=$(printf '%s' "$rules_json" | python3 -c "
import sys, json
raw = sys.stdin.read().strip()
doc = json.loads(raw) if raw else {}
for r in (doc.get('data') or []):
    if r.get('direction') == 'EGRESS' and r.get('destination') == '0.0.0.0/0' and r.get('protocol') == 'all':
        print('yes')
        sys.exit(0)
print('no')
")
    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS  NSG egress rule: all outbound to 0.0.0.0/0"
        return
    fi
    local payload="[{\"direction\":\"EGRESS\",\"protocol\":\"all\",\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"isStateless\":false,\"description\":\"Allow all outbound traffic\"}]"
    oci_cmd network nsg rules add --nsg-id "$NSG_ID" --security-rules "$payload" >/dev/null
    echo "ADDED   NSG egress rule: all outbound to 0.0.0.0/0"
}

add_nsg_ingress_if_missing "$ADMIN_IP_CIDR" 22 "SSH (TCP 22) from admin public IP /32 only"
add_nsg_ingress_if_missing "$SECURITY_VCN_CIDR" 11434 "Ollama API (TCP 11434) internal to security-vcn (172.16.0.0/16) only"
add_nsg_ingress_if_missing "0.0.0.0/0" 1514 "Wazuh agent data (TCP 1514)"
add_nsg_ingress_if_missing "0.0.0.0/0" 1515 "Wazuh agent registration (TCP 1515)"
add_nsg_ingress_if_missing "$ADMIN_IP_CIDR" 443 "Wazuh dashboard HTTPS (TCP 443) from admin public IP /32 only"
add_nsg_egress_if_missing

echo "=== Saving Section 1 Verification Evidence JSONs ==="
oci_cmd network vcn get --vcn-id "$VCN_ID" > "${EVIDENCE_DIR}/vcn-get.json"
oci_cmd network subnet get --subnet-id "$SUBNET_ID" > "${EVIDENCE_DIR}/subnet-get.json"
oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$VCN_ID" > "${EVIDENCE_DIR}/nsg-list.json"
oci_cmd network nsg rules list --nsg-id "$NSG_ID" --all > "${EVIDENCE_DIR}/nsg-rules-list.json"

echo "VCN_ID=${VCN_ID}"
echo "SUBNET_ID=${SUBNET_ID}"
echo "NSG_ID=${NSG_ID}"
