#!/usr/bin/env bash
#
# infra/instances.sh
#
# Phase 3 Oracle Cloud Infrastructure (OCI) Compute provisioning for the
# Always Free Tier academic SOC lab design.
# Creates three instances when they do not already exist:
#   - soc-automation-web   (VM.Standard.E2.1.Micro, 1 GB RAM, Public Subnet)
#   - soc-automation-db    (VM.Standard.E2.1.Micro, 1 GB RAM, Private Subnet)
#   - soc-automation-wazuh (VM.Standard.A1.Flex, 4 OCPUs / 24 GB RAM, Security Subnet)
#
# Supports PLAN_ONLY=true for dry-run inspection without launching instances.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
EXPECTED_OCI_TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
PLAN_ONLY="${PLAN_ONLY:-false}"

PROJECT="soc-automation"
ENVIRONMENT="lab"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/oci-phase3-compute}"
EVIDENCE_FILE="${EVIDENCE_FILE:-${EVIDENCE_DIR}/instances-after.json}"
PUBLIC_KEY_PATH="${PUBLIC_KEY_PATH:-${HOME}/.ssh/soc-automation-ed25519.pub}"

WEB_SHAPE="${WEB_SHAPE:-VM.Standard.E2.1.Micro}"
DB_SHAPE="${DB_SHAPE:-VM.Standard.E2.1.Micro}"
WAZUH_SHAPE="${WAZUH_SHAPE:-VM.Standard.A1.Flex}"
WAZUH_OCPUS="${WAZUH_OCPUS:-4}"
WAZUH_MEMORY_GB="${WAZUH_MEMORY_GB:-24}"

PROD_VCN_NAME="${PROJECT}-prod-vcn"
SECURITY_VCN_NAME="${PROJECT}-security-vcn"
PROD_PUB_SUBNET_NAME="${PROJECT}-prod-public"
PROD_PRIV_SUBNET_NAME="${PROJECT}-prod-private"
SECURITY_MGMT_SUBNET_NAME="${PROJECT}-security-mgmt"

WEB_NSG_NAME="${PROJECT}-prod-web-nsg"
DB_NSG_NAME="${PROJECT}-prod-db-nsg"
MGMT_NSG_NAME="${PROJECT}-security-mgmt-nsg"

WEB_INSTANCE_NAME="${PROJECT}-web"
DB_INSTANCE_NAME="${PROJECT}-db"
WAZUH_INSTANCE_NAME="${PROJECT}-wazuh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_USER_DATA="${SCRIPT_DIR}/user-data/web.sh"
DB_USER_DATA="${SCRIPT_DIR}/user-data/db.sh"
WAZUH_USER_DATA="${SCRIPT_DIR}/user-data/wazuh-base.sh"

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

plan_mode_enabled() {
    [[ "$PLAN_ONLY" == "true" || "$PLAN_ONLY" == "1" || "$PLAN_ONLY" == "yes" ]]
}

require_public_key() {
    if [[ ! -f "$PUBLIC_KEY_PATH" ]]; then
        fatal "Missing SSH public key at ${PUBLIC_KEY_PATH}. Run 'bash infra/bind-local-pc.sh' first."
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

    AD_NAME=$(oci_cmd iam availability-domain list --compartment-id "$EXPECTED_OCI_TENANCY_OCID" --query "data[0].name" --raw-output)
    [[ -n "$AD_NAME" ]] || fatal "Could not resolve OCI Availability Domain."

    echo "Tenancy OCID:        $tenancy_id"
    echo "Compartment OCID:    $OCI_COMPARTMENT_OCID"
    echo "Region:              $OCI_REGION"
    echo "Availability Domain: $AD_NAME"
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

resolve_ubuntu_image() {
    local shape="$1"
    local result_var="$2"
    local images_json
    local image_id

    images_json=$(oci_cmd compute image list \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --operating-system "Canonical Ubuntu" \
        --shape "$shape" \
        --sort-by TIMECREATED \
        --sort-order DESC \
        --all \
        --output json)

    image_id=$(printf '%s' "$images_json" | python3 -c "
import sys, json
doc = json.load(sys.stdin)
for img in doc.get('data', []):
    name = img.get('display-name', '')
    if ('22.04' in name or '24.04' in name) and 'Minimal' not in name:
        print(img['id'])
        sys.exit(0)
")
    [[ -n "$image_id" ]] || fatal "No Canonical Ubuntu 22.04/24.04 image found for shape ${shape}."
    printf -v "$result_var" '%s' "$image_id"
}

resolve_dependencies() {
    echo "=== Pre-flight: resolving VCNs, Subnets, and NSGs ==="
    PROD_VCN_ID=$(find_resource_by_name "$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$PROD_VCN_NAME" --output json)" "$PROD_VCN_NAME")
    SECURITY_VCN_ID=$(find_resource_by_name "$(oci_cmd network vcn list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$SECURITY_VCN_NAME" --output json)" "$SECURITY_VCN_NAME")
    [[ -n "$PROD_VCN_ID" && -n "$SECURITY_VCN_ID" ]] || fatal "VCNs missing. Run infra/provision.sh first."

    PROD_PUB_SUBNET_ID=$(find_resource_by_name "$(oci_cmd network subnet list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$PROD_VCN_ID" --display-name "$PROD_PUB_SUBNET_NAME" --output json)" "$PROD_PUB_SUBNET_NAME")
    PROD_PRIV_SUBNET_ID=$(find_resource_by_name "$(oci_cmd network subnet list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$PROD_VCN_ID" --display-name "$PROD_PRIV_SUBNET_NAME" --output json)" "$PROD_PRIV_SUBNET_NAME")
    SECURITY_MGMT_SUBNET_ID=$(find_resource_by_name "$(oci_cmd network subnet list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$SECURITY_VCN_ID" --display-name "$SECURITY_MGMT_SUBNET_NAME" --output json)" "$SECURITY_MGMT_SUBNET_NAME")

    WEB_NSG_ID=$(find_resource_by_name "$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$PROD_VCN_ID" --display-name "$WEB_NSG_NAME" --output json)" "$WEB_NSG_NAME")
    DB_NSG_ID=$(find_resource_by_name "$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$PROD_VCN_ID" --display-name "$DB_NSG_NAME" --output json)" "$DB_NSG_NAME")
    MGMT_NSG_ID=$(find_resource_by_name "$(oci_cmd network nsg list --compartment-id "$OCI_COMPARTMENT_OCID" --vcn-id "$SECURITY_VCN_ID" --display-name "$MGMT_NSG_NAME" --output json)" "$MGMT_NSG_NAME")
    [[ -n "$WEB_NSG_ID" && -n "$DB_NSG_ID" && -n "$MGMT_NSG_ID" ]] || fatal "NSGs missing. Run infra/security.sh first."

    resolve_ubuntu_image "$WEB_SHAPE" X86_IMAGE_ID
    resolve_ubuntu_image "$WAZUH_SHAPE" ARM_IMAGE_ID

    echo "Production Public Subnet:  $PROD_PUB_SUBNET_ID"
    echo "Production Private Subnet: $PROD_PRIV_SUBNET_ID"
    echo "Security Mgmt Subnet:      $SECURITY_MGMT_SUBNET_ID"
    echo "x86 Ubuntu Image OCID:     $X86_IMAGE_ID"
    echo "ARM64 Ubuntu Image OCID:   $ARM_IMAGE_ID"
    echo ""
}

launch_or_reuse_instance() {
    local name="$1"
    local role="$2"
    local shape="$3"
    local shape_config="$4"
    local image_id="$5"
    local subnet_id="$6"
    local nsg_id="$7"
    local assign_public_ip="$8"
    local boot_gb="$9"
    local user_data_file="${10}"
    local result_var="${11}"

    local list_json
    list_json=$(oci_cmd compute instance list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$name" --output json 2>/dev/null || echo '{"data":[]}')
    local instance_id
    instance_id=$(find_resource_by_name "$list_json" "$name")

    if [[ -n "$instance_id" ]]; then
        echo "EXISTS   Instance ${name}: ${instance_id}"
        printf -v "$result_var" '%s' "$instance_id"
        return
    fi

    if plan_mode_enabled; then
        echo "PLAN CREATE ${name}: shape=${shape}, subnet=${subnet_id}, nsg=${nsg_id}, public_ip=${assign_public_ip}, boot=${boot_gb}GB"
        printf -v "$result_var" '%s' "plan-${name}"
        return
    fi

    local tags="{\"Project\":\"${PROJECT}\",\"Environment\":\"${ENVIRONMENT}\",\"Role\":\"${role}\"}"
    local -a args=(
        compute instance launch
        --availability-domain "$AD_NAME"
        --compartment-id "$OCI_COMPARTMENT_OCID"
        --display-name "$name"
        --shape "$shape"
        --image-id "$image_id"
        --subnet-id "$subnet_id"
        --nsg-ids "[\"${nsg_id}\"]"
        --assign-public-ip "$assign_public_ip"
        --boot-volume-size-in-gbs "$boot_gb"
        --ssh-authorized-keys-file "$PUBLIC_KEY_PATH"
        --user-data-file "$user_data_file"
        --freeform-tags "$tags"
        --wait-for-state RUNNING
        --query "data.id"
        --raw-output
    )

    if [[ -n "$shape_config" ]]; then
        args+=(--shape-config "$shape_config")
    fi

    instance_id=$(oci_cmd "${args[@]}")
    echo "CREATED  Instance ${name}: ${instance_id}"
    printf -v "$result_var" '%s' "$instance_id"
}

write_inventory() {
    if plan_mode_enabled; then
        return
    fi
    mkdir -p "$EVIDENCE_DIR"
    local raw_json
    raw_json=$(oci_cmd compute instance list --compartment-id "$OCI_COMPARTMENT_OCID" --output json)
    python3 - "$EVIDENCE_FILE" "$EXPECTED_OCI_TENANCY_OCID" "$OCI_COMPARTMENT_OCID" "$OCI_CLI_PROFILE" "$OCI_REGION" "$raw_json" <<'PY'
import json
import sys
from pathlib import Path

out_path, tenancy, compartment, profile, region, raw = sys.argv[1:]
items = json.loads(raw).get("data", [])
filtered = [
    {
        "display_name": i.get("display-name"),
        "id": i.get("id"),
        "shape": i.get("shape"),
        "lifecycle_state": i.get("lifecycle-state"),
        "availability_domain": i.get("availability-domain"),
        "region": i.get("region"),
        "freeform_tags": i.get("freeform-tags", {}),
    }
    for i in items
    if (i.get("freeform-tags") or {}).get("Project") == "soc-automation"
    and i.get("lifecycle-state") != "TERMINATED"
]
doc = {
    "metadata": {
        "cloud": "oracle-cloud-infrastructure",
        "tenancy_ocid": tenancy,
        "compartment_ocid": compartment,
        "profile": profile,
        "region": region,
        "project": "soc-automation",
        "note": "Sanitized OCI compute inventory. No private keys or credentials included.",
    },
    "instances": filtered,
}
Path(out_path).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
    echo "Evidence written: $EVIDENCE_FILE"
}

require_public_key
require_oci_context
resolve_dependencies

echo "=== Launching / Verifying OCI Compute Instances ==="
launch_or_reuse_instance "$WEB_INSTANCE_NAME" "web" "$WEB_SHAPE" "" "$X86_IMAGE_ID" "$PROD_PUB_SUBNET_ID" "$WEB_NSG_ID" "true" "47" "$WEB_USER_DATA" WEB_INSTANCE_ID
launch_or_reuse_instance "$DB_INSTANCE_NAME" "db" "$DB_SHAPE" "" "$X86_IMAGE_ID" "$PROD_PRIV_SUBNET_ID" "$DB_NSG_ID" "false" "47" "$DB_USER_DATA" DB_INSTANCE_ID
launch_or_reuse_instance "$WAZUH_INSTANCE_NAME" "wazuh" "$WAZUH_SHAPE" "{\"ocpus\":${WAZUH_OCPUS},\"memoryInGBs\":${WAZUH_MEMORY_GB}}" "$ARM_IMAGE_ID" "$SECURITY_MGMT_SUBNET_ID" "$MGMT_NSG_ID" "true" "100" "$WAZUH_USER_DATA" WAZUH_INSTANCE_ID

write_inventory

echo ""
echo "================================================="
echo "  OCI Compute Provisioning Complete"
echo "================================================="
echo "  Web:   $WEB_INSTANCE_ID ($WEB_SHAPE)"
echo "  DB:    $DB_INSTANCE_ID ($DB_SHAPE)"
echo "  Wazuh: $WAZUH_INSTANCE_ID ($WAZUH_SHAPE: ${WAZUH_OCPUS} OCPUs / ${WAZUH_MEMORY_GB} GB RAM)"
echo "================================================="
