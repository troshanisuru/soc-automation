#!/usr/bin/env bash
#
# scripts/01_setup_oci_logging.sh
# Automated setup for OCI Object Storage bucket (for WAF & VCN Flow Logs)
# and OCI Logging Group in the soc-automation compartment.
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"

if [[ -z "$OCI_COMPARTMENT_OCID" ]]; then
    echo "ERROR: Set OCI_COMPARTMENT_OCID before running 01_setup_oci_logging.sh" >&2
    exit 1
fi

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

NAMESPACE=$(oci_cmd os ns get --query "data" --raw-output)
BUCKET_NAME="oci-waf-vcn-logs-soc-project"
LOG_GROUP_NAME="soc-automation-log-group"

echo "=========================================================="
echo "  OCI LOGGING & OBJECT STORAGE PROVISIONING FOR WAZUH"
echo "=========================================================="
echo "Region:      ${OCI_REGION}"
echo "Namespace:   ${NAMESPACE}"
echo "Bucket Name: ${BUCKET_NAME}"
echo "Compartment: ${OCI_COMPARTMENT_OCID}"
echo "----------------------------------------------------------"

echo "=== 1. Creating Private OCI Object Storage Bucket ==="
EXISTING_BUCKET=$(oci_cmd os bucket get --namespace-name "$NAMESPACE" --bucket-name "$BUCKET_NAME" --query "data.name" --raw-output 2>/dev/null || true)
if [[ -z "$EXISTING_BUCKET" ]]; then
    oci_cmd os bucket create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --namespace-name "$NAMESPACE" \
        --name "$BUCKET_NAME" \
        --public-access-type NoPublicAccess >/dev/null
    echo "CREATED OCI Object Storage bucket: ${BUCKET_NAME}"
else
    echo "EXISTS  OCI Object Storage bucket: ${BUCKET_NAME}"
fi

echo "=== 2. Creating OCI Logging Group for VCN Flow & WAF Logs ==="
EXISTING_LG=$(oci_cmd logging log-group list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$LOG_GROUP_NAME" --query "data[0].id" --raw-output 2>/dev/null || true)
if [[ -z "$EXISTING_LG" || "$EXISTING_LG" == "null" ]]; then
    LG_ID=$(oci_cmd logging log-group create \
        --compartment-id "$OCI_COMPARTMENT_OCID" \
        --display-name "$LOG_GROUP_NAME" \
        --description "Centralized OCI VCN Flow Logs and WAF telemetry for Wazuh" \
        --query "data" --raw-output)
    echo "CREATED OCI Log Group: ${LOG_GROUP_NAME} (${LG_ID})"
else
    echo "EXISTS  OCI Log Group: ${LOG_GROUP_NAME} (${EXISTING_LG})"
fi

echo "=========================================================="
echo "  OCI LOGGING SETUP COMPLETE"
echo "=========================================================="
echo "  S3-Compatible Endpoint for Wazuh Manager:"
echo "    https://${NAMESPACE}.compat.objectstorage.${OCI_REGION}.oraclecloud.com"
echo "=========================================================="
