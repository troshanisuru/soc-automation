#!/usr/bin/env bash
#
# infra/stop-lab.sh
# Gracefully stop the three tagged OCI Compute lab instances.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
OCI_REGION="${OCI_REGION:-ap-mumbai-1}"
EXPECTED_OCI_TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.tenancy.oc1..aaaaaaaaczd46q2x7vvqwb35wnuvetzlervmdfiv36wvlfhwgk34xx3ztz7q}"

EXPECTED_NAMES=("soc-automation-web" "soc-automation-db" "soc-automation-wazuh")

oci_cmd() {
    command oci --profile "$OCI_CLI_PROFILE" --region "$OCI_REGION" "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ -n "$EXPECTED_OCI_TENANCY_OCID" ]] || fatal "Set EXPECTED_OCI_TENANCY_OCID."
[[ -n "$OCI_COMPARTMENT_OCID" ]] || fatal "Set OCI_COMPARTMENT_OCID."

TENANCY_ID=$(oci_cmd iam tenancy get --tenancy-id "$EXPECTED_OCI_TENANCY_OCID" --query "data.id" --raw-output)
[[ "$TENANCY_ID" == "$EXPECTED_OCI_TENANCY_OCID" ]] || fatal "Tenancy OCID mismatch."

for name in "${EXPECTED_NAMES[@]}"; do
    list_json=$(oci_cmd compute instance list --compartment-id "$OCI_COMPARTMENT_OCID" --display-name "$name" --output json)
    info=$(printf '%s' "$list_json" | python3 -c "
import sys, json
for item in json.load(sys.stdin).get('data', []):
    if item.get('display-name') == sys.argv[1] and item.get('lifecycle-state') != 'TERMINATED':
        print(item['id'], item['lifecycle-state'])
        sys.exit(0)
" "$name")
    if [[ -z "$info" ]]; then
        echo "MISSING  ${name}"
        continue
    fi
    instance_id=${info%% *}
    state=${info#* }

    if [[ "$state" == "RUNNING" ]]; then
        echo "STOPPING ${name}: ${instance_id}"
        oci_cmd compute instance action --instance-id "$instance_id" --action SOFTSTOP --wait-for-state STOPPED >/dev/null
    else
        echo "EXISTS   ${name}: ${instance_id} (${state})"
    fi
done

echo "OCI lab instances are STOPPED."
