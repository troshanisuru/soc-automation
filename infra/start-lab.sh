#!/usr/bin/env bash
#
# Start the three tagged EC2 lab instances after they were stopped for cost control.
# This script never creates, terminates, or replaces instances.

set -euo pipefail

AWS_PROFILE="${AWS_PROFILE:-soc-project}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-908157891283}"

PROJECT="soc-automation"
ENVIRONMENT="lab"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/aws-phase3-compute}"
EVIDENCE_FILE="${EVIDENCE_FILE:-${EVIDENCE_DIR}/start-lab-after.json}"

EXPECTED_NAMES=("soc-automation-web" "soc-automation-db" "soc-automation-wazuh")
EXPECTED_ROLES=("web" "db" "wazuh")

aws_ec2() {
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 "$@"
}

aws_sts() {
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" sts "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

require_expected_account() {
    local caller_identity
    caller_identity=$(aws_sts get-caller-identity --output json)

    ACCOUNT_ID=$(printf '%s' "$caller_identity" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
    CALLER_ARN=$(printf '%s' "$caller_identity" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")

    echo "Caller ARN: $CALLER_ARN"
    echo "Account ID: $ACCOUNT_ID"
    echo "Profile:    $AWS_PROFILE"
    echo "Region:     $AWS_REGION"

    if [[ "$ACCOUNT_ID" != "$EXPECTED_AWS_ACCOUNT_ID" ]]; then
        fatal "Expected AWS account ${EXPECTED_AWS_ACCOUNT_ID}, got ${ACCOUNT_ID}. Stopping before any write operation."
    fi
}

find_expected_instance() {
    local name="$1"
    local role="$2"
    local instances_json
    instances_json=$(aws_ec2 describe-instances \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=tag:Role,Values=${role}" \
                  "Name=tag:Environment,Values=${ENVIRONMENT}" \
        --output json)

    printf '%s' "$instances_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
instances = []
for reservation in data.get('Reservations', []):
    for instance in reservation.get('Instances', []):
        state = instance.get('State', {}).get('Name', 'unknown')
        if state != 'terminated':
            instances.append(instance)
if len(instances) > 1:
    print('ERROR multiple matching instances', file=sys.stderr)
    for instance in instances:
        print(instance.get('InstanceId') + ' ' + instance.get('State', {}).get('Name', 'unknown'), file=sys.stderr)
    sys.exit(2)
if instances:
    instance = instances[0]
    print(instance.get('InstanceId'), instance.get('State', {}).get('Name', 'unknown'))
"
}

write_inventory() {
    local -a ids=("$@")
    mkdir -p "$EVIDENCE_DIR"

    local tmp
    tmp=$(mktemp)
    aws_ec2 describe-instances \
        --instance-ids "${ids[@]}" \
        --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Role:Tags[?Key=='Role']|[0].Value,InstanceId:InstanceId,State:State.Name,PrivateIpAddress:PrivateIpAddress,PublicIpAddress:PublicIpAddress}" \
        --output json > "$tmp"

    python3 - "$tmp" "$EVIDENCE_FILE" "$ACCOUNT_ID" "$AWS_PROFILE" "$AWS_REGION" <<'PY'
import json
import sys
from pathlib import Path
instances_path, out, account, profile, region = sys.argv[1:]
Path(out).write_text(json.dumps({
    "metadata": {
        "account": account,
        "profile": profile,
        "region": region,
        "project": "soc-automation",
        "note": "Sanitized start-lab inventory. No credentials, key material, passwords, tokens, or user-data are included."
    },
    "instances": json.loads(Path(instances_path).read_text())
}, indent=2, sort_keys=True) + "\n")
PY
    rm -f "$tmp"
    echo "Evidence written: $EVIDENCE_FILE"
}

require_expected_account

to_start=()
all_ids=()
for i in "${!EXPECTED_NAMES[@]}"; do
    match=$(find_expected_instance "${EXPECTED_NAMES[$i]}" "${EXPECTED_ROLES[$i]}")
    if [[ -z "$match" ]]; then
        fatal "Missing expected instance ${EXPECTED_NAMES[$i]} (${EXPECTED_ROLES[$i]}). Run infra/instances.sh only after EC2 provisioning is authorized."
    fi

    instance_id=${match%% *}
    state=${match#* }
    all_ids+=("$instance_id")

    case "$state" in
        stopped)
            to_start+=("$instance_id")
            echo "STARTING ${EXPECTED_NAMES[$i]}: ${instance_id}"
            ;;
        running|pending)
            echo "EXISTS   ${EXPECTED_NAMES[$i]}: ${instance_id} (${state})"
            ;;
        stopping)
            fatal "${EXPECTED_NAMES[$i]} is stopping (${instance_id}); wait until stopped before starting."
            ;;
        shutting-down)
            fatal "${EXPECTED_NAMES[$i]} is shutting down (${instance_id}); refusing to manage it."
            ;;
        *)
            fatal "${EXPECTED_NAMES[$i]} has unexpected state ${state} (${instance_id})."
            ;;
    esac
done

if [[ "${#to_start[@]}" -gt 0 ]]; then
    aws_ec2 start-instances --instance-ids "${to_start[@]}" > /dev/null
else
    echo "No stopped lab instances needed starting."
fi

aws_ec2 wait instance-running --instance-ids "${all_ids[@]}"
aws_ec2 wait instance-status-ok --instance-ids "${all_ids[@]}"
echo "Lab instances are running and status checks passed."

write_inventory "${all_ids[@]}"
