#!/usr/bin/env bash
#
# Rotate the admin /32 CIDR on existing soc-automation Security Groups.
#
# This script adds the new admin CIDR first, verifies it, then removes only
# matching old admin CIDR rules. It does not select Security Groups by wildcard.

set -euo pipefail

AWS_PROFILE="${AWS_PROFILE:-soc-project}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
EXPECTED_AWS_PROFILE="${EXPECTED_AWS_PROFILE:-soc-project}"
EXPECTED_AWS_REGION="${EXPECTED_AWS_REGION:-ap-southeast-1}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-908157891283}"

PROJECT="soc-automation"
OLD_ADMIN_IP_CIDR="${OLD_ADMIN_IP_CIDR:-}"
NEW_ADMIN_IP_CIDR="${NEW_ADMIN_IP_CIDR:-}"

PROD_VPC_ID="vpc-01d5230934a140846"
SECURITY_VPC_ID="vpc-0fb2381154ad1b418"

WEB_SG_ID="sg-01dc0bd14c2808f21"
MGMT_SG_ID="sg-0effe1d21b6836624"
DB_SG_ID="sg-03e665ea5e9403e11"

WEB_SG_NAME="${PROJECT}-prod-web-sg"
MGMT_SG_NAME="${PROJECT}-security-mgmt-sg"
DB_SG_NAME="${PROJECT}-prod-db-sg"

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

validate_cidr() {
    local name="$1"
    local value="$2"

    if [[ -z "$value" ]]; then
        fatal "${name} must be set."
    fi

    if [[ "$value" == "0.0.0.0/0" ]]; then
        fatal "${name} must not be 0.0.0.0/0."
    fi

    python3 -c "
import ipaddress
import sys
name, value = sys.argv[1], sys.argv[2]
try:
    network = ipaddress.ip_network(value, strict=True)
except ValueError as exc:
    raise SystemExit(f'{name} must be a valid IPv4 /32 CIDR: {exc}')
if network.version != 4 or network.prefixlen != 32:
    raise SystemExit(f'{name} must be a valid IPv4 /32 CIDR.')
if not network.network_address.is_global:
    raise SystemExit(f'{name} must be a public IPv4 /32 CIDR.')
" "$name" "$value"
}

require_current_public_ip() {
    local expected_ip
    local current_ip

    expected_ip="${NEW_ADMIN_IP_CIDR%/32}"
    current_ip=$(curl -fsS -4 https://checkip.amazonaws.com | tr -d '[:space:]')

    python3 -c "
import ipaddress
import sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
except ValueError as exc:
    raise SystemExit(f'Current public IP check returned an invalid IPv4 address: {exc}')
if ip.version != 4 or not ip.is_global:
    raise SystemExit('Current public IP check did not return a public IPv4 address.')
" "$current_ip"

    if [[ "$current_ip" != "$expected_ip" ]]; then
        fatal "Current public IPv4 is ${current_ip}, expected ${expected_ip}. Stopping before AWS changes."
    fi

    echo "Current public IPv4 confirmed: ${current_ip}"
    echo "New admin CIDR: ${NEW_ADMIN_IP_CIDR}"
}

require_expected_account() {
    local caller_identity
    local account_id
    local caller_arn

    if [[ "$AWS_PROFILE" != "$EXPECTED_AWS_PROFILE" ]]; then
        fatal "Expected AWS profile ${EXPECTED_AWS_PROFILE}, got ${AWS_PROFILE}. Stopping before AWS changes."
    fi

    if [[ "$AWS_REGION" != "$EXPECTED_AWS_REGION" ]]; then
        fatal "Expected AWS region ${EXPECTED_AWS_REGION}, got ${AWS_REGION}. Stopping before AWS changes."
    fi

    caller_identity=$(aws_sts get-caller-identity --output json)
    account_id=$(printf '%s' "$caller_identity" | python3 -c "import json,sys; print(json.load(sys.stdin)['Account'])")
    caller_arn=$(printf '%s' "$caller_identity" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])")

    echo "Caller ARN: ${caller_arn}"
    echo "Account ID: ${account_id}"
    echo "Profile:    ${AWS_PROFILE}"
    echo "Region:     ${AWS_REGION}"

    if [[ "$account_id" != "$EXPECTED_AWS_ACCOUNT_ID" ]]; then
        fatal "Expected AWS account ${EXPECTED_AWS_ACCOUNT_ID}, got ${account_id}. Stopping before AWS changes."
    fi
}

validate_security_group() {
    local sg_id="$1"
    local expected_name="$2"
    local expected_vpc="$3"
    local label="$4"
    local sg_json

    sg_json=$(aws_ec2 describe-security-groups --group-ids "$sg_id" --output json)

    printf '%s' "$sg_json" | python3 -c "
import json
import sys
expected_name, expected_project, expected_vpc, label = sys.argv[1:5]
doc = json.load(sys.stdin)
groups = doc.get('SecurityGroups', [])
if len(groups) != 1:
    raise SystemExit(f'{label}: expected exactly one Security Group, got {len(groups)}')
sg = groups[0]
tags = {t.get('Key'): t.get('Value') for t in sg.get('Tags', [])}
errors = []
if sg.get('VpcId') != expected_vpc:
    errors.append(f'VpcId expected {expected_vpc}, got {sg.get(\"VpcId\")}')
if tags.get('Name') != expected_name:
    errors.append(f'Name tag expected {expected_name}, got {tags.get(\"Name\")}')
if tags.get('Project') != expected_project:
    errors.append(f'Project tag expected {expected_project}, got {tags.get(\"Project\")}')
if errors:
    raise SystemExit(f'{label}: ' + '; '.join(errors))
" "$expected_name" "$PROJECT" "$expected_vpc" "$label"

    echo "Validated ${label}: ${sg_id}"
}

rule_exists() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local rules

    rules=$(aws_ec2 describe-security-groups \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions" \
        --output json)

    printf '%s' "$rules" | python3 -c "
import json
import sys
protocol, port, cidr = sys.argv[1], int(sys.argv[2]), sys.argv[3]
for rule in json.load(sys.stdin):
    if rule.get('IpProtocol') != protocol:
        continue
    if rule.get('FromPort') != port or rule.get('ToPort') != port:
        continue
    for ip_range in rule.get('IpRanges', []):
        if ip_range.get('CidrIp') == cidr:
            print('yes')
            raise SystemExit(0)
print('no')
" "$protocol" "$port" "$cidr"
}

require_rule_present() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local label="$5"
    local exists

    exists=$(rule_exists "$sg_id" "$protocol" "$port" "$cidr")
    if [[ "$exists" != "yes" ]]; then
        fatal "Missing expected rule after update: ${label}"
    fi
}

require_rule_absent() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local label="$5"
    local exists

    exists=$(rule_exists "$sg_id" "$protocol" "$port" "$cidr")
    if [[ "$exists" == "yes" ]]; then
        fatal "Unexpected rule still present: ${label}"
    fi
}

dry_run_ec2() {
    local label="$1"
    shift
    local output
    local status

    set +e
    output=$(aws_ec2 "$@" --dry-run 2>&1)
    status=$?
    set -e

    if printf '%s' "$output" | grep -q "DryRunOperation"; then
        echo "DRYRUN  authorized ${label}"
        return
    fi

    if printf '%s' "$output" | grep -q "UnauthorizedOperation"; then
        fatal "Dry-run denied for ${label}: ${output}"
    fi

    fatal "Dry-run failed for ${label} with exit status ${status}: ${output}"
}

authorize_if_missing() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local label="$5"
    local exists

    exists=$(rule_exists "$sg_id" "$protocol" "$port" "$cidr")
    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS  ${label}"
        return
    fi

    aws_ec2 authorize-security-group-ingress \
        --group-id "$sg_id" \
        --protocol "$protocol" \
        --port "$port" \
        --cidr "$cidr" > /dev/null

    echo "ADDED   ${label}"
}

revoke_if_present() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local label="$5"
    local exists

    exists=$(rule_exists "$sg_id" "$protocol" "$port" "$cidr")
    if [[ "$exists" != "yes" ]]; then
        echo "ABSENT  ${label}"
        return
    fi

    aws_ec2 revoke-security-group-ingress \
        --group-id "$sg_id" \
        --protocol "$protocol" \
        --port "$port" \
        --cidr "$cidr" > /dev/null

    echo "REMOVED ${label}"
}

security_groups_json() {
    aws_ec2 describe-security-groups \
        --group-ids "$WEB_SG_ID" "$MGMT_SG_ID" "$DB_SG_ID" \
        --output json
}

require_no_sensitive_public_rules() {
    local data
    data=$(security_groups_json)

    printf '%s' "$data" | python3 -c "
import json
import sys
doc = json.load(sys.stdin)
sensitive = {
    'sg-01dc0bd14c2808f21': {22},
    'sg-0effe1d21b6836624': {22, 443, 1514, 1515, 55000},
    'sg-03e665ea5e9403e11': {22, 5432},
}
bad = []
for sg in doc.get('SecurityGroups', []):
    sg_id = sg.get('GroupId')
    for rule in sg.get('IpPermissions', []):
        if rule.get('IpProtocol') != 'tcp':
            continue
        from_port, to_port = rule.get('FromPort'), rule.get('ToPort')
        if from_port != to_port or from_port not in sensitive.get(sg_id, set()):
            continue
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                bad.append(f'{sg_id}: tcp/{from_port} from 0.0.0.0/0')
if bad:
    raise SystemExit('Public sensitive ingress found: ' + '; '.join(bad))
"
}

require_expected_admin_cidr_usage() {
    local data
    data=$(security_groups_json)

    printf '%s' "$data" | python3 -c "
import json
import sys
old, new = sys.argv[1], sys.argv[2]
allowed_old = {
    ('sg-01dc0bd14c2808f21', 22),
    ('sg-0effe1d21b6836624', 22),
    ('sg-0effe1d21b6836624', 443),
    ('sg-0effe1d21b6836624', 55000),
    ('sg-03e665ea5e9403e11', 22),
}
allowed_new = {
    ('sg-01dc0bd14c2808f21', 22),
    ('sg-0effe1d21b6836624', 22),
    ('sg-0effe1d21b6836624', 443),
    ('sg-0effe1d21b6836624', 55000),
}
bad = []
for sg in json.load(sys.stdin).get('SecurityGroups', []):
    sg_id = sg.get('GroupId')
    for rule in sg.get('IpPermissions', []):
        if rule.get('IpProtocol') != 'tcp':
            continue
        from_port, to_port = rule.get('FromPort'), rule.get('ToPort')
        if from_port != to_port:
            continue
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')
            key = (sg_id, from_port)
            if cidr == old and key not in allowed_old:
                bad.append(f'unexpected old admin CIDR on {sg_id} tcp/{from_port}')
            if cidr == new and key not in allowed_new:
                bad.append(f'unexpected new admin CIDR on {sg_id} tcp/{from_port}')
if bad:
    raise SystemExit('; '.join(bad))
" "$OLD_ADMIN_IP_CIDR" "$NEW_ADMIN_IP_CIDR"
}

require_old_absent_from_all_project_sgs() {
    local data
    data=$(security_groups_json)

    printf '%s' "$data" | python3 -c "
import json
import sys
old = sys.argv[1]
bad = []
for sg in json.load(sys.stdin).get('SecurityGroups', []):
    sg_id = sg.get('GroupId')
    for rule in sg.get('IpPermissions', []):
        if rule.get('IpProtocol') != 'tcp':
            continue
        from_port, to_port = rule.get('FromPort'), rule.get('ToPort')
        if from_port != to_port:
            continue
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == old:
                bad.append(f'{sg_id} tcp/{from_port}')
if bad:
    raise SystemExit('Old admin CIDR still present: ' + '; '.join(bad))
" "$OLD_ADMIN_IP_CIDR"
}

main() {
    validate_cidr "OLD_ADMIN_IP_CIDR" "$OLD_ADMIN_IP_CIDR"
    validate_cidr "NEW_ADMIN_IP_CIDR" "$NEW_ADMIN_IP_CIDR"

    if [[ "$OLD_ADMIN_IP_CIDR" == "$NEW_ADMIN_IP_CIDR" ]]; then
        fatal "OLD_ADMIN_IP_CIDR and NEW_ADMIN_IP_CIDR must be different."
    fi

    require_current_public_ip
    require_expected_account

    validate_security_group "$WEB_SG_ID" "$WEB_SG_NAME" "$PROD_VPC_ID" "prod-web-sg"
    validate_security_group "$MGMT_SG_ID" "$MGMT_SG_NAME" "$SECURITY_VPC_ID" "security-mgmt-sg"
    validate_security_group "$DB_SG_ID" "$DB_SG_NAME" "$PROD_VPC_ID" "prod-db-sg"

    require_no_sensitive_public_rules
    require_expected_admin_cidr_usage

    echo "=== Permission dry-run ==="
    [[ "$(rule_exists "$WEB_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR")" != "yes" ]] && \
        dry_run_ec2 "add web SSH ${NEW_ADMIN_IP_CIDR}" authorize-security-group-ingress --group-id "$WEB_SG_ID" --protocol tcp --port 22 --cidr "$NEW_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$MGMT_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR")" != "yes" ]] && \
        dry_run_ec2 "add management SSH ${NEW_ADMIN_IP_CIDR}" authorize-security-group-ingress --group-id "$MGMT_SG_ID" --protocol tcp --port 22 --cidr "$NEW_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$MGMT_SG_ID" tcp 443 "$NEW_ADMIN_IP_CIDR")" != "yes" ]] && \
        dry_run_ec2 "add management HTTPS ${NEW_ADMIN_IP_CIDR}" authorize-security-group-ingress --group-id "$MGMT_SG_ID" --protocol tcp --port 443 --cidr "$NEW_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$MGMT_SG_ID" tcp 55000 "$NEW_ADMIN_IP_CIDR")" != "yes" ]] && \
        dry_run_ec2 "add management Wazuh API ${NEW_ADMIN_IP_CIDR}" authorize-security-group-ingress --group-id "$MGMT_SG_ID" --protocol tcp --port 55000 --cidr "$NEW_ADMIN_IP_CIDR"

    [[ "$(rule_exists "$WEB_SG_ID" tcp 22 "$OLD_ADMIN_IP_CIDR")" == "yes" ]] && \
        dry_run_ec2 "remove web SSH ${OLD_ADMIN_IP_CIDR}" revoke-security-group-ingress --group-id "$WEB_SG_ID" --protocol tcp --port 22 --cidr "$OLD_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$MGMT_SG_ID" tcp 22 "$OLD_ADMIN_IP_CIDR")" == "yes" ]] && \
        dry_run_ec2 "remove management SSH ${OLD_ADMIN_IP_CIDR}" revoke-security-group-ingress --group-id "$MGMT_SG_ID" --protocol tcp --port 22 --cidr "$OLD_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$MGMT_SG_ID" tcp 443 "$OLD_ADMIN_IP_CIDR")" == "yes" ]] && \
        dry_run_ec2 "remove management HTTPS ${OLD_ADMIN_IP_CIDR}" revoke-security-group-ingress --group-id "$MGMT_SG_ID" --protocol tcp --port 443 --cidr "$OLD_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$MGMT_SG_ID" tcp 55000 "$OLD_ADMIN_IP_CIDR")" == "yes" ]] && \
        dry_run_ec2 "remove management Wazuh API ${OLD_ADMIN_IP_CIDR}" revoke-security-group-ingress --group-id "$MGMT_SG_ID" --protocol tcp --port 55000 --cidr "$OLD_ADMIN_IP_CIDR"
    [[ "$(rule_exists "$DB_SG_ID" tcp 22 "$OLD_ADMIN_IP_CIDR")" == "yes" ]] && \
        dry_run_ec2 "remove direct DB SSH ${OLD_ADMIN_IP_CIDR}" revoke-security-group-ingress --group-id "$DB_SG_ID" --protocol tcp --port 22 --cidr "$OLD_ADMIN_IP_CIDR"

    echo "=== Adding new admin CIDR rules ==="
    authorize_if_missing "$WEB_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR" "prod-web-sg tcp/22 from ${NEW_ADMIN_IP_CIDR}"
    authorize_if_missing "$MGMT_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR" "security-mgmt-sg tcp/22 from ${NEW_ADMIN_IP_CIDR}"
    authorize_if_missing "$MGMT_SG_ID" tcp 443 "$NEW_ADMIN_IP_CIDR" "security-mgmt-sg tcp/443 from ${NEW_ADMIN_IP_CIDR}"
    authorize_if_missing "$MGMT_SG_ID" tcp 55000 "$NEW_ADMIN_IP_CIDR" "security-mgmt-sg tcp/55000 from ${NEW_ADMIN_IP_CIDR}"

    echo "=== Verifying new admin CIDR rules before removal ==="
    require_rule_present "$WEB_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR" "prod-web-sg tcp/22 from ${NEW_ADMIN_IP_CIDR}"
    require_rule_present "$MGMT_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR" "security-mgmt-sg tcp/22 from ${NEW_ADMIN_IP_CIDR}"
    require_rule_present "$MGMT_SG_ID" tcp 443 "$NEW_ADMIN_IP_CIDR" "security-mgmt-sg tcp/443 from ${NEW_ADMIN_IP_CIDR}"
    require_rule_present "$MGMT_SG_ID" tcp 55000 "$NEW_ADMIN_IP_CIDR" "security-mgmt-sg tcp/55000 from ${NEW_ADMIN_IP_CIDR}"
    require_rule_absent "$DB_SG_ID" tcp 22 "$NEW_ADMIN_IP_CIDR" "prod-db-sg direct tcp/22 from ${NEW_ADMIN_IP_CIDR}"

    echo "=== Removing old admin CIDR rules ==="
    revoke_if_present "$WEB_SG_ID" tcp 22 "$OLD_ADMIN_IP_CIDR" "prod-web-sg tcp/22 from ${OLD_ADMIN_IP_CIDR}"
    revoke_if_present "$MGMT_SG_ID" tcp 22 "$OLD_ADMIN_IP_CIDR" "security-mgmt-sg tcp/22 from ${OLD_ADMIN_IP_CIDR}"
    revoke_if_present "$MGMT_SG_ID" tcp 443 "$OLD_ADMIN_IP_CIDR" "security-mgmt-sg tcp/443 from ${OLD_ADMIN_IP_CIDR}"
    revoke_if_present "$MGMT_SG_ID" tcp 55000 "$OLD_ADMIN_IP_CIDR" "security-mgmt-sg tcp/55000 from ${OLD_ADMIN_IP_CIDR}"
    revoke_if_present "$DB_SG_ID" tcp 22 "$OLD_ADMIN_IP_CIDR" "prod-db-sg direct tcp/22 from ${OLD_ADMIN_IP_CIDR}"

    echo "=== Final checks ==="
    require_old_absent_from_all_project_sgs
    require_no_sensitive_public_rules
    require_expected_admin_cidr_usage

    echo "Admin CIDR rotation complete."
}

main "$@"
