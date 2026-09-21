#!/usr/bin/env bash
#
# infra/security.sh
#
# Idempotent script that creates:
#   1. Three Security Groups: prod-web, prod-db, and security-mgmt.
#   2. IAM Role SOC-Middleware-Role.
#   3. IAM managed policy SOC-Middleware-WebSG-Policy scoped to prod-web-sg.
#
# Must be run AFTER provision.sh.
#
# Usage:
#   chmod +x infra/security.sh
#   ADMIN_IP_CIDR="203.0.113.10/32" ./infra/security.sh
#
# Prerequisites:
#   - AWS CLI v2 available
#   - AWS credentials configured outside this repository
#   - AWS profile: soc-project
#   - Region: ap-southeast-1

set -euo pipefail

# -------------------------------------------------------------------
# Mandatory deployment guard configuration
# -------------------------------------------------------------------
AWS_PROFILE="${AWS_PROFILE:-soc-project}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-908157891283}"

PROJECT="soc-automation"
ADMIN_IP_CIDR="${ADMIN_IP_CIDR:-}"

PROD_VPC_CIDR="10.0.0.0/16"
SECURITY_VPC_CIDR="172.16.0.0/16"
SECURITY_MGMT_1A_CIDR="172.16.1.0/24"

PROD_VPC_NAME="${PROJECT}-prod-vpc"
SECURITY_VPC_NAME="${PROJECT}-security-vpc"

WEB_SG_NAME="${PROJECT}-prod-web-sg"
DB_SG_NAME="${PROJECT}-prod-db-sg"
MGMT_SG_NAME="${PROJECT}-security-mgmt-sg"

IAM_ROLE_NAME="SOC-Middleware-Role"
IAM_POLICY_NAME="SOC-Middleware-WebSG-Policy"
INSTANCE_PROFILE_NAME="$IAM_ROLE_NAME"

# -------------------------------------------------------------------
# AWS wrappers: all AWS CLI calls use the required profile and region.
# -------------------------------------------------------------------
aws_ec2() {
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 "$@"
}

aws_iam() {
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" iam "$@"
}

aws_sts() {
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" sts "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

single_id_or_empty() {
    local label="$1"
    local raw="${2:-}"
    local -a ids=()

    if [[ -n "$raw" ]]; then
        read -r -a ids <<< "$raw"
    fi

    if [[ "${#ids[@]}" -gt 1 ]]; then
        fatal "Multiple matches found for ${label}: ${raw}. Refusing to select the first resource."
    fi

    if [[ "${#ids[@]}" -eq 1 ]]; then
        printf '%s\n' "${ids[0]}"
    fi
}

require_admin_cidr() {
    if [[ -z "$ADMIN_IP_CIDR" ]]; then
        fatal "Set ADMIN_IP_CIDR to your admin IP range, for example 203.0.113.10/32."
    fi

    if [[ "$ADMIN_IP_CIDR" == "0.0.0.0/0" ]]; then
        fatal "ADMIN_IP_CIDR must not be 0.0.0.0/0."
    fi

    local cidr_ok
    cidr_ok=$(python3 -c "
import ipaddress, sys
try:
    network = ipaddress.ip_network(sys.argv[1], strict=False)
    print('yes' if network.version == 4 else 'no')
except ValueError:
    print('no')
" "$ADMIN_IP_CIDR")

    if [[ "$cidr_ok" != "yes" ]]; then
        fatal "ADMIN_IP_CIDR must be a valid IPv4 CIDR, got '${ADMIN_IP_CIDR}'."
    fi
}

require_expected_account() {
    echo "=== Pre-flight: verifying AWS identity ==="

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

    echo ""
}

# -------------------------------------------------------------------
# EC2 lookup helpers
# -------------------------------------------------------------------
find_vpc() {
    local name="$1"
    local cidr="$2"
    local raw
    raw=$(aws_ec2 describe-vpcs \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=cidr-block,Values=${cidr}" \
        --query "Vpcs[].VpcId" \
        --output text)
    single_id_or_empty "VPC ${name} (${cidr})" "$raw"
}

find_sg() {
    local name="$1"
    local vpc_id="$2"
    local by_tags
    local by_group_name

    by_tags=$(aws_ec2 describe-security-groups \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=vpc-id,Values=${vpc_id}" \
        --query "SecurityGroups[].GroupId" \
        --output text)

    by_group_name=$(aws_ec2 describe-security-groups \
        --filters "Name=group-name,Values=${name}" \
                  "Name=vpc-id,Values=${vpc_id}" \
        --query "SecurityGroups[].GroupId" \
        --output text)

    if [[ -n "$by_group_name" && -z "$by_tags" ]]; then
        fatal "Security group named ${name} exists in ${vpc_id} without required Project and Name tags."
    fi

    single_id_or_empty "Security Group ${name} in ${vpc_id}" "$by_tags"
}

ingress_rule_exists() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local source="$4"
    local rules

    rules=$(aws_ec2 describe-security-groups \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions" \
        --output json)

    printf '%s' "$rules" | python3 -c "
import sys, json
protocol, port, source = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rules = json.load(sys.stdin)
for rule in rules:
    if rule.get('IpProtocol') != protocol:
        continue
    if rule.get('FromPort') != port or rule.get('ToPort') != port:
        continue
    if '/' in source:
        for cidr in rule.get('IpRanges', []):
            if cidr.get('CidrIp') == source:
                print('yes')
                sys.exit(0)
    else:
        for pair in rule.get('UserIdGroupPairs', []):
            if pair.get('GroupId') == source:
                print('yes')
                sys.exit(0)
print('no')
" "$protocol" "$port" "$source"
}

add_ingress() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local source="$4"
    local label="$5"
    local exists

    exists=$(ingress_rule_exists "$sg_id" "$protocol" "$port" "$source")
    if [[ "$exists" == "yes" ]]; then
        echo "EXISTS   rule ${label}"
        return
    fi

    if [[ "$source" == *"/"* ]]; then
        aws_ec2 authorize-security-group-ingress \
            --group-id "$sg_id" \
            --protocol "$protocol" \
            --port "$port" \
            --cidr "$source" > /dev/null
    else
        aws_ec2 authorize-security-group-ingress \
            --group-id "$sg_id" \
            --protocol "$protocol" \
            --port "$port" \
            --source-group "$source" > /dev/null
    fi

    echo "CREATED  rule ${label}"
}

ensure_sg() {
    local name="$1"
    local vpc_id="$2"
    local description="$3"
    local label="$4"
    local result_var="$5"
    local sg_id

    sg_id=$(find_sg "$name" "$vpc_id")
    if [[ -z "$sg_id" ]]; then
        sg_id=$(aws_ec2 create-security-group \
            --vpc-id "$vpc_id" \
            --group-name "$name" \
            --description "$description" \
            --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${PROJECT}}]" \
            --query "GroupId" \
            --output text)
        echo "CREATED  ${label}: ${sg_id}"
    else
        echo "EXISTS   ${label}: ${sg_id}"
    fi

    printf -v "$result_var" '%s' "$sg_id"
}

# -------------------------------------------------------------------
# IAM lookup and policy helpers
# -------------------------------------------------------------------
require_project_tag() {
    local label="$1"
    local tags_json="$2"
    local tag_ok

    tag_ok=$(printf '%s' "$tags_json" | python3 -c "
import sys, json
tags = json.load(sys.stdin)
print('yes' if any(t.get('Key') == 'Project' and t.get('Value') == 'soc-automation' for t in tags) else 'no')
")

    if [[ "$tag_ok" != "yes" ]]; then
        fatal "${label} exists but is not tagged Project=${PROJECT}; refusing to modify it."
    fi
}

find_project_role() {
    local name="$1"
    local output
    local status
    set +e
    output=$(aws_iam get-role --role-name "$name" --query "Role.RoleName" --output text 2>&1)
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        if [[ "$output" == *"NoSuchEntity"* ]]; then
            return 0
        fi
        fatal "Unable to read IAM role ${name}: ${output}"
    fi

    local tags
    tags=$(aws_iam list-role-tags --role-name "$name" --query "Tags" --output json)
    require_project_tag "IAM role ${name}" "$tags"
    printf '%s\n' "$output"
}

find_project_policy() {
    local policy_name="$1"
    local account_id="$2"
    local arn="arn:aws:iam::${account_id}:policy/${policy_name}"
    local output
    local status
    set +e
    output=$(aws_iam get-policy --policy-arn "$arn" --query "Policy.Arn" --output text 2>&1)
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        if [[ "$output" == *"NoSuchEntity"* ]]; then
            return 0
        fi
        fatal "Unable to read IAM policy ${policy_name}: ${output}"
    fi

    local tags
    tags=$(aws_iam list-policy-tags --policy-arn "$arn" --query "Tags" --output json)
    require_project_tag "IAM policy ${policy_name}" "$tags"
    printf '%s\n' "$output"
}

find_project_instance_profile() {
    local name="$1"
    local output
    local status
    set +e
    output=$(aws_iam get-instance-profile --instance-profile-name "$name" --query "InstanceProfile.InstanceProfileName" --output text 2>&1)
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        if [[ "$output" == *"NoSuchEntity"* ]]; then
            return 0
        fi
        fatal "Unable to read instance profile ${name}: ${output}"
    fi

    local tags
    tags=$(aws_iam list-instance-profile-tags --instance-profile-name "$name" --query "Tags" --output json)
    require_project_tag "Instance profile ${name}" "$tags"
    printf '%s\n' "$output"
}

policy_doc_matches_current() {
    local policy_arn="$1"
    local desired_policy="$2"
    local default_version
    local current_policy

    default_version=$(aws_iam get-policy \
        --policy-arn "$policy_arn" \
        --query "Policy.DefaultVersionId" \
        --output text)

    current_policy=$(aws_iam get-policy-version \
        --policy-arn "$policy_arn" \
        --version-id "$default_version" \
        --query "PolicyVersion.Document" \
        --output json)

    printf '%s' "$current_policy" | python3 -c "
import sys, json
current = json.load(sys.stdin)
desired = json.loads(sys.argv[1])
print('yes' if current == desired else 'no')
" "$desired_policy"
}

ensure_policy_version_capacity() {
    local policy_arn="$1"
    local versions_json
    local version_count
    local oldest_non_default

    versions_json=$(aws_iam list-policy-versions --policy-arn "$policy_arn" --output json)
    version_count=$(printf '%s' "$versions_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('Versions', [])))")

    if [[ "$version_count" -lt 5 ]]; then
        return
    fi

    oldest_non_default=$(printf '%s' "$versions_json" | python3 -c "
import sys, json
versions = [v for v in json.load(sys.stdin).get('Versions', []) if not v.get('IsDefaultVersion')]
if not versions:
    sys.exit(2)
versions.sort(key=lambda v: v.get('CreateDate', ''))
print(versions[0]['VersionId'])
")

    if [[ -z "$oldest_non_default" ]]; then
        fatal "Policy ${policy_arn} already has five versions and no non-default version can be pruned."
    fi

    aws_iam delete-policy-version \
        --policy-arn "$policy_arn" \
        --version-id "$oldest_non_default"
    echo "DELETED  oldest non-default policy version: $oldest_non_default"
}

# -------------------------------------------------------------------
# Pre-flight
# -------------------------------------------------------------------
require_admin_cidr
require_expected_account

echo "=== Pre-flight: resolving VPC IDs ==="
PROD_VPC_ID=$(find_vpc "$PROD_VPC_NAME" "$PROD_VPC_CIDR")
if [[ -z "$PROD_VPC_ID" ]]; then
    fatal "Production VPC '${PROD_VPC_NAME}' not found with CIDR ${PROD_VPC_CIDR}. Run provision.sh first."
fi
echo "Production VPC: $PROD_VPC_ID"

SECURITY_VPC_ID=$(find_vpc "$SECURITY_VPC_NAME" "$SECURITY_VPC_CIDR")
if [[ -z "$SECURITY_VPC_ID" ]]; then
    fatal "Security VPC '${SECURITY_VPC_NAME}' not found with CIDR ${SECURITY_VPC_CIDR}. Run provision.sh first."
fi
echo "Security VPC:   $SECURITY_VPC_ID"
echo ""

# ===================================================================
# 1. Security Groups
# ===================================================================
echo "=== 1. Creating Security Groups ==="

ensure_sg "$WEB_SG_NAME" "$PROD_VPC_ID" \
    "Production web server and SSH brute-force target" \
    "prod-web-sg" WEB_SG_ID
add_ingress "$WEB_SG_ID" "tcp" "22" "$ADMIN_IP_CIDR" "prod-web-sg: SSH 22 from admin CIDR"
add_ingress "$WEB_SG_ID" "tcp" "80" "0.0.0.0/0" "prod-web-sg: HTTP 80 from internet"
add_ingress "$WEB_SG_ID" "tcp" "443" "0.0.0.0/0" "prod-web-sg: HTTPS 443 from internet"
echo ""

ensure_sg "$MGMT_SG_NAME" "$SECURITY_VPC_ID" \
    "Wazuh Manager and Python AI middleware" \
    "security-mgmt-sg" MGMT_SG_ID
add_ingress "$MGMT_SG_ID" "tcp" "22" "$ADMIN_IP_CIDR" "security-mgmt-sg: SSH 22 from admin CIDR"
add_ingress "$MGMT_SG_ID" "tcp" "443" "$ADMIN_IP_CIDR" "security-mgmt-sg: HTTPS 443 from admin CIDR"
add_ingress "$MGMT_SG_ID" "tcp" "1514" "$PROD_VPC_CIDR" "security-mgmt-sg: Wazuh agent 1514 from Production VPC"
add_ingress "$MGMT_SG_ID" "tcp" "1515" "$PROD_VPC_CIDR" "security-mgmt-sg: Wazuh registration 1515 from Production VPC"
add_ingress "$MGMT_SG_ID" "tcp" "55000" "$ADMIN_IP_CIDR" "security-mgmt-sg: Wazuh API 55000 from admin CIDR"
add_ingress "$MGMT_SG_ID" "tcp" "55000" "$SECURITY_MGMT_1A_CIDR" "security-mgmt-sg: Wazuh API 55000 from security mgmt subnet"
echo ""

ensure_sg "$DB_SG_NAME" "$PROD_VPC_ID" \
    "Production private database server" \
    "prod-db-sg" DB_SG_ID
add_ingress "$DB_SG_ID" "tcp" "5432" "$WEB_SG_ID" "prod-db-sg: PostgreSQL 5432 from prod-web-sg"
add_ingress "$DB_SG_ID" "tcp" "22" "$MGMT_SG_ID" "prod-db-sg: SSH 22 from security-mgmt-sg"
# DB administration is routed through security-mgmt-sg. Do not add a direct
# public admin CIDR rule to the private database security group.
echo ""

# ===================================================================
# 2. IAM Role and Managed Policy
# ===================================================================
echo "=== 2. Creating IAM Role and Policy ==="

WEB_SG_ARN="arn:aws:ec2:${AWS_REGION}:${ACCOUNT_ID}:security-group/${WEB_SG_ID}"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${IAM_POLICY_NAME}"
echo "Production web SG ARN: $WEB_SG_ARN"

TRUST_POLICY=$(cat <<'TRUST_EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
TRUST_EOF
)

# TODO(active response): Security Groups are allow-only. They cannot deny one
# malicious IP if a broader allow rule still permits that IP. The active-response
# mechanism will be redesigned separately, and this IAM permission must not be
# claimed as a working per-IP blocking solution.
PERMISSIONS_POLICY=$(cat <<POLICY_EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowDescribeSecurityGroups",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupRules"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowModifyProdWebSGIngressOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "${WEB_SG_ARN}"
        }
    ]
}
POLICY_EOF
)

EXISTING_ROLE=$(find_project_role "$IAM_ROLE_NAME")
if [[ -z "$EXISTING_ROLE" ]]; then
    aws_iam create-role \
        --role-name "$IAM_ROLE_NAME" \
        --assume-role-policy-document "$TRUST_POLICY" \
        --description "Role for SOC middleware lab automation" \
        --tags Key=Project,Value="$PROJECT" \
        --output text \
        --query "Role.Arn" > /dev/null
    echo "CREATED  IAM role: $IAM_ROLE_NAME"
else
    aws_iam update-assume-role-policy \
        --role-name "$IAM_ROLE_NAME" \
        --policy-document "$TRUST_POLICY"
    echo "EXISTS   IAM role: $IAM_ROLE_NAME"
fi

EXISTING_POLICY=$(find_project_policy "$IAM_POLICY_NAME" "$ACCOUNT_ID")
if [[ -z "$EXISTING_POLICY" ]]; then
    POLICY_ARN=$(aws_iam create-policy \
        --policy-name "$IAM_POLICY_NAME" \
        --policy-document "$PERMISSIONS_POLICY" \
        --description "Allows SOC middleware lab role to manage prod-web-sg ingress only" \
        --tags Key=Project,Value="$PROJECT" \
        --query "Policy.Arn" \
        --output text)
    echo "CREATED  IAM policy: $IAM_POLICY_NAME ($POLICY_ARN)"
else
    POLICY_ARN="$EXISTING_POLICY"
    echo "EXISTS   IAM policy: $IAM_POLICY_NAME ($POLICY_ARN)"

    if [[ "$(policy_doc_matches_current "$POLICY_ARN" "$PERMISSIONS_POLICY")" == "yes" ]]; then
        echo "EXISTS   IAM policy document is unchanged; no new version created"
    else
        ensure_policy_version_capacity "$POLICY_ARN"
        aws_iam create-policy-version \
            --policy-arn "$POLICY_ARN" \
            --policy-document "$PERMISSIONS_POLICY" \
            --set-as-default > /dev/null
        echo "UPDATED  IAM policy default version"
    fi
fi

ATTACHED_POLICY_ARN=$(aws_iam list-attached-role-policies \
    --role-name "$IAM_ROLE_NAME" \
    --query "AttachedPolicies[?PolicyName=='${IAM_POLICY_NAME}'].PolicyArn | [0]" \
    --output text 2>/dev/null | grep -v "^None$" || true)

if [[ -z "$ATTACHED_POLICY_ARN" ]]; then
    aws_iam attach-role-policy --role-name "$IAM_ROLE_NAME" --policy-arn "$POLICY_ARN"
    echo "ATTACHED policy ${IAM_POLICY_NAME} to role ${IAM_ROLE_NAME}"
else
    echo "EXISTS   policy ${IAM_POLICY_NAME} attached to role ${IAM_ROLE_NAME}"
fi

EXISTING_PROFILE=$(find_project_instance_profile "$INSTANCE_PROFILE_NAME")
if [[ -z "$EXISTING_PROFILE" ]]; then
    aws_iam create-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" \
        --tags Key=Project,Value="$PROJECT" > /dev/null
    echo "CREATED  instance profile: $INSTANCE_PROFILE_NAME"
else
    echo "EXISTS   instance profile: $INSTANCE_PROFILE_NAME"
fi

PROFILE_ROLES=$(aws_iam get-instance-profile \
    --instance-profile-name "$INSTANCE_PROFILE_NAME" \
    --query "InstanceProfile.Roles[].RoleName" \
    --output text)

if [[ -z "$PROFILE_ROLES" ]]; then
    aws_iam add-role-to-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" \
        --role-name "$IAM_ROLE_NAME"
    echo "BOUND    role ${IAM_ROLE_NAME} to instance profile ${INSTANCE_PROFILE_NAME}"
elif [[ "$PROFILE_ROLES" == "$IAM_ROLE_NAME" ]]; then
    echo "EXISTS   role ${IAM_ROLE_NAME} bound to instance profile ${INSTANCE_PROFILE_NAME}"
else
    fatal "Instance profile ${INSTANCE_PROFILE_NAME} contains unexpected role(s): ${PROFILE_ROLES}"
fi

echo ""

# ===================================================================
# Summary
# ===================================================================
echo "==========================================="
echo "  Security and IAM Provisioning Complete"
echo "==========================================="
echo ""
echo "  Account:            $ACCOUNT_ID"
echo "  Profile:            $AWS_PROFILE"
echo "  Region:             $AWS_REGION"
echo ""
echo "  Security Groups:"
echo "    prod-web-sg (Production VPC):        $WEB_SG_ID"
echo "    prod-db-sg (Production VPC):         $DB_SG_ID"
echo "    security-mgmt-sg (Security VPC):     $MGMT_SG_ID"
echo ""
echo "  IAM:"
echo "    Role:             $IAM_ROLE_NAME"
echo "    Policy:           $IAM_POLICY_NAME"
echo "    Instance Profile: $INSTANCE_PROFILE_NAME"
echo "    Policy Resource:  $WEB_SG_ARN"
echo ""
echo "  Next steps:"
echo "    - Launch EC2 instances after validating instance parameters"
echo "    - Deploy Wazuh and middleware"
echo "==========================================="
