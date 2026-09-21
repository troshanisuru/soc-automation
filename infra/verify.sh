#!/usr/bin/env bash
#
# infra/verify.sh
#
# Read-only verification for the PDF-aligned dual-VPC, single-AZ topology.
# Checks resources created by provision.sh and security.sh, then keeps
# non-blocking warnings for EC2 reachability if instances do not exist yet.
#
# Usage:
#   chmod +x infra/verify.sh
#   ADMIN_IP_CIDR="203.0.113.10/32" ./infra/verify.sh

set -euo pipefail

# -------------------------------------------------------------------
# Mandatory deployment guard configuration
# -------------------------------------------------------------------
AWS_PROFILE="${AWS_PROFILE:-soc-project}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-908157891283}"

PROJECT="soc-automation"
ADMIN_IP_CIDR="${ADMIN_IP_CIDR:-}"
AZ_A="${AWS_REGION}a"

PROD_VPC_CIDR="10.0.0.0/16"
SECURITY_VPC_CIDR="172.16.0.0/16"
PROD_PUBLIC_1A_CIDR="10.0.1.0/24"
PROD_PRIVATE_1A_CIDR="10.0.2.0/24"
SECURITY_MGMT_1A_CIDR="172.16.1.0/24"

PROD_VPC_NAME="${PROJECT}-prod-vpc"
SECURITY_VPC_NAME="${PROJECT}-security-vpc"
PROD_PUBLIC_1A_NAME="${PROJECT}-prod-public-1a"
PROD_PRIVATE_1A_NAME="${PROJECT}-prod-private-1a"
SECURITY_MGMT_1A_NAME="${PROJECT}-security-mgmt-1a"
PROD_IGW_NAME="${PROJECT}-prod-igw"
SECURITY_IGW_NAME="${PROJECT}-security-igw"
PEERING_NAME="${PROJECT}-prod-to-security-peering"
PROD_PUB_RT_NAME="${PROJECT}-prod-public-rt"
PROD_PRIV_RT_NAME="${PROJECT}-prod-private-rt"
SECURITY_MGMT_RT_NAME="${PROJECT}-security-mgmt-rt"

WEB_SG_NAME="${PROJECT}-prod-web-sg"
DB_SG_NAME="${PROJECT}-prod-db-sg"
MGMT_SG_NAME="${PROJECT}-security-mgmt-sg"

IAM_ROLE_NAME="SOC-Middleware-Role"
IAM_POLICY_NAME="SOC-Middleware-WebSG-Policy"
INSTANCE_PROFILE_NAME="$IAM_ROLE_NAME"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

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

fatal() {
    echo "FATAL: $*" >&2
    exit 1
}

section() {
    echo ""
    echo "==========================================="
    echo "  $1"
    echo "==========================================="
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
        fatal "Set ADMIN_IP_CIDR before running verification."
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
        fatal "Expected AWS account ${EXPECTED_AWS_ACCOUNT_ID}, got ${ACCOUNT_ID}. Stopping before verification."
    fi
}

# -------------------------------------------------------------------
# Lookup helpers
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

find_subnet() {
    local name="$1"
    local cidr="$2"
    local expected_vpc_id="$3"
    local raw
    raw=$(aws_ec2 describe-subnets \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=cidr-block,Values=${cidr}" \
                  "Name=vpc-id,Values=${expected_vpc_id}" \
                  "Name=availability-zone,Values=${AZ_A}" \
        --query "Subnets[].SubnetId" \
        --output text)
    single_id_or_empty "Subnet ${name} (${cidr}, ${AZ_A})" "$raw"
}

find_sg() {
    local name="$1"
    local vpc_id="$2"
    local raw
    raw=$(aws_ec2 describe-security-groups \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=vpc-id,Values=${vpc_id}" \
        --query "SecurityGroups[].GroupId" \
        --output text)
    single_id_or_empty "Security Group ${name} in ${vpc_id}" "$raw"
}

find_rtb() {
    local name="$1"
    local vpc_id="$2"
    local raw
    raw=$(aws_ec2 describe-route-tables \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=vpc-id,Values=${vpc_id}" \
        --query "RouteTables[].RouteTableId" \
        --output text)
    single_id_or_empty "Route Table ${name} in ${vpc_id}" "$raw"
}

find_igw() {
    local name="$1"
    local raw
    raw=$(aws_ec2 describe-internet-gateways \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
        --query "InternetGateways[].InternetGatewayId" \
        --output text)
    single_id_or_empty "Internet Gateway ${name}" "$raw"
}

find_peering() {
    local prod_vpc_id="$1"
    local security_vpc_id="$2"
    local peering_json

    peering_json=$(aws_ec2 describe-vpc-peering-connections \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${PEERING_NAME}" \
                  "Name=status-code,Values=active,pending-acceptance,provisioning" \
        --output json)

    printf '%s' "$peering_json" | python3 -c "
import sys, json
prod = sys.argv[1]
security = sys.argv[2]
data = json.load(sys.stdin)
matches = []
conflicts = []
for pcx in data.get('VpcPeeringConnections', []):
    requester = pcx.get('RequesterVpcInfo', {}).get('VpcId')
    accepter = pcx.get('AccepterVpcInfo', {}).get('VpcId')
    pcx_id = pcx.get('VpcPeeringConnectionId')
    if {requester, accepter} == {prod, security}:
        matches.append(pcx_id)
    else:
        conflicts.append(pcx_id)
if conflicts:
    print('ERROR: Peering name/tag matches unexpected VPCs: ' + ' '.join(conflicts), file=sys.stderr)
    sys.exit(2)
if len(matches) > 1:
    print('ERROR: Multiple matching peering connections: ' + ' '.join(matches), file=sys.stderr)
    sys.exit(2)
if matches:
    print(matches[0])
" "$prod_vpc_id" "$security_vpc_id"
}

route_target_for_destination() {
    local rtb_id="$1"
    local dest_cidr="$2"
    local route_json

    route_json=$(aws_ec2 describe-route-tables \
        --route-table-ids "$rtb_id" \
        --query "RouteTables[0].Routes[?DestinationCidrBlock=='${dest_cidr}']" \
        --output json 2>/dev/null)

    printf '%s' "$route_json" | python3 -c "
import sys, json
routes = json.load(sys.stdin)
if not routes:
    sys.exit(0)
if len(routes) > 1:
    print('ERROR: Multiple routes found for destination ' + sys.argv[1], file=sys.stderr)
    sys.exit(2)
route = routes[0]
for field in (
    'GatewayId',
    'VpcPeeringConnectionId',
    'NatGatewayId',
    'TransitGatewayId',
    'NetworkInterfaceId',
    'InstanceId',
    'EgressOnlyInternetGatewayId',
    'LocalGatewayId',
    'CarrierGatewayId',
    'CoreNetworkArn'
):
    if route.get(field):
        print(route[field])
        sys.exit(0)
print('UNKNOWN')
" "$dest_cidr"
}

iam_role_exists() {
    local output
    local status
    set +e
    output=$(aws_iam get-role --role-name "$IAM_ROLE_NAME" --query "Role.RoleName" --output text 2>/dev/null)
    status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
        printf '%s\n' "$output"
    fi
}

iam_policy_arn() {
    local arn="arn:aws:iam::${ACCOUNT_ID}:policy/${IAM_POLICY_NAME}"
    local output
    local status
    set +e
    output=$(aws_iam get-policy --policy-arn "$arn" --query "Policy.Arn" --output text 2>/dev/null)
    status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
        printf '%s\n' "$output"
    fi
}

# -------------------------------------------------------------------
# Check helpers
# -------------------------------------------------------------------
check_required_az() {
    local az_json
    local az_ok
    az_json=$(aws_ec2 describe-availability-zones \
        --all-availability-zones \
        --filters "Name=zone-name,Values=${AZ_A}" \
        --output json)
    az_ok=$(printf '%s' "$az_json" | python3 -c "
import sys, json
target = sys.argv[1]
data = json.load(sys.stdin)
for az in data.get('AvailabilityZones', []):
    opt_in = az.get('OptInStatus') or 'opt-in-not-required'
    if az.get('ZoneName') == target and az.get('State') == 'available' and opt_in in ('opt-in-not-required', 'opted-in'):
        print('yes')
        sys.exit(0)
print('no')
" "$AZ_A")

    if [[ "$az_ok" == "yes" ]]; then
        pass "Required AZ ${AZ_A} is available"
    else
        fail "Required AZ ${AZ_A} unavailable" "Subnets must not be created in a different AZ silently"
    fi
}

check_vpc_dns() {
    local vpc_id="$1"
    local label="$2"
    local dns_support
    local dns_hostnames

    dns_support=$(aws_ec2 describe-vpc-attribute \
        --vpc-id "$vpc_id" \
        --attribute enableDnsSupport \
        --query "EnableDnsSupport.Value" \
        --output text 2>/dev/null)
    dns_hostnames=$(aws_ec2 describe-vpc-attribute \
        --vpc-id "$vpc_id" \
        --attribute enableDnsHostnames \
        --query "EnableDnsHostnames.Value" \
        --output text 2>/dev/null)

    if [[ "$dns_support" == "True" && "$dns_hostnames" == "True" ]]; then
        pass "$label DNS support and hostnames enabled"
    else
        fail "$label DNS attributes" "enableDnsSupport=${dns_support} enableDnsHostnames=${dns_hostnames}; both must be True"
    fi
}

check_subnet() {
    local name="$1"
    local expected_cidr="$2"
    local expected_vpc_id="$3"
    local expected_public_ip="$4"
    local result_var="$5"
    local subnet_id
    local map_public

    subnet_id=$(find_subnet "$name" "$expected_cidr" "$expected_vpc_id")
    if [[ -z "$subnet_id" ]]; then
        fail "Subnet ${name} missing" "Expected Project=${PROJECT}, Name=${name}, CIDR=${expected_cidr}, VPC=${expected_vpc_id}, AZ=${AZ_A}"
        return
    fi

    pass "Subnet ${name} exists with expected CIDR, VPC, tags, and AZ"

    map_public=$(aws_ec2 describe-subnets \
        --subnet-ids "$subnet_id" \
        --query "Subnets[0].MapPublicIpOnLaunch" \
        --output text 2>/dev/null)

    if [[ "$map_public" == "$expected_public_ip" ]]; then
        pass "Subnet ${name} MapPublicIpOnLaunch is ${expected_public_ip}"
    else
        fail "Subnet ${name} public IP auto-assign mismatch" "Expected ${expected_public_ip}, got ${map_public}"
    fi

    printf -v "$result_var" '%s' "$subnet_id"
}

check_igw() {
    local name="$1"
    local expected_vpc_id="$2"
    local result_var="$3"
    local igw_id
    local attached_vpc

    igw_id=$(find_igw "$name")
    if [[ -z "$igw_id" ]]; then
        fail "IGW ${name} missing" "Expected Project=${PROJECT} and Name=${name}"
        return
    fi

    attached_vpc=$(aws_ec2 describe-internet-gateways \
        --internet-gateway-ids "$igw_id" \
        --query "InternetGateways[0].Attachments[0].VpcId" \
        --output text 2>/dev/null | grep -v "^None$" || true)

    if [[ "$attached_vpc" == "$expected_vpc_id" ]]; then
        pass "IGW ${name} attached to expected VPC"
    else
        fail "IGW ${name} attachment mismatch" "Expected ${expected_vpc_id}, got ${attached_vpc:-DETACHED}"
    fi

    printf -v "$result_var" '%s' "$igw_id"
}

store_rtb() {
    local name="$1"
    local vpc_id="$2"
    local result_var="$3"
    local rtb_id

    rtb_id=$(find_rtb "$name" "$vpc_id")
    if [[ -n "$rtb_id" ]]; then
        pass "Route table ${name} exists in expected VPC"
        printf -v "$result_var" '%s' "$rtb_id"
    else
        fail "Route table ${name} missing" "Expected Project=${PROJECT}, Name=${name}, VPC=${vpc_id}"
    fi
}

check_route_target() {
    local rtb_id="$1"
    local dest_cidr="$2"
    local expected_target="$3"
    local label="$4"
    local current_target

    current_target=$(route_target_for_destination "$rtb_id" "$dest_cidr")
    if [[ "$current_target" == "$expected_target" ]]; then
        pass "Route ${dest_cidr} targets ${expected_target} in ${label}"
    elif [[ -z "$current_target" ]]; then
        fail "Route ${dest_cidr} missing in ${label}" "Expected target ${expected_target}"
    else
        fail "Route ${dest_cidr} conflict in ${label}" "Expected target ${expected_target}, got ${current_target}"
    fi
}

check_sg_rule() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local source="$4"
    local label="$5"
    local rules
    local found

    rules=$(aws_ec2 describe-security-groups \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions" \
        --output json 2>/dev/null)

    found=$(printf '%s' "$rules" | python3 -c "
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
" "$protocol" "$port" "$source")

    if [[ "$found" == "yes" ]]; then
        pass "SG rule: ${label}"
    else
        fail "SG rule missing: ${label}" "Expected ${protocol}/${port} from ${source} on ${sg_id}"
    fi
}

check_sg_rule_absent() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local source="$4"
    local label="$5"
    local rules
    local found

    rules=$(aws_ec2 describe-security-groups \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions" \
        --output json 2>/dev/null)

    found=$(printf '%s' "$rules" | python3 -c "
import sys, json
protocol, port, source = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rules = json.load(sys.stdin)
for rule in rules:
    if rule.get('IpProtocol') != protocol:
        continue
    if rule.get('FromPort') != port or rule.get('ToPort') != port:
        continue
    for cidr in rule.get('IpRanges', []):
        if cidr.get('CidrIp') == source:
            print('yes')
            sys.exit(0)
print('no')
" "$protocol" "$port" "$source")

    if [[ "$found" == "no" ]]; then
        pass "SG excludes ${label}"
    else
        fail "Unsafe SG rule present: ${label}" "Remove ${protocol}/${port} from ${source} on ${sg_id}"
    fi
}

find_instance_in_sg() {
    local sg_id="$1"
    aws_ec2 describe-instances \
        --filters "Name=instance.group-id,Values=${sg_id}" \
                  "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].InstanceId" \
        --output text 2>/dev/null | grep -v "^None$" || true
}

get_public_ip() {
    local instance_id="$1"
    aws_ec2 describe-instances \
        --instance-ids "$instance_id" \
        --query "Reservations[0].Instances[0].PublicIpAddress" \
        --output text 2>/dev/null | grep -v "^None$" || true
}

get_instance_subnet() {
    local instance_id="$1"
    aws_ec2 describe-instances \
        --instance-ids "$instance_id" \
        --query "Reservations[0].Instances[0].SubnetId" \
        --output text 2>/dev/null | grep -v "^None$" || true
}

check_project_tag() {
    local label="$1"
    local tags_json="$2"
    local tag_ok

    tag_ok=$(printf '%s' "$tags_json" | python3 -c "
import sys, json
tags = json.load(sys.stdin)
print('yes' if any(t.get('Key') == 'Project' and t.get('Value') == 'soc-automation' for t in tags) else 'no')
")

    if [[ "$tag_ok" == "yes" ]]; then
        pass "${label} has Project=${PROJECT} tag"
    else
        fail "${label} missing Project tag" "Expected Project=${PROJECT}"
    fi
}

# -------------------------------------------------------------------
# Verification
# -------------------------------------------------------------------
require_admin_cidr
require_expected_account

section "1. Account and AZ"
check_required_az

section "2. VPCs"

PROD_VPC_ID=$(find_vpc "$PROD_VPC_NAME" "$PROD_VPC_CIDR")
if [[ -n "$PROD_VPC_ID" ]]; then
    pass "Production VPC exists: $PROD_VPC_ID ($PROD_VPC_CIDR)"
    check_vpc_dns "$PROD_VPC_ID" "Production VPC"
else
    fail "Production VPC missing" "Expected '${PROD_VPC_NAME}' with CIDR ${PROD_VPC_CIDR}"
fi

SECURITY_VPC_ID=$(find_vpc "$SECURITY_VPC_NAME" "$SECURITY_VPC_CIDR")
if [[ -n "$SECURITY_VPC_ID" ]]; then
    pass "Security VPC exists: $SECURITY_VPC_ID ($SECURITY_VPC_CIDR)"
    check_vpc_dns "$SECURITY_VPC_ID" "Security VPC"
else
    fail "Security VPC missing" "Expected '${SECURITY_VPC_NAME}' with CIDR ${SECURITY_VPC_CIDR}"
fi

if [[ -z "${PROD_VPC_ID:-}" || -z "${SECURITY_VPC_ID:-}" ]]; then
    echo ""
    echo "FATAL: Required VPCs are missing. Cannot continue verification."
    exit 1
fi

section "3. Subnets"

PROD_PUBLIC_1A_ID=""
PROD_PRIVATE_1A_ID=""
SECURITY_MGMT_1A_ID=""

check_subnet "$PROD_PUBLIC_1A_NAME" "$PROD_PUBLIC_1A_CIDR" "$PROD_VPC_ID" "True" PROD_PUBLIC_1A_ID
check_subnet "$PROD_PRIVATE_1A_NAME" "$PROD_PRIVATE_1A_CIDR" "$PROD_VPC_ID" "False" PROD_PRIVATE_1A_ID
check_subnet "$SECURITY_MGMT_1A_NAME" "$SECURITY_MGMT_1A_CIDR" "$SECURITY_VPC_ID" "True" SECURITY_MGMT_1A_ID

section "4. Internet Gateways"

PROD_IGW_ID=""
SECURITY_IGW_ID=""
check_igw "$PROD_IGW_NAME" "$PROD_VPC_ID" PROD_IGW_ID
check_igw "$SECURITY_IGW_NAME" "$SECURITY_VPC_ID" SECURITY_IGW_ID

section "5. VPC Peering"

PEERING_ID=$(find_peering "$PROD_VPC_ID" "$SECURITY_VPC_ID")
if [[ -n "$PEERING_ID" ]]; then
    PEERING_STATUS=$(aws_ec2 describe-vpc-peering-connections \
        --vpc-peering-connection-ids "$PEERING_ID" \
        --query "VpcPeeringConnections[0].Status.Code" \
        --output text 2>/dev/null)

    if [[ "$PEERING_STATUS" == "active" ]]; then
        pass "Peering ${PEERING_ID} is active"
    else
        fail "Peering ${PEERING_ID} is not active" "Status is ${PEERING_STATUS}"
    fi
else
    fail "VPC peering missing" "Expected Project=${PROJECT}, Name=${PEERING_NAME}, Production <-> Security"
fi

section "6. Route Tables"

PROD_PUB_RTB_ID=""
PROD_PRIV_RTB_ID=""
SECURITY_MGMT_RTB_ID=""

store_rtb "$PROD_PUB_RT_NAME" "$PROD_VPC_ID" PROD_PUB_RTB_ID
store_rtb "$PROD_PRIV_RT_NAME" "$PROD_VPC_ID" PROD_PRIV_RTB_ID
store_rtb "$SECURITY_MGMT_RT_NAME" "$SECURITY_VPC_ID" SECURITY_MGMT_RTB_ID

if [[ -n "$PROD_PUB_RTB_ID" && -n "$PROD_IGW_ID" ]]; then
    check_route_target "$PROD_PUB_RTB_ID" "0.0.0.0/0" "$PROD_IGW_ID" "$PROD_PUB_RT_NAME"
fi
if [[ -n "$SECURITY_MGMT_RTB_ID" && -n "$SECURITY_IGW_ID" ]]; then
    check_route_target "$SECURITY_MGMT_RTB_ID" "0.0.0.0/0" "$SECURITY_IGW_ID" "$SECURITY_MGMT_RT_NAME"
fi
if [[ -n "${PEERING_ID:-}" ]]; then
    [[ -n "$PROD_PUB_RTB_ID" ]] && check_route_target "$PROD_PUB_RTB_ID" "$SECURITY_VPC_CIDR" "$PEERING_ID" "$PROD_PUB_RT_NAME"
    [[ -n "$PROD_PRIV_RTB_ID" ]] && check_route_target "$PROD_PRIV_RTB_ID" "$SECURITY_VPC_CIDR" "$PEERING_ID" "$PROD_PRIV_RT_NAME"
    [[ -n "$SECURITY_MGMT_RTB_ID" ]] && check_route_target "$SECURITY_MGMT_RTB_ID" "$PROD_VPC_CIDR" "$PEERING_ID" "$SECURITY_MGMT_RT_NAME"
fi

section "7. Security Groups"

WEB_SG_ID=$(find_sg "$WEB_SG_NAME" "$PROD_VPC_ID")
DB_SG_ID=$(find_sg "$DB_SG_NAME" "$PROD_VPC_ID")
MGMT_SG_ID=$(find_sg "$MGMT_SG_NAME" "$SECURITY_VPC_ID")

if [[ -n "$WEB_SG_ID" ]]; then
    pass "prod-web-sg exists: $WEB_SG_ID"
    check_sg_rule "$WEB_SG_ID" "tcp" "22" "$ADMIN_IP_CIDR" "prod-web-sg SSH from admin CIDR"
    check_sg_rule "$WEB_SG_ID" "tcp" "80" "0.0.0.0/0" "prod-web-sg HTTP from internet"
    check_sg_rule "$WEB_SG_ID" "tcp" "443" "0.0.0.0/0" "prod-web-sg HTTPS from internet"
    check_sg_rule_absent "$WEB_SG_ID" "tcp" "22" "0.0.0.0/0" "prod-web-sg SSH from 0.0.0.0/0"
else
    fail "prod-web-sg missing" "Expected '${WEB_SG_NAME}' in Production VPC"
fi

if [[ -n "$MGMT_SG_ID" ]]; then
    pass "security-mgmt-sg exists: $MGMT_SG_ID"
    check_sg_rule "$MGMT_SG_ID" "tcp" "22" "$ADMIN_IP_CIDR" "security-mgmt-sg SSH from admin CIDR"
    check_sg_rule "$MGMT_SG_ID" "tcp" "443" "$ADMIN_IP_CIDR" "security-mgmt-sg HTTPS from admin CIDR"
    check_sg_rule "$MGMT_SG_ID" "tcp" "1514" "$PROD_VPC_CIDR" "security-mgmt-sg Wazuh agent traffic from Production VPC"
    check_sg_rule "$MGMT_SG_ID" "tcp" "1515" "$PROD_VPC_CIDR" "security-mgmt-sg Wazuh registration from Production VPC"
    check_sg_rule "$MGMT_SG_ID" "tcp" "55000" "$ADMIN_IP_CIDR" "security-mgmt-sg Wazuh API from admin CIDR"
    check_sg_rule "$MGMT_SG_ID" "tcp" "55000" "$SECURITY_MGMT_1A_CIDR" "security-mgmt-sg Wazuh API from security mgmt subnet"
    check_sg_rule_absent "$MGMT_SG_ID" "tcp" "22" "0.0.0.0/0" "security-mgmt-sg SSH from 0.0.0.0/0"
    check_sg_rule_absent "$MGMT_SG_ID" "tcp" "443" "0.0.0.0/0" "security-mgmt-sg HTTPS from 0.0.0.0/0"
    check_sg_rule_absent "$MGMT_SG_ID" "tcp" "55000" "0.0.0.0/0" "security-mgmt-sg Wazuh API from 0.0.0.0/0"
else
    fail "security-mgmt-sg missing" "Expected '${MGMT_SG_NAME}' in Security VPC"
fi

if [[ -n "$DB_SG_ID" ]]; then
    pass "prod-db-sg exists: $DB_SG_ID"
    [[ -n "$WEB_SG_ID" ]] && check_sg_rule "$DB_SG_ID" "tcp" "5432" "$WEB_SG_ID" "prod-db-sg PostgreSQL from prod-web-sg"
    [[ -n "$MGMT_SG_ID" ]] && check_sg_rule "$DB_SG_ID" "tcp" "22" "$MGMT_SG_ID" "prod-db-sg SSH from security-mgmt-sg"
    check_sg_rule_absent "$DB_SG_ID" "tcp" "22" "$ADMIN_IP_CIDR" "prod-db-sg direct SSH from admin CIDR"
    check_sg_rule_absent "$DB_SG_ID" "tcp" "22" "0.0.0.0/0" "prod-db-sg SSH from 0.0.0.0/0"
    check_sg_rule_absent "$DB_SG_ID" "tcp" "5432" "0.0.0.0/0" "prod-db-sg PostgreSQL from 0.0.0.0/0"
else
    fail "prod-db-sg missing" "Expected '${DB_SG_NAME}' in Production VPC"
fi

section "8. IAM Role and Policy"

ROLE_EXISTS=$(iam_role_exists)
if [[ -n "$ROLE_EXISTS" ]]; then
    pass "IAM role exists: $IAM_ROLE_NAME"

    ROLE_TAGS=$(aws_iam list-role-tags --role-name "$IAM_ROLE_NAME" --query "Tags" --output json)
    check_project_tag "IAM role ${IAM_ROLE_NAME}" "$ROLE_TAGS"

    TRUST_PRINCIPAL=$(aws_iam get-role \
        --role-name "$IAM_ROLE_NAME" \
        --query "Role.AssumeRolePolicyDocument" \
        --output json 2>/dev/null | python3 -c "
import sys, json
doc = json.load(sys.stdin)
for stmt in doc.get('Statement', []):
    principal = stmt.get('Principal', {})
    service = principal.get('Service', '')
    services = service if isinstance(service, list) else [service]
    if 'ec2.amazonaws.com' in services:
        print('yes')
        sys.exit(0)
print('no')
")
    if [[ "$TRUST_PRINCIPAL" == "yes" ]]; then
        pass "IAM trust policy allows EC2"
    else
        fail "IAM trust policy misconfigured" "Expected ec2.amazonaws.com trust principal"
    fi
else
    fail "IAM role ${IAM_ROLE_NAME} missing" "Run security.sh first"
fi

ATTACHED_POLICY_ARN=""
if [[ -n "$ROLE_EXISTS" ]]; then
    ATTACHED_POLICY_ARN=$(aws_iam list-attached-role-policies \
        --role-name "$IAM_ROLE_NAME" \
        --query "AttachedPolicies[?PolicyName=='${IAM_POLICY_NAME}'].PolicyArn | [0]" \
        --output text 2>/dev/null | grep -v "^None$" || true)
fi

if [[ -n "$ATTACHED_POLICY_ARN" ]]; then
    pass "Policy ${IAM_POLICY_NAME} attached to role"
    POLICY_TAGS=$(aws_iam list-policy-tags --policy-arn "$ATTACHED_POLICY_ARN" --query "Tags" --output json)
    check_project_tag "IAM policy ${IAM_POLICY_NAME}" "$POLICY_TAGS"

    if [[ -n "${WEB_SG_ID:-}" ]]; then
        EXPECTED_SG_ARN="arn:aws:ec2:${AWS_REGION}:${ACCOUNT_ID}:security-group/${WEB_SG_ID}"
        POLICY_VERSION=$(aws_iam get-policy \
            --policy-arn "$ATTACHED_POLICY_ARN" \
            --query "Policy.DefaultVersionId" \
            --output text 2>/dev/null)
        POLICY_DOC=$(aws_iam get-policy-version \
            --policy-arn "$ATTACHED_POLICY_ARN" \
            --version-id "$POLICY_VERSION" \
            --query "PolicyVersion.Document" \
            --output json 2>/dev/null)
        RESOURCE_MATCH=$(printf '%s' "$POLICY_DOC" | python3 -c "
import sys, json
doc = json.load(sys.stdin)
target = sys.argv[1]
modify_actions = {
    'ec2:authorizesecuritygroupingress',
    'ec2:revokesecuritygroupingress',
}
found_target = False
bad_resources = []
for stmt in doc.get('Statement', []):
    actions = stmt.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    normalized_actions = {a.lower() for a in actions}
    if not (normalized_actions & modify_actions):
        continue
    resources = stmt.get('Resource', [])
    if isinstance(resources, str):
        resources = [resources]
    if resources == [target]:
        found_target = True
    else:
        bad_resources.extend(resources)
print('yes' if found_target and not bad_resources else 'no')
" "$EXPECTED_SG_ARN")
        if [[ "$RESOURCE_MATCH" == "yes" ]]; then
            pass "IAM modify permissions target prod-web-sg only"
        else
            fail "IAM policy Resource is not scoped to prod-web-sg only" "Expected modify actions to use only ${EXPECTED_SG_ARN}"
        fi
    fi
else
    fail "Policy ${IAM_POLICY_NAME} not attached" "Expected policy attached to ${IAM_ROLE_NAME}"
fi

PROFILE_NAME=$(aws_iam get-instance-profile \
    --instance-profile-name "$INSTANCE_PROFILE_NAME" \
    --query "InstanceProfile.InstanceProfileName" \
    --output text 2>/dev/null || true)
if [[ "$PROFILE_NAME" == "$INSTANCE_PROFILE_NAME" ]]; then
    pass "Instance profile exists: $INSTANCE_PROFILE_NAME"
    PROFILE_TAGS=$(aws_iam list-instance-profile-tags --instance-profile-name "$INSTANCE_PROFILE_NAME" --query "Tags" --output json)
    check_project_tag "Instance profile ${INSTANCE_PROFILE_NAME}" "$PROFILE_TAGS"
else
    fail "Instance profile missing" "Expected ${INSTANCE_PROFILE_NAME}"
fi

section "9. EC2 Reachability"

if [[ -n "${WEB_SG_ID:-}" ]]; then
    WEB_INSTANCE_ID=$(find_instance_in_sg "$WEB_SG_ID")
    if [[ -n "$WEB_INSTANCE_ID" ]]; then
        WEB_SUBNET=$(get_instance_subnet "$WEB_INSTANCE_ID")
        WEB_PUBLIC_IP=$(get_public_ip "$WEB_INSTANCE_ID")
        if [[ "$WEB_SUBNET" == "$PROD_PUBLIC_1A_ID" ]]; then
            pass "Web instance is in prod-public-1a"
        else
            fail "Web instance subnet mismatch" "Expected ${PROD_PUBLIC_1A_ID}, got ${WEB_SUBNET}"
        fi
        if [[ -n "$WEB_PUBLIC_IP" ]]; then
            pass "Web instance has public IP"
        else
            fail "Web instance has no public IP" "Production web target should be in public subnet"
        fi
    else
        warn "No running web instance found in ${WEB_SG_NAME}; skipping live reachability checks"
    fi
fi

if [[ -n "${DB_SG_ID:-}" ]]; then
    DB_INSTANCE_ID=$(find_instance_in_sg "$DB_SG_ID")
    if [[ -n "$DB_INSTANCE_ID" ]]; then
        DB_SUBNET=$(get_instance_subnet "$DB_INSTANCE_ID")
        DB_PUBLIC_IP=$(get_public_ip "$DB_INSTANCE_ID")
        if [[ "$DB_SUBNET" == "$PROD_PRIVATE_1A_ID" ]]; then
            pass "DB instance is in prod-private-1a"
        else
            fail "DB instance subnet mismatch" "Expected ${PROD_PRIVATE_1A_ID}, got ${DB_SUBNET}"
        fi
        if [[ -z "$DB_PUBLIC_IP" ]]; then
            pass "DB instance has no public IP"
        else
            fail "DB instance has public IP" "DB server must remain private"
        fi
    else
        warn "No running DB instance found in ${DB_SG_NAME}; skipping live reachability checks"
    fi
fi

section "Verification Results"

echo ""
echo "  Passed:   $PASS_COUNT"
echo "  Failed:   $FAIL_COUNT"
echo "  Warnings: $WARN_COUNT"
echo ""

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "  VERIFICATION FAILED"
    exit 1
fi

if [[ "$WARN_COUNT" -gt 0 ]]; then
    echo "  Verification passed with non-blocking warnings."
else
    echo "  ALL CHECKS PASSED"
fi

exit 0
