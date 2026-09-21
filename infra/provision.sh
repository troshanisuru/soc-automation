#!/usr/bin/env bash
#
# infra/provision.sh
#
# Idempotent provisioning script for the PDF-aligned dual-VPC network topology.
# Creates: VPCs, subnets, internet gateways, route tables, and VPC peering.
# Does NOT create: Security Groups, IAM Roles, NAT Gateways, or EC2 instances.
#
# Usage:
#   chmod +x infra/provision.sh
#   AWS_PROFILE=soc-project AWS_REGION=ap-southeast-1 ./infra/provision.sh
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
AZ_A="${AWS_REGION}a"

# Production VPC
PROD_VPC_CIDR="10.0.0.0/16"
PROD_PUBLIC_1A_CIDR="10.0.1.0/24"
PROD_PRIVATE_1A_CIDR="10.0.2.0/24"

# Security VPC
SECURITY_VPC_CIDR="172.16.0.0/16"
SECURITY_MGMT_1A_CIDR="172.16.1.0/24"

PROD_VPC_NAME="${PROJECT}-prod-vpc"
SECURITY_VPC_NAME="${PROJECT}-security-vpc"
PROD_IGW_NAME="${PROJECT}-prod-igw"
SECURITY_IGW_NAME="${PROJECT}-security-igw"
PROD_PUB_RT_NAME="${PROJECT}-prod-public-rt"
PROD_PRIV_RT_NAME="${PROJECT}-prod-private-rt"
SECURITY_MGMT_RT_NAME="${PROJECT}-security-mgmt-rt"
PEERING_NAME="${PROJECT}-prod-to-security-peering"

# -------------------------------------------------------------------
# AWS wrappers: all AWS CLI calls use the required profile and region.
# -------------------------------------------------------------------
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

validate_required_az() {
    echo "=== Pre-flight: validating required AZ ==="

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

    if [[ "$az_ok" != "yes" ]]; then
        fatal "Required availability zone ${AZ_A} is not available to this account. Stopping safely."
    fi

    echo "AZ available: $AZ_A"
    echo ""
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
    local vpc_id="$2"
    local cidr="$3"
    local az="$4"
    local raw
    raw=$(aws_ec2 describe-subnets \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=vpc-id,Values=${vpc_id}" \
                  "Name=cidr-block,Values=${cidr}" \
                  "Name=availability-zone,Values=${az}" \
        --query "Subnets[].SubnetId" \
        --output text)
    single_id_or_empty "Subnet ${name} (${cidr}, ${az})" "$raw"
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
        --output json)

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

subnet_association_for() {
    local subnet_id="$1"
    local assoc_json

    assoc_json=$(aws_ec2 describe-route-tables \
        --filters "Name=association.subnet-id,Values=${subnet_id}" \
        --output json)

    printf '%s' "$assoc_json" | python3 -c "
import sys, json
subnet_id = sys.argv[1]
data = json.load(sys.stdin)
matches = []
for table in data.get('RouteTables', []):
    for assoc in table.get('Associations', []):
        if assoc.get('SubnetId') == subnet_id:
            matches.append((table.get('RouteTableId'), assoc.get('RouteTableAssociationId')))
if len(matches) > 1:
    print('ERROR: Multiple route table associations for subnet ' + subnet_id, file=sys.stderr)
    sys.exit(2)
if matches:
    print(matches[0][0] + ' ' + matches[0][1])
" "$subnet_id"
}

# -------------------------------------------------------------------
# Create/update helpers
# -------------------------------------------------------------------
ensure_vpc() {
    local name="$1"
    local cidr="$2"
    local result_var="$3"
    local vpc_id

    vpc_id=$(find_vpc "$name" "$cidr")
    if [[ -z "$vpc_id" ]]; then
        vpc_id=$(aws_ec2 create-vpc \
            --cidr-block "$cidr" \
            --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${PROJECT}}]" \
            --query "Vpc.VpcId" \
            --output text)
        echo "CREATED  ${name}: ${vpc_id}"
    else
        echo "EXISTS   ${name}: ${vpc_id}"
    fi

    aws_ec2 modify-vpc-attribute --vpc-id "$vpc_id" --enable-dns-support '{"Value":true}'
    aws_ec2 modify-vpc-attribute --vpc-id "$vpc_id" --enable-dns-hostnames '{"Value":true}'

    printf -v "$result_var" '%s' "$vpc_id"
}

ensure_subnet() {
    local name="$1"
    local vpc_id="$2"
    local cidr="$3"
    local az="$4"
    local map_public_ip="$5"
    local result_var="$6"
    local subnet_id

    subnet_id=$(find_subnet "$name" "$vpc_id" "$cidr" "$az")
    if [[ -z "$subnet_id" ]]; then
        # Tags are supplied at create time so IAM request-tag enforcement can authorize subnet creation.
        subnet_id=$(aws_ec2 create-subnet \
            --vpc-id "$vpc_id" \
            --cidr-block "$cidr" \
            --availability-zone "$az" \
            --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${PROJECT}}]" \
            --query "Subnet.SubnetId" \
            --output text)
        echo "CREATED  ${name}: ${subnet_id}"
    else
        echo "EXISTS   ${name}: ${subnet_id}"
    fi

    if [[ "$map_public_ip" == "true" ]]; then
        aws_ec2 modify-subnet-attribute --subnet-id "$subnet_id" --map-public-ip-on-launch
    else
        aws_ec2 modify-subnet-attribute --subnet-id "$subnet_id" --no-map-public-ip-on-launch
    fi

    printf -v "$result_var" '%s' "$subnet_id"
}

ensure_igw() {
    local name="$1"
    local vpc_id="$2"
    local result_var="$3"
    local igw_id
    local attached_vpcs

    igw_id=$(find_igw "$name")
    if [[ -z "$igw_id" ]]; then
        igw_id=$(aws_ec2 create-internet-gateway \
            --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${PROJECT}}]" \
            --query "InternetGateway.InternetGatewayId" \
            --output text)
        echo "CREATED  ${name}: ${igw_id}"
    else
        echo "EXISTS   ${name}: ${igw_id}"
    fi

    attached_vpcs=$(aws_ec2 describe-internet-gateways \
        --internet-gateway-ids "$igw_id" \
        --query "InternetGateways[0].Attachments[].VpcId" \
        --output text | tr '\t' ' ')

    if [[ -z "$attached_vpcs" ]]; then
        aws_ec2 attach-internet-gateway --internet-gateway-id "$igw_id" --vpc-id "$vpc_id"
        echo "ATTACHED ${name} to ${vpc_id}"
    elif [[ "$attached_vpcs" == "$vpc_id" ]]; then
        echo "EXISTS   ${name} attached to ${vpc_id}"
    else
        fatal "${name} is attached to ${attached_vpcs}, expected ${vpc_id}"
    fi

    printf -v "$result_var" '%s' "$igw_id"
}

ensure_rtb() {
    local name="$1"
    local vpc_id="$2"
    local result_var="$3"
    local rtb_id

    rtb_id=$(find_rtb "$name" "$vpc_id")
    if [[ -z "$rtb_id" ]]; then
        rtb_id=$(aws_ec2 create-route-table \
            --vpc-id "$vpc_id" \
            --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${PROJECT}}]" \
            --query "RouteTable.RouteTableId" \
            --output text)
        echo "CREATED  ${name}: ${rtb_id}"
    else
        echo "EXISTS   ${name}: ${rtb_id}"
    fi

    printf -v "$result_var" '%s' "$rtb_id"
}

ensure_subnet_association() {
    local rtb_id="$1"
    local subnet_id="$2"
    local label="$3"
    local current
    local current_rtb

    current=$(subnet_association_for "$subnet_id")
    if [[ -z "$current" ]]; then
        aws_ec2 associate-route-table \
            --route-table-id "$rtb_id" \
            --subnet-id "$subnet_id" \
            --output text > /dev/null
        echo "ASSOCIATED ${label} to ${rtb_id}"
        return
    fi

    current_rtb=${current%% *}
    if [[ "$current_rtb" == "$rtb_id" ]]; then
        echo "EXISTS     ${label} associated to ${rtb_id}"
    else
        fatal "${label} is already associated to ${current_rtb}, expected ${rtb_id}. Refusing to replace automatically."
    fi
}

ensure_route() {
    local rtb_id="$1"
    local dest_cidr="$2"
    local expected_target="$3"
    local target_type="$4"
    local label="$5"
    local current_target

    current_target=$(route_target_for_destination "$rtb_id" "$dest_cidr")

    if [[ -z "$current_target" ]]; then
        if [[ "$target_type" == "igw" ]]; then
            aws_ec2 create-route \
                --route-table-id "$rtb_id" \
                --destination-cidr-block "$dest_cidr" \
                --gateway-id "$expected_target" > /dev/null
        elif [[ "$target_type" == "peering" ]]; then
            aws_ec2 create-route \
                --route-table-id "$rtb_id" \
                --destination-cidr-block "$dest_cidr" \
                --vpc-peering-connection-id "$expected_target" > /dev/null
        else
            fatal "Unknown route target type ${target_type}"
        fi
        echo "CREATED  route ${dest_cidr} -> ${expected_target} in ${label}"
    elif [[ "$current_target" == "$expected_target" ]]; then
        echo "EXISTS   route ${dest_cidr} -> ${expected_target} in ${label}"
    else
        fatal "Route conflict in ${label}: ${dest_cidr} points to ${current_target}, expected ${expected_target}"
    fi
}

# -------------------------------------------------------------------
# Pre-flight
# -------------------------------------------------------------------
require_expected_account
validate_required_az

# ===================================================================
# 1. VPCs
# ===================================================================
echo "=== 1. Creating VPCs ==="
ensure_vpc "$PROD_VPC_NAME" "$PROD_VPC_CIDR" PROD_VPC_ID
ensure_vpc "$SECURITY_VPC_NAME" "$SECURITY_VPC_CIDR" SECURITY_VPC_ID
echo ""

# ===================================================================
# 2. Subnets
# ===================================================================
echo "=== 2. Creating Subnets ==="
ensure_subnet "${PROJECT}-prod-public-1a" "$PROD_VPC_ID" "$PROD_PUBLIC_1A_CIDR" "$AZ_A" "true" PROD_PUB_1A_ID
ensure_subnet "${PROJECT}-prod-private-1a" "$PROD_VPC_ID" "$PROD_PRIVATE_1A_CIDR" "$AZ_A" "false" PROD_PRIV_1A_ID
ensure_subnet "${PROJECT}-security-mgmt-1a" "$SECURITY_VPC_ID" "$SECURITY_MGMT_1A_CIDR" "$AZ_A" "true" SECURITY_MGMT_1A_ID
echo ""

# ===================================================================
# 3. Internet Gateways
# ===================================================================
echo "=== 3. Creating Internet Gateways ==="
ensure_igw "$PROD_IGW_NAME" "$PROD_VPC_ID" PROD_IGW_ID
ensure_igw "$SECURITY_IGW_NAME" "$SECURITY_VPC_ID" SECURITY_IGW_ID
echo ""

# ===================================================================
# 4. Route Tables and Associations
# ===================================================================
echo "=== 4. Creating Route Tables ==="
ensure_rtb "$PROD_PUB_RT_NAME" "$PROD_VPC_ID" PROD_PUB_RTB_ID
ensure_rtb "$PROD_PRIV_RT_NAME" "$PROD_VPC_ID" PROD_PRIV_RTB_ID
ensure_rtb "$SECURITY_MGMT_RT_NAME" "$SECURITY_VPC_ID" SECURITY_MGMT_RTB_ID
echo ""

echo "=== 4a. Associating subnets with route tables ==="
ensure_subnet_association "$PROD_PUB_RTB_ID" "$PROD_PUB_1A_ID" "prod-public-1a"
ensure_subnet_association "$PROD_PRIV_RTB_ID" "$PROD_PRIV_1A_ID" "prod-private-1a"
ensure_subnet_association "$SECURITY_MGMT_RTB_ID" "$SECURITY_MGMT_1A_ID" "security-mgmt-1a"
echo ""

echo "=== 4b. Adding internet gateway routes ==="
ensure_route "$PROD_PUB_RTB_ID" "0.0.0.0/0" "$PROD_IGW_ID" "igw" "$PROD_PUB_RT_NAME"
ensure_route "$SECURITY_MGMT_RTB_ID" "0.0.0.0/0" "$SECURITY_IGW_ID" "igw" "$SECURITY_MGMT_RT_NAME"
echo ""

# ===================================================================
# 5. VPC Peering
# ===================================================================
echo "=== 5. Creating VPC Peering Connection ==="
PEERING_ID=$(find_peering "$PROD_VPC_ID" "$SECURITY_VPC_ID")

if [[ -z "$PEERING_ID" ]]; then
    PEERING_ID=$(aws_ec2 create-vpc-peering-connection \
        --vpc-id "$PROD_VPC_ID" \
        --peer-vpc-id "$SECURITY_VPC_ID" \
        --peer-region "$AWS_REGION" \
        --tag-specifications "ResourceType=vpc-peering-connection,Tags=[{Key=Name,Value=${PEERING_NAME}},{Key=Project,Value=${PROJECT}}]" \
        --query "VpcPeeringConnection.VpcPeeringConnectionId" \
        --output text)
    echo "CREATED  peering: $PEERING_ID"
else
    echo "EXISTS   peering: $PEERING_ID"
fi

PEERING_STATUS=$(aws_ec2 describe-vpc-peering-connections \
    --vpc-peering-connection-ids "$PEERING_ID" \
    --query "VpcPeeringConnections[0].Status.Code" \
    --output text)

if [[ "$PEERING_STATUS" == "pending-acceptance" ]]; then
    aws_ec2 accept-vpc-peering-connection --vpc-peering-connection-id "$PEERING_ID" > /dev/null
    echo "ACCEPTED peering: $PEERING_ID"
elif [[ "$PEERING_STATUS" == "active" ]]; then
    echo "STATUS   peering: $PEERING_ID (active)"
else
    fatal "Peering ${PEERING_ID} is in unexpected status ${PEERING_STATUS}"
fi
echo ""

echo "=== 5a. Adding peering routes ==="
ensure_route "$PROD_PUB_RTB_ID" "$SECURITY_VPC_CIDR" "$PEERING_ID" "peering" "$PROD_PUB_RT_NAME"
ensure_route "$PROD_PRIV_RTB_ID" "$SECURITY_VPC_CIDR" "$PEERING_ID" "peering" "$PROD_PRIV_RT_NAME"
ensure_route "$SECURITY_MGMT_RTB_ID" "$PROD_VPC_CIDR" "$PEERING_ID" "peering" "$SECURITY_MGMT_RT_NAME"
echo ""

# ===================================================================
# Summary
# ===================================================================
echo "==========================================="
echo "  SOC Infrastructure Provisioning Complete"
echo "==========================================="
echo ""
echo "  Account:            $ACCOUNT_ID"
echo "  Profile:            $AWS_PROFILE"
echo "  Region/AZ:          $AWS_REGION / $AZ_A"
echo ""
echo "  Production VPC:     $PROD_VPC_ID ($PROD_VPC_CIDR)"
echo "    prod-public-1a:   $PROD_PUB_1A_ID ($PROD_PUBLIC_1A_CIDR)"
echo "    prod-private-1a:  $PROD_PRIV_1A_ID ($PROD_PRIVATE_1A_CIDR)"
echo "    IGW:              $PROD_IGW_ID"
echo "    Public RT:        $PROD_PUB_RTB_ID"
echo "    Private RT:       $PROD_PRIV_RTB_ID"
echo ""
echo "  Security VPC:       $SECURITY_VPC_ID ($SECURITY_VPC_CIDR)"
echo "    security-mgmt-1a: $SECURITY_MGMT_1A_ID ($SECURITY_MGMT_1A_CIDR)"
echo "    IGW:              $SECURITY_IGW_ID"
echo "    Security RT:      $SECURITY_MGMT_RTB_ID"
echo ""
echo "  Peering:            $PEERING_ID"
echo ""
echo "  Next steps:"
echo "    - Create security groups and IAM role with infra/security.sh"
echo "    - Launch EC2 instances after validating least-privilege permissions"
echo "==========================================="
