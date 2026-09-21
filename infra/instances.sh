#!/usr/bin/env bash
#
# infra/instances.sh
#
# Phase 3 EC2 provisioning for the lowest-cost academic SOC lab design.
# Creates exactly three EC2 instances when they do not already exist:
#   - soc-automation-web
#   - soc-automation-db
#   - soc-automation-wazuh
#
# This script assumes Phase 1 network and Phase 2 security/IAM have passed.

set -euo pipefail

AWS_PROFILE="${AWS_PROFILE:-soc-project}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-908157891283}"

PROJECT="soc-automation"
ENVIRONMENT="lab"
AZ_A="${AWS_REGION}a"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/aws-phase3-compute}"
EVIDENCE_FILE="${EVIDENCE_FILE:-${EVIDENCE_DIR}/instances-after.json}"
PLAN_ONLY="${PLAN_ONLY:-false}"

CANONICAL_OWNER_ID="099720109477"
KEY_NAME="${PROJECT}-key"
PUBLIC_KEY_PATH="${PUBLIC_KEY_PATH:-${HOME}/.ssh/soc-automation-ed25519.pub}"

PROD_VPC_CIDR="10.0.0.0/16"
SECURITY_VPC_CIDR="172.16.0.0/16"
PROD_PUBLIC_1A_CIDR="10.0.1.0/24"
PROD_PRIVATE_1A_CIDR="10.0.2.0/24"
SECURITY_MGMT_1A_CIDR="172.16.1.0/24"

EXPECTED_PROD_VPC_ID="vpc-01d5230934a140846"
EXPECTED_SECURITY_VPC_ID="vpc-0fb2381154ad1b418"
EXPECTED_PEERING_ID="pcx-0d0b43fb860ec81c6"
EXPECTED_WEB_SG_ID="sg-01dc0bd14c2808f21"
EXPECTED_MGMT_SG_ID="sg-0effe1d21b6836624"
EXPECTED_DB_SG_ID="sg-03e665ea5e9403e11"

PROD_VPC_NAME="${PROJECT}-prod-vpc"
SECURITY_VPC_NAME="${PROJECT}-security-vpc"
PROD_PUBLIC_1A_NAME="${PROJECT}-prod-public-1a"
PROD_PRIVATE_1A_NAME="${PROJECT}-prod-private-1a"
SECURITY_MGMT_1A_NAME="${PROJECT}-security-mgmt-1a"
PEERING_NAME="${PROJECT}-prod-to-security-peering"

WEB_SG_NAME="${PROJECT}-prod-web-sg"
DB_SG_NAME="${PROJECT}-prod-db-sg"
MGMT_SG_NAME="${PROJECT}-security-mgmt-sg"
INSTANCE_PROFILE_NAME="SOC-Middleware-Role"

WEB_INSTANCE_NAME="${PROJECT}-web"
DB_INSTANCE_NAME="${PROJECT}-db"
WAZUH_INSTANCE_NAME="${PROJECT}-wazuh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_USER_DATA="${SCRIPT_DIR}/user-data/web.sh"
DB_USER_DATA="${SCRIPT_DIR}/user-data/db.sh"
WAZUH_USER_DATA="${SCRIPT_DIR}/user-data/wazuh-base.sh"

plan_mode_enabled() {
    [[ "$PLAN_ONLY" == "true" || "$PLAN_ONLY" == "1" || "$PLAN_ONLY" == "yes" ]]
}

ec2_write_command() {
    case "${1:-}" in
        import-key-pair|run-instances|start-instances|stop-instances|create-tags|create-security-group|authorize-security-group-ingress|revoke-security-group-ingress|create-vpc|modify-vpc-attribute|create-subnet|modify-subnet-attribute|create-internet-gateway|attach-internet-gateway|create-route-table|associate-route-table|create-route|create-vpc-peering-connection|accept-vpc-peering-connection)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

iam_write_command() {
    case "${1:-}" in
        create-role|update-assume-role-policy|create-policy|create-policy-version|delete-policy-version|attach-role-policy|create-instance-profile|add-role-to-instance-profile)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

aws_ec2() {
    if plan_mode_enabled && ec2_write_command "${1:-}"; then
        fatal "PLAN_ONLY blocked AWS write command: ec2 ${1}"
    fi
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 "$@"
}

aws_iam() {
    if plan_mode_enabled && iam_write_command "${1:-}"; then
        fatal "PLAN_ONLY blocked AWS write command: iam ${1}"
    fi
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" iam "$@"
}

aws_sts() {
    command aws --profile "$AWS_PROFILE" --region "$AWS_REGION" sts "$@"
}

fatal() {
    echo "ERROR: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fatal "Required command not found: $1"
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

tag_value_from_json() {
    local json="$1"
    local key="$2"
    printf '%s' "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
key = sys.argv[1]
for tag in data:
    if tag.get('Key') == key:
        print(tag.get('Value', ''))
        sys.exit(0)
" "$key"
}

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
    local raw
    raw=$(aws_ec2 describe-subnets \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${name}" \
                  "Name=vpc-id,Values=${vpc_id}" \
                  "Name=cidr-block,Values=${cidr}" \
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

find_peering() {
    local prod_vpc_id="$1"
    local security_vpc_id="$2"
    local peering_json
    peering_json=$(aws_ec2 describe-vpc-peering-connections \
        --filters "Name=tag:Project,Values=${PROJECT}" \
                  "Name=tag:Name,Values=${PEERING_NAME}" \
                  "Name=status-code,Values=active" \
        --output json)

    printf '%s' "$peering_json" | python3 -c "
import sys, json
prod, security = sys.argv[1], sys.argv[2]
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
    print('ERROR: Peering tag matches unexpected VPCs: ' + ' '.join(conflicts), file=sys.stderr)
    sys.exit(2)
if len(matches) > 1:
    print('ERROR: Multiple active peering matches: ' + ' '.join(matches), file=sys.stderr)
    sys.exit(2)
if matches:
    print(matches[0])
" "$prod_vpc_id" "$security_vpc_id"
}

find_instance_profile() {
    local output
    local status
    set +e
    output=$(aws_iam get-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" \
        --query "InstanceProfile" \
        --output json 2>&1)
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        fatal "Instance profile ${INSTANCE_PROFILE_NAME} is required before EC2 provisioning: ${output}"
    fi

    printf '%s' "$output" | python3 -c "
import sys, json
profile = json.load(sys.stdin)
expected = sys.argv[1]
project = sys.argv[2]
name = profile.get('InstanceProfileName')
tags = {tag.get('Key'): tag.get('Value') for tag in profile.get('Tags', [])}
roles = [role.get('RoleName') for role in profile.get('Roles', [])]
if name != expected:
    print(f'Unexpected instance profile name: {name}', file=sys.stderr)
    sys.exit(2)
if tags.get('Project') != project:
    print(f'Instance profile {expected} is missing Project={project} tag', file=sys.stderr)
    sys.exit(2)
if roles != [expected]:
    print(f'Instance profile {expected} must contain only role {expected}; got {roles}', file=sys.stderr)
    sys.exit(2)
print(name)
" "$INSTANCE_PROFILE_NAME" "$PROJECT"
}

require_public_key() {
    if [[ ! -f "$PUBLIC_KEY_PATH" ]]; then
        fatal "Missing public key ${PUBLIC_KEY_PATH}. Create it locally with: ssh-keygen -t ed25519 -f ~/.ssh/soc-automation-ed25519 -C soc-automation-key"
    fi

    local key_type
    key_type=$(awk 'NR==1 {print $1}' "$PUBLIC_KEY_PATH")
    if [[ "$key_type" != "ssh-ed25519" ]]; then
        fatal "Expected an ssh-ed25519 public key at ${PUBLIC_KEY_PATH}; found key type '${key_type}'."
    fi
}

ensure_key_pair() {
    echo "=== Pre-flight: ensuring EC2 public key pair ==="

    require_public_key

    local output
    local status
    set +e
    output=$(aws_ec2 describe-key-pairs \
        --key-names "$KEY_NAME" \
        --query "KeyPairs[0]" \
        --output json 2>&1)
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        if [[ "$output" == *"InvalidKeyPair.NotFound"* ]]; then
            aws_ec2 import-key-pair \
                --key-name "$KEY_NAME" \
                --public-key-material "fileb://${PUBLIC_KEY_PATH}" \
                --tag-specifications "ResourceType=key-pair,Tags=[{Key=Name,Value=${KEY_NAME}},{Key=Project,Value=${PROJECT}},{Key=Environment,Value=${ENVIRONMENT}}]" \
                --output text \
                --query "KeyName" > /dev/null
            echo "IMPORTED EC2 key pair: $KEY_NAME"
            echo ""
            return
        fi
        fatal "Unable to inspect EC2 key pair ${KEY_NAME}: ${output}"
    fi

    local tags_json
    local project_tag
    local name_tag
    tags_json=$(printf '%s' "$output" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('Tags', [])))")
    project_tag=$(tag_value_from_json "$tags_json" "Project")
    name_tag=$(tag_value_from_json "$tags_json" "Name")

    if [[ "$project_tag" != "$PROJECT" || "$name_tag" != "$KEY_NAME" ]]; then
        fatal "Key pair ${KEY_NAME} exists but does not have expected Project and Name tags. Refusing to reuse an ambiguous key."
    fi

    echo "EXISTS   EC2 key pair: $KEY_NAME"
    echo ""
}

inspect_key_pair_plan() {
    echo "=== PLAN_ONLY: checking SSH key pair readiness ==="

    if [[ -f "${HOME}/.ssh/soc-automation-ed25519" ]]; then
        echo "Local private key: present (not read)"
    else
        echo "Local private key: missing"
    fi

    if [[ -f "$PUBLIC_KEY_PATH" ]]; then
        echo "Local public key:  present"
    else
        echo "Local public key:  missing"
        echo "Create it before real provisioning with: ssh-keygen -t ed25519 -f ~/.ssh/soc-automation-ed25519 -C soc-automation-key"
    fi

    local output
    local status
    set +e
    output=$(aws_ec2 describe-key-pairs \
        --key-names "$KEY_NAME" \
        --query "KeyPairs[0]" \
        --output json 2>&1)
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        if [[ "$output" == *"InvalidKeyPair.NotFound"* ]]; then
            echo "EC2 key pair:      missing; real run would import the public key only"
            echo ""
            return
        fi
        fatal "Unable to inspect EC2 key pair ${KEY_NAME}: ${output}"
    fi

    local tags_json
    local project_tag
    local name_tag
    tags_json=$(printf '%s' "$output" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('Tags', [])))")
    project_tag=$(tag_value_from_json "$tags_json" "Project")
    name_tag=$(tag_value_from_json "$tags_json" "Name")

    if [[ "$project_tag" != "$PROJECT" || "$name_tag" != "$KEY_NAME" ]]; then
        fatal "Key pair ${KEY_NAME} exists but does not have expected Project and Name tags. Refusing to plan around an ambiguous key."
    fi

    echo "EC2 key pair:      exists and is tagged for this project"
    echo ""
}

resolve_ubuntu_ami() {
    echo "=== Pre-flight: resolving Canonical Ubuntu 22.04 LTS AMI ==="

    local images_json
    local ami_selection
    images_json=$(aws_ec2 describe-images \
        --owners "$CANONICAL_OWNER_ID" \
        --filters \
            "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*,ubuntu/images/hvm-ssd-gp3/ubuntu-jammy-22.04-amd64-server-*" \
            "Name=architecture,Values=x86_64" \
            "Name=root-device-type,Values=ebs" \
            "Name=virtualization-type,Values=hvm" \
            "Name=image-type,Values=machine" \
            "Name=state,Values=available" \
        --output json)

    ami_selection=$(printf '%s' "$images_json" | python3 -c "
import sys, json
owner = '099720109477'
data = json.load(sys.stdin)
valid = []
for image in data.get('Images', []):
    name = image.get('Name', '')
    if image.get('OwnerId') != owner:
        continue
    if not name.startswith(('ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-', 'ubuntu/images/hvm-ssd-gp3/ubuntu-jammy-22.04-amd64-server-')):
        continue
    if image.get('Architecture') != 'x86_64':
        continue
    if image.get('RootDeviceType') != 'ebs':
        continue
    if image.get('VirtualizationType') != 'hvm':
        continue
    if image.get('State') != 'available':
        continue
    if image.get('ImageType') != 'machine':
        continue
    if not image.get('RootDeviceName'):
        continue
    valid.append(image)
if not valid:
    print('ERROR no valid Canonical Ubuntu 22.04 x86_64 EBS-backed AMI found', file=sys.stderr)
    sys.exit(2)
valid.sort(key=lambda item: (item.get('CreationDate', ''), item.get('ImageId', '')))
selected = valid[-1]
print(selected['ImageId'], selected['RootDeviceName'], selected['Name'], selected.get('CreationDate', 'unknown'))
")
    read -r AMI_ID AMI_ROOT_DEVICE AMI_NAME AMI_CREATED <<< "$ami_selection"

    [[ -n "${AMI_ID:-}" ]] || fatal "AMI resolution failed."
    echo "Selected AMI: $AMI_ID"
    echo "AMI name:     $AMI_NAME"
    echo "Created:      $AMI_CREATED"
    echo ""
}

require_expected_id() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    if [[ "$actual" != "$expected" ]]; then
        fatal "${label} expected ${expected}, got ${actual}."
    fi
}

resolve_dependencies() {
    echo "=== Pre-flight: resolving Phase 1 and Phase 2 dependencies ==="

    PROD_VPC_ID=$(find_vpc "$PROD_VPC_NAME" "$PROD_VPC_CIDR")
    SECURITY_VPC_ID=$(find_vpc "$SECURITY_VPC_NAME" "$SECURITY_VPC_CIDR")
    require_expected_id "Production VPC" "$PROD_VPC_ID" "$EXPECTED_PROD_VPC_ID"
    require_expected_id "Security VPC" "$SECURITY_VPC_ID" "$EXPECTED_SECURITY_VPC_ID"

    PROD_PUBLIC_SUBNET_ID=$(find_subnet "$PROD_PUBLIC_1A_NAME" "$PROD_VPC_ID" "$PROD_PUBLIC_1A_CIDR")
    PROD_PRIVATE_SUBNET_ID=$(find_subnet "$PROD_PRIVATE_1A_NAME" "$PROD_VPC_ID" "$PROD_PRIVATE_1A_CIDR")
    SECURITY_MGMT_SUBNET_ID=$(find_subnet "$SECURITY_MGMT_1A_NAME" "$SECURITY_VPC_ID" "$SECURITY_MGMT_1A_CIDR")

    WEB_SG_ID=$(find_sg "$WEB_SG_NAME" "$PROD_VPC_ID")
    DB_SG_ID=$(find_sg "$DB_SG_NAME" "$PROD_VPC_ID")
    MGMT_SG_ID=$(find_sg "$MGMT_SG_NAME" "$SECURITY_VPC_ID")
    require_expected_id "Web security group" "$WEB_SG_ID" "$EXPECTED_WEB_SG_ID"
    require_expected_id "DB security group" "$DB_SG_ID" "$EXPECTED_DB_SG_ID"
    require_expected_id "Management security group" "$MGMT_SG_ID" "$EXPECTED_MGMT_SG_ID"

    PEERING_ID=$(find_peering "$PROD_VPC_ID" "$SECURITY_VPC_ID")
    require_expected_id "VPC peering" "$PEERING_ID" "$EXPECTED_PEERING_ID"

    INSTANCE_PROFILE=$(find_instance_profile)

    echo "Production public subnet:  $PROD_PUBLIC_SUBNET_ID"
    echo "Production private subnet: $PROD_PRIVATE_SUBNET_ID"
    echo "Security mgmt subnet:      $SECURITY_MGMT_SUBNET_ID"
    echo "Web SG:                    $WEB_SG_ID"
    echo "DB SG:                     $DB_SG_ID"
    echo "Management SG:             $MGMT_SG_ID"
    echo "Peering:                   $PEERING_ID"
    echo "Instance profile:          $INSTANCE_PROFILE"
    echo ""
}

find_instance() {
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
        instances.append(instance)
if len(instances) > 1:
    print('ERROR multiple instances match', file=sys.stderr)
    for instance in instances:
        print(instance.get('InstanceId') + ' ' + instance.get('State', {}).get('Name', 'unknown'), file=sys.stderr)
    sys.exit(2)
if instances:
    instance = instances[0]
    state = instance.get('State', {}).get('Name', 'unknown')
    print(instance.get('InstanceId'), state)
"
}

launch_instance() {
    local name="$1"
    local role="$2"
    local instance_type="$3"
    local volume_gib="$4"
    local subnet_id="$5"
    local sg_id="$6"
    local associate_public_ip="$7"
    local user_data_file="$8"
    local iam_profile_name="$9"
    local result_var="${10}"
    local existing
    local instance_id
    local state

    [[ -f "$user_data_file" ]] || fatal "Missing user-data file: $user_data_file"

    existing=$(find_instance "$name" "$role")
    if [[ -n "$existing" ]]; then
        instance_id=${existing%% *}
        state=${existing#* }
        case "$state" in
            pending|running)
                echo "EXISTS   ${name}: ${instance_id} (${state})"
                printf -v "$result_var" '%s' "$instance_id"
                return
                ;;
            stopped|stopping)
                fatal "${name} exists as ${instance_id} but is ${state}. Use infra/start-lab.sh; refusing to replace it."
                ;;
            shutting-down|terminated)
                fatal "${name} has a matching ${state} instance ${instance_id}. Refusing automatic replacement."
                ;;
            *)
                fatal "${name} has unexpected state ${state} on ${instance_id}."
                ;;
        esac
    fi

    local -a args=(
        run-instances
        --image-id "$AMI_ID"
        --instance-type "$instance_type"
        --count 1
        --key-name "$KEY_NAME"
        --network-interfaces "DeviceIndex=0,SubnetId=${subnet_id},Groups=[${sg_id}],AssociatePublicIpAddress=${associate_public_ip},DeleteOnTermination=true"
        --block-device-mappings "DeviceName=${AMI_ROOT_DEVICE},Ebs={VolumeSize=${volume_gib},VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}"
        --metadata-options "HttpEndpoint=enabled,HttpTokens=required"
        --user-data "file://${user_data_file}"
        --tag-specifications
            "ResourceType=instance,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${PROJECT}},{Key=Role,Value=${role}},{Key=Environment,Value=${ENVIRONMENT}}]"
            "ResourceType=volume,Tags=[{Key=Name,Value=${name}-root},{Key=Project,Value=${PROJECT}},{Key=Role,Value=${role}},{Key=Environment,Value=${ENVIRONMENT}}]"
        --query "Instances[0].InstanceId"
        --output text
    )

    if [[ -n "$iam_profile_name" ]]; then
        args+=(--iam-instance-profile "Name=${iam_profile_name}")
    fi

    instance_id=$(aws_ec2 "${args[@]}")
    echo "CREATED  ${name}: ${instance_id}"
    printf -v "$result_var" '%s' "$instance_id"
}

plan_instance() {
    local name="$1"
    local role="$2"
    local instance_type="$3"
    local volume_gib="$4"
    local subnet_id="$5"
    local sg_id="$6"
    local associate_public_ip="$7"
    local user_data_file="$8"
    local iam_profile_name="$9"
    local existing
    local instance_id
    local state

    [[ -f "$user_data_file" ]] || fatal "Missing user-data file: $user_data_file"

    existing=$(find_instance "$name" "$role")
    if [[ -n "$existing" ]]; then
        instance_id=${existing%% *}
        state=${existing#* }
        echo "PLAN REUSE ${name}: ${instance_id} (${state})"
        return
    fi

    if [[ -n "$iam_profile_name" ]]; then
        echo "PLAN CREATE ${name}: ${instance_type}, subnet=${subnet_id}, sg=${sg_id}, public-ip=${associate_public_ip}, root=${volume_gib}GiB encrypted gp3, iam-profile=${iam_profile_name}, user-data=${user_data_file}"
    else
        echo "PLAN CREATE ${name}: ${instance_type}, subnet=${subnet_id}, sg=${sg_id}, public-ip=${associate_public_ip}, root=${volume_gib}GiB encrypted gp3, iam-profile=none, user-data=${user_data_file}"
    fi
}

run_plan_only() {
    echo "=== PLAN_ONLY enabled: no AWS write operations will be called ==="
    echo ""
    inspect_key_pair_plan

    echo "=== PLAN_ONLY: EC2 instance plan ==="
    echo "AMI: $AMI_ID ($AMI_NAME)"
    echo "AMI root device: $AMI_ROOT_DEVICE"
    plan_instance "$WEB_INSTANCE_NAME" "web" "t3.micro" "12" "$PROD_PUBLIC_SUBNET_ID" "$WEB_SG_ID" "true" "$WEB_USER_DATA" ""
    plan_instance "$DB_INSTANCE_NAME" "db" "t3.micro" "12" "$PROD_PRIVATE_SUBNET_ID" "$DB_SG_ID" "false" "$DB_USER_DATA" ""
    plan_instance "$WAZUH_INSTANCE_NAME" "wazuh" "t3.large" "50" "$SECURITY_MGMT_SUBNET_ID" "$MGMT_SG_ID" "true" "$WAZUH_USER_DATA" "$INSTANCE_PROFILE_NAME"
    echo ""
    echo "PLAN_ONLY complete. No key pair import, RunInstances, waiters, or evidence inventory writes were executed."
}

wait_for_instances() {
    echo ""
    echo "=== Waiting for EC2 instances ==="
    aws_ec2 wait instance-running --instance-ids "$WEB_INSTANCE_ID" "$DB_INSTANCE_ID" "$WAZUH_INSTANCE_ID"
    echo "Instances are running."
    aws_ec2 wait instance-status-ok --instance-ids "$WEB_INSTANCE_ID" "$DB_INSTANCE_ID" "$WAZUH_INSTANCE_ID"
    echo "Instance status checks passed."
    echo ""
}

write_inventory() {
    mkdir -p "$EVIDENCE_DIR"

    local tmp
    tmp=$(mktemp)
    aws_ec2 describe-instances \
        --instance-ids "$WEB_INSTANCE_ID" "$DB_INSTANCE_ID" "$WAZUH_INSTANCE_ID" \
        --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Project:Tags[?Key=='Project']|[0].Value,Role:Tags[?Key=='Role']|[0].Value,Environment:Tags[?Key=='Environment']|[0].Value,InstanceId:InstanceId,State:State.Name,InstanceType:InstanceType,ImageId:ImageId,SubnetId:SubnetId,VpcId:VpcId,PrivateIpAddress:PrivateIpAddress,PublicIpAddress:PublicIpAddress,SecurityGroups:SecurityGroups[].GroupId,IamInstanceProfile:IamInstanceProfile.Arn,RootDeviceName:RootDeviceName,BlockDeviceMappings:BlockDeviceMappings[].{DeviceName:DeviceName,VolumeId:Ebs.VolumeId,DeleteOnTermination:Ebs.DeleteOnTermination}}" \
        --output json > "$tmp"

    python3 - "$tmp" "$EVIDENCE_FILE" "$ACCOUNT_ID" "$AWS_PROFILE" "$AWS_REGION" "$AZ_A" "$AMI_ID" <<'PY'
import json
import sys
from pathlib import Path

instances_path, out_path, account, profile, region, az, ami = sys.argv[1:]
instances = json.loads(Path(instances_path).read_text())
document = {
    "metadata": {
        "account": account,
        "profile": profile,
        "region": region,
        "availability_zone": az,
        "project": "soc-automation",
        "ami_id": ami,
        "note": "Sanitized inventory. No credentials, key material, passwords, tokens, or user-data are included."
    },
    "instances": instances
}
Path(out_path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
    rm -f "$tmp"
    echo "Evidence written: $EVIDENCE_FILE"
}

require_command aws
require_command python3

require_expected_account
validate_required_az
resolve_dependencies
resolve_ubuntu_ami

if plan_mode_enabled; then
    run_plan_only
    exit 0
fi

ensure_key_pair

echo "=== Creating/reusing EC2 instances ==="
launch_instance "$WEB_INSTANCE_NAME" "web" "t3.micro" "12" "$PROD_PUBLIC_SUBNET_ID" "$WEB_SG_ID" "true" "$WEB_USER_DATA" "" WEB_INSTANCE_ID
launch_instance "$DB_INSTANCE_NAME" "db" "t3.micro" "12" "$PROD_PRIVATE_SUBNET_ID" "$DB_SG_ID" "false" "$DB_USER_DATA" "" DB_INSTANCE_ID
launch_instance "$WAZUH_INSTANCE_NAME" "wazuh" "t3.large" "50" "$SECURITY_MGMT_SUBNET_ID" "$MGMT_SG_ID" "true" "$WAZUH_USER_DATA" "$INSTANCE_PROFILE_NAME" WAZUH_INSTANCE_ID

wait_for_instances
write_inventory

echo "==========================================="
echo "  EC2 Instance Provisioning Complete"
echo "==========================================="
echo "  Web:    $WEB_INSTANCE_ID"
echo "  DB:     $DB_INSTANCE_ID"
echo "  Wazuh:  $WAZUH_INSTANCE_ID"
echo ""
echo "No Elastic IPs, NAT gateways, RDS resources, load balancers, endpoints, or Wazuh services were created."
echo "Security Groups are allow-only; middleware per-attacker-IP blocking remains TODO."
