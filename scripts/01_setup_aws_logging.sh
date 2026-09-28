#!/usr/bin/env bash
#
# scripts/01_setup_aws_logging.sh
# Automated setup for S3 logging bucket and Wazuh IAM reader user.
#

set -euo pipefail

AWS_REGION="${AWS_REGION:-ap-southeast-1}"
RANDOM_SUFFIX=$(python3 -c "import secrets; print(secrets.token_hex(4))")
BUCKET_NAME="aws-waf-logs-soc-project-${RANDOM_SUFFIX}"
POLICY_NAME="SOCWazuhS3ReadOnlyPolicy"
IAM_USER_NAME="wazuh-s3-agent"

echo "=========================================================="
echo "  AWS LOGGING & S3 BUCKET PROVISIONING FOR WAZUH MODULE"
echo "=========================================================="
echo "Region:      ${AWS_REGION}"
echo "Bucket Name: ${BUCKET_NAME}"
echo "IAM User:    ${IAM_USER_NAME}"
echo "----------------------------------------------------------"

echo "=== 1. Creating Private S3 Bucket ==="
if [[ "${AWS_REGION}" == "us-east-1" ]]; then
  aws s3api create-bucket \
    --bucket "${BUCKET_NAME}" \
    --region "${AWS_REGION}"
else
  aws s3api create-bucket \
    --bucket "${BUCKET_NAME}" \
    --region "${AWS_REGION}" \
    --create-bucket-configuration LocationConstraint="${AWS_REGION}"
fi

echo "=== 2. Enabling S3 Bucket Public Access Block & Encryption ==="
aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3api put-bucket-encryption \
  --bucket "${BUCKET_NAME}" \
  --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

echo "=== 3. Creating IAM Read-Only Policy for Wazuh ==="
POLICY_DOC=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "WazuhS3ListBucket",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::${BUCKET_NAME}"
        },
        {
            "Sid": "WazuhS3GetObject",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::${BUCKET_NAME}/*"
        }
    ]
}
EOF
)

ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

if ! aws iam get-policy --policy-arn "${POLICY_ARN}" >/dev/null 2>&1; then
  aws iam create-policy \
    --policy-name "${POLICY_NAME}" \
    --policy-document "${POLICY_DOC}" \
    --description "Read-only access for Wazuh S3 module to fetch WAF and VPC logs" >/dev/null
  echo "CREATED IAM policy: ${POLICY_ARN}"
else
  echo "EXISTS  IAM policy: ${POLICY_ARN}"
fi

echo "=== 4. Creating IAM User and Attaching Policy ==="
if ! aws iam get-user --user-name "${IAM_USER_NAME}" >/dev/null 2>&1; then
  aws iam create-user --user-name "${IAM_USER_NAME}" >/dev/null
  echo "CREATED IAM user: ${IAM_USER_NAME}"
else
  echo "EXISTS  IAM user: ${IAM_USER_NAME}"
fi

aws iam attach-user-policy \
  --user-name "${IAM_USER_NAME}" \
  --policy-arn "${POLICY_ARN}"
echo "ATTACHED policy to user ${IAM_USER_NAME}"

echo "=========================================================="
echo "  PROVISIONING COMPLETE"
echo "=========================================================="
echo "  S3 Bucket Created: ${BUCKET_NAME}"
echo ""
echo "  To generate AWS Access Credentials for the Wazuh Manager, run:"
echo "    aws iam create-access-key --user-name ${IAM_USER_NAME}"
echo "=========================================================="
