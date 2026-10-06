# AI-Assisted SOC Automation System

This project is a cybersecurity final year project for building an AI-assisted Security Operations Center automation workflow. The system is planned to ingest security alerts, classify events using machine learning, and support automated response decisions.

The system uses AWS API/Boto3 for cloud response actions, Wazuh for security monitoring and alert ingestion, Python middleware for orchestration and decision logic, and ML classification for identifying benign or malicious activity.

## AWS Deployment Guard

Infrastructure scripts must be run only against the new project account:

- AWS CLI profile: `soc-project`
- AWS region: `ap-southeast-1`
- Expected account ID: `908157891283`
- Expected caller: `arn:aws:iam::908157891283:user/soc-project-developer`

Each infrastructure script calls STS with the named profile before any write operation, prints the caller ARN/account/profile/region, and exits if the account ID does not match. Do not store AWS credentials in this repository or in `.env`.

The previous all-in-one policy draft [infra/deployer-policy.json](/Users/user/soc-automation/infra/deployer-policy.json) is superseded for AWS Console attachment. Use the split customer-managed policy files instead:

- [infra/deployer-network-policy.json](/Users/user/soc-automation/infra/deployer-network-policy.json) as `SOCAutomationDeployerPolicy` for VPC, subnet, internet gateway, route table, VPC peering, and project Security Group setup operations.
- [infra/deployer-iam-policy.json](/Users/user/soc-automation/infra/deployer-iam-policy.json) as `SOCAutomationIAMDeployerPolicy` for the exact `SOC-Middleware-Role`, instance profile, and `SOC-Middleware-WebSG-Policy` IAM operations.
- [infra/deployer-compute-policy.json](/Users/user/soc-automation/infra/deployer-compute-policy.json) as `SOCAutomationComputeDeployerPolicy` for the planned EC2 key-pair import, instance launch, and lab start/stop operations.
- [infra/deployer-sg-rule-policy.json](/Users/user/soc-automation/infra/deployer-sg-rule-policy.json) as `SOCAutomationSecurityGroupRulePolicy` for admin CIDR rotation on only the three exact project Security Groups.

The Security Group rule policy is separate because the larger deployer policy reached AWS managed-policy size constraints. It has one narrow responsibility: allow rule additions/removals only on the exact project Security Groups already created for this lab.

IAM policy JSON cannot contain comments, so policy notes are documented here and in [infra/spec.md](/Users/user/soc-automation/infra/spec.md).

## Folder Purpose

- `ai_engine/` - AI-driven multi-agent SOC reasoning and decision pipeline.
- `archive/` - Archived prototype v1 code.
- `evidence/` - Project evidence and artifacts.
- `infra/` - Infrastructure configuration and automation scripts.
- `wazuh/` - Wazuh configuration, alert examples, and ingestion resources.
