# Project Plan

| Phase | Goal | Tasks | Expected output | Status |
| --- | --- | --- | --- | --- |
| Phase 1: Project setup and planning | Define the project scope, structure, and required documentation. | Create planning files, requirements, environment template, and ignore rules. | Baseline project documentation and setup files. | DONE |
| Phase 2: AWS infrastructure configuration scripts | Prepare safe AWS infrastructure configuration scripts. | Harden Bash scripts for `soc-project`, `ap-southeast-1`, account guard `908157891283`, strict tag lookups, and least-privilege deployer policy. | Guarded scripts and console policy draft ready for review. | DONE |
| Phase 3: AWS EC2 compute provisioning | Provision Web, DB, and Wazuh EC2 instances with security groups and IAM instance profile. | Execute Phase 3 provisioning script, verify instance status, and generate inventory evidence. | Running EC2 instances (`soc-automation-web`, `soc-automation-db`, `soc-automation-wazuh`) and `inventory-after.json`. | DONE |
| Phase 4: Wazuh configuration and alert ingestion | Configure Wazuh alert collection for authentication and security events. | Prepare alert ingestion format, sample alerts, and parser expectations. | Wazuh alert ingestion workflow. | TODO |
| Phase 5: ML model training and evaluation | Train and evaluate an ML classifier for benign and malicious events. | Prepare dataset, features, model training flow, metrics, and saved model output. | Evaluated ML model and evidence. | TODO |
| Phase 6: Python middleware and decision engine | Build middleware logic for normalization, classification, and response decisions. | Connect alert parser, model prediction, confidence threshold, and action policy. | Middleware decision engine. | TODO |
| Phase 7: Boto3 active response integration | Integrate approved AWS API actions through Boto3. | Implement least-privilege block action workflow with audit logging and safety checks. | Controlled AWS active response flow. | TODO |
| Phase 8: Testing, evidence collection, and report output | Verify the full workflow and collect final project evidence. | Run system tests, collect logs, generate report output, and document results. | Test evidence and final report artifacts. | TODO |

## Deployment Safety Notes

- Required AWS CLI profile: `soc-project`
- Required region: `ap-southeast-1`
- Required account ID: `908157891283`
- Infrastructure scripts must stop before write operations if STS returns any other account.
- Do not store AWS credentials in this repository or in `.env`.
- AWS Console policy inventory:
  - `SOCAutomationDeployerPolicy` from `infra/deployer-network-policy.json`
  - `SOCAutomationIAMDeployerPolicy` from `infra/deployer-iam-policy.json`
  - `SOCAutomationComputeDeployerPolicy` from `infra/deployer-compute-policy.json`
  - `SOCAutomationSecurityGroupRulePolicy` from `infra/deployer-sg-rule-policy.json`
