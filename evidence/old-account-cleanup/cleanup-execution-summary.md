# Cleanup Execution Summary

- Account ID: `421515025823`
- Region: `ap-southeast-1`
- Timestamp UTC: `2026-09-08T15:32:24.330116+00:00`

## Deleted

- `vpc-peering-connection` `pcx-0ec60bac4cf5228bc`
- `route-table-association` `rtbassoc-09d11a25e45cc140b`
- `route-table` `rtb-053921ab07c4d5e2e`
- `route-table-association` `rtbassoc-03099931c766cfda1`
- `route-table-association` `rtbassoc-0d86ed55f08e094d5`
- `route-table` `rtb-00f1d65a0d9a4cf2c`
- `route-table-association` `rtbassoc-026877ecd0e080753`
- `route-table-association` `rtbassoc-09a5cd67cb8dc4ae2`
- `route-table` `rtb-0011c474f65ad1e98`
- `route-table-association` `rtbassoc-0b756ad459dbccc97`
- `route-table` `rtb-0dd1e11e886f4ad75`
- `security-group` `sg-039424d17ef6630ec`
- `security-group` `sg-0f0f82178384295fd`
- `security-group` `sg-0dcbfd4796182c3b2`
- `internet-gateway-attachment` `igw-01b777b4c1c717e9f->vpc-0d53143e2f0a14450`
- `internet-gateway` `igw-01b777b4c1c717e9f`
- `internet-gateway-attachment` `igw-07cd9187e7423d4d3->vpc-0fda586ca71a8e583`
- `internet-gateway` `igw-07cd9187e7423d4d3`
- `subnet` `subnet-0dd8f8677781c9f44`
- `subnet` `subnet-0e6a021cf71f8a608`
- `subnet` `subnet-07ce59ad6eb6d68aa`
- `subnet` `subnet-0a75f102db2028159`
- `subnet` `subnet-09232eb5d82ddab7a`
- `subnet` `subnet-04b84a9083b538649`
- `vpc` `vpc-0d53143e2f0a14450`
- `vpc` `vpc-0fda586ca71a8e583`

## Skipped

- `iam-role` `SOC-Middleware-Role`: unexpected role dependencies found; left for manual review
- `iam-instance-profile` `SOC-Middleware-Role`: still contains role bindings; left for manual review

## Failures

- Command failed: aws iam delete-policy-version --policy-arn arn:aws:iam::421515025823:policy/SOC-Middleware-WebSG-Policy --version-id v1
An error occurred (DeleteConflict) when calling the DeletePolicyVersion operation: Cannot delete the default version of a policy.

## Continuation

- IAM cleanup was completed after this failure. See `cleanup-final-summary.md` and `inventory-after.json`.
