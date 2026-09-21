# Cleanup Final Summary

- Account ID: `421515025823`
- Region: `ap-southeast-1`
- Timestamp UTC: `2026-09-08T15:36:47.655806+00:00`
- Credential handling: no credential values were written to evidence.

## Regional Deletions Completed

- Deleted VPC peering connection `pcx-0ec60bac4cf5228bc`.
- Deleted 4 custom route tables and 6 route-table associations.
- Deleted 3 project security groups.
- Detached and deleted 2 internet gateways.
- Deleted 6 project subnets.
- Deleted 2 non-default project VPCs: `vpc-0d53143e2f0a14450`, `vpc-0fda586ca71a8e583`.

## IAM Deletions Completed

- Deleted instance profiles `SOC-Middleware-Profile` and `SOC-Middleware-Role`.
- Detached and deleted managed policy `SOC-Middleware-WebSG-Policy`.
- Deleted inline role policy `SOC-SG-Modify-Policy`.
- Deleted role `SOC-Middleware-Role`.

## Final Verification

- `Project=soc-automation` tagged resources remaining from Resource Groups Tagging API: `1`.
- Name-prefix `soc-automation-*` regional resources remaining: `{'vpcs': 0, 'subnets': 0, 'route_tables': 0, 'internet_gateways': 0, 'vpc_peering_connections': 1, 'security_groups': 0, 'instances': 0}`.
- The one remaining regional record is VPC peering connection `pcx-0ec60bac4cf5228bc`, and its AWS status is `deleted`.
- IAM SOC middleware role/profile/policy absence checks all returned not found: `True`.

## Evidence Files

- `inventory-before.json`
- `CLEANUP_PLAN.md`
- `cleanup-execution-log.json`
- `cleanup-execution-summary.md`
- `inventory-after.json`
- `cleanup-final-summary.md`
