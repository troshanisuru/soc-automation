# Old Account soc-automation Cleanup Plan

This is a planning document only. It is not an executable deletion script.

## Account Scope

- Account ID: `421515025823`
- Caller ARN: `arn:aws:iam::421515025823:user/cyber-user`
- Region: `ap-southeast-1`
- Active profile/credential source: `default credential chain; AWS_PROFILE not set`
- Cleanup candidate rule: `Project=soc-automation` tag or `Name`/resource name beginning `soc-automation-`.
- Default VPCs are excluded even if tagged or named like the project.

## Cleanup Candidates

### VPCs
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `vpc-0d53143e2f0a14450` `soc-automation-mgmt-vpc` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `vpc-0fda586ca71a8e583` `soc-automation-soc-vpc` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |

### Subnets
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `subnet-0dd8f8677781c9f44` `soc-automation-soc-public-1a` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `subnet-0e6a021cf71f8a608` `soc-automation-soc-private-1b` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `subnet-07ce59ad6eb6d68aa` `soc-automation-mgmt-private-1a` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `subnet-0a75f102db2028159` `soc-automation-soc-public-1b` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `subnet-09232eb5d82ddab7a` `soc-automation-soc-private-1a` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `subnet-04b84a9083b538649` `soc-automation-mgmt-public-1a` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |

### Route Tables
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `rtb-053921ab07c4d5e2e` `soc-automation-mgmt-public-rt` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `rtb-00f1d65a0d9a4cf2c` `soc-automation-soc-private-rt` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `rtb-0011c474f65ad1e98` `soc-automation-soc-public-rt` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `rtb-0dd1e11e886f4ad75` `soc-automation-mgmt-private-rt` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `rtb-08a63f5113aa20dc0` | VPC-OWNED DEFAULT | AWS main route table inside project VPC; deleted with VPC, not a separate cleanup target |
| `rtb-05f373f548095b016` | VPC-OWNED DEFAULT | AWS main route table inside project VPC; deleted with VPC, not a separate cleanup target |

### Internet Gateways
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `igw-01b777b4c1c717e9f` `soc-automation-mgmt-igw` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `igw-07cd9187e7423d4d3` `soc-automation-soc-igw` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |

### VPC Peering Connections
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `pcx-0ec60bac4cf5228bc` `soc-automation-soc-to-mgmt-peering` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |

### Security Groups
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `sg-039424d17ef6630ec` `soc-automation-db-sg` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `sg-0dcbfd4796182c3b2` `soc-automation-security-mgmt-sg` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `sg-0f0f82178384295fd` `soc-automation-web-sg` | CANDIDATE | Project tag = soc-automation; Name tag/name begins with soc-automation- |
| `sg-008389d7095f9b53a` `default` | VPC-OWNED DEFAULT | AWS default security group inside project VPC; deleted with VPC, not a separate cleanup target |
| `sg-0941206a64a86a3fa` `default` | VPC-OWNED DEFAULT | AWS default security group inside project VPC; deleted with VPC, not a separate cleanup target |

### Network ACLs
| Resource ID / Name | Status | Why included |
| --- | --- | --- |
| `acl-0c0a6b5ad6def4a77` | VPC-OWNED DEFAULT | AWS default network ACL inside project VPC; deleted with VPC, not a separate cleanup target |
| `acl-016a50040ba7f5bef` | VPC-OWNED DEFAULT | AWS default network ACL inside project VPC; deleted with VPC, not a separate cleanup target |

### EC2 Instances
No resources discovered.

### Network Interfaces
No resources discovered.

### Elastic IP Addresses
No resources discovered.

### NAT Gateways
No resources discovered.

### ELBv2 Load Balancers
No resources discovered.

### Classic Load Balancers
No resources discovered.

### VPC Endpoints
No resources discovered.

### RDS DB Instances
No resources discovered.

### RDS DB Clusters
No resources discovered.

### RDS DB Subnet Groups
No resources discovered.

### IAM Resources
| Resource | Status | Why included |
| --- | --- | --- |
| `arn:aws:iam::421515025823:instance-profile/SOC-Middleware-Role` | BLOCKED | Explicit project IAM name requested for inspection, but no Project=soc-automation tag or soc-automation- Name prefix |
| `arn:aws:iam::421515025823:policy/SOC-Middleware-WebSG-Policy` | CANDIDATE | Project tag = soc-automation; Explicit project IAM policy name requested for inspection |
| `arn:aws:iam::421515025823:role/SOC-Middleware-Role` | BLOCKED | Explicit project IAM name requested for inspection, but no Project=soc-automation tag or soc-automation- Name prefix |

## Ambiguous Or Untagged Dependencies

These resources are BLOCKED pending confirmation because they are not clearly tagged/named as soc-automation resources under the strict cleanup rule.

| Type | Resource ID | Reason |
| --- | --- | --- |
| iam-role | `arn:aws:iam::421515025823:role/SOC-Middleware-Role` | IAM resource has the expected SOC-Middleware-Role name but does not match the strict Project tag or soc-automation- Name-prefix cleanup rule. |
| iam-instance-profile | `arn:aws:iam::421515025823:instance-profile/SOC-Middleware-Role` | IAM resource has the expected SOC-Middleware-Role name but does not match the strict Project tag or soc-automation- Name-prefix cleanup rule. |

## VPC-Owned Default Components

These are untagged AWS default components inside discovered non-default project VPCs. They are not separate cleanup targets and do not block VPC deletion.

| Type | Resource ID | VPC |
| --- | --- | --- |
| main-route-table | `rtb-08a63f5113aa20dc0` | `vpc-0d53143e2f0a14450` |
| main-route-table | `rtb-05f373f548095b016` | `vpc-0fda586ca71a8e583` |
| default-security-group | `sg-008389d7095f9b53a` | `vpc-0d53143e2f0a14450` |
| default-security-group | `sg-0941206a64a86a3fa` | `vpc-0fda586ca71a8e583` |
| default-network-acl | `acl-0c0a6b5ad6def4a77` | `vpc-0d53143e2f0a14450` |
| default-network-acl | `acl-016a50040ba7f5bef` | `vpc-0fda586ca71a8e583` |

## Resources Blocking VPC Deletion

| Type | Resource ID | Status |
| --- | --- | --- |
| internet_gateways | `igw-01b777b4c1c717e9f` | CANDIDATE |
| internet_gateways | `igw-07cd9187e7423d4d3` | CANDIDATE |
| vpc_peering_connections | `pcx-0ec60bac4cf5228bc` | CANDIDATE |
| security_groups | `sg-039424d17ef6630ec` | CANDIDATE |
| security_groups | `sg-0dcbfd4796182c3b2` | CANDIDATE |
| security_groups | `sg-0f0f82178384295fd` | CANDIDATE |
| route_tables | `rtb-053921ab07c4d5e2e` | CANDIDATE |
| route_tables | `rtb-00f1d65a0d9a4cf2c` | CANDIDATE |
| route_tables | `rtb-0011c474f65ad1e98` | CANDIDATE |
| route_tables | `rtb-0dd1e11e886f4ad75` | CANDIDATE |
| subnets | `subnet-0dd8f8677781c9f44` | CANDIDATE |
| subnets | `subnet-0e6a021cf71f8a608` | CANDIDATE |
| subnets | `subnet-07ce59ad6eb6d68aa` | CANDIDATE |
| subnets | `subnet-0a75f102db2028159` | CANDIDATE |
| subnets | `subnet-09232eb5d82ddab7a` | CANDIDATE |
| subnets | `subnet-04b84a9083b538649` | CANDIDATE |

## Proposed Deletion Order

Do not execute deletion until all BLOCKED ambiguous resources are reviewed and confirmed.

1. Confirm account ID and region match this plan.
2. Delete or drain project load balancers and their listeners/target groups, if any are confirmed candidates.
3. Delete confirmed project RDS DB clusters/instances, then DB subnet groups.
4. Terminate confirmed project EC2 instances, including stopped instances.
5. Delete confirmed project NAT gateways, then release confirmed project Elastic IP addresses.
6. Delete confirmed project VPC endpoints.
7. Delete remaining confirmed project ENIs after their parent resources are gone.
8. Delete confirmed project VPC peering connections.
9. Detach and delete confirmed project internet gateways.
10. Delete confirmed custom project security groups after no ENIs reference them.
11. Delete confirmed custom network ACLs, route-table routes/associations, and custom route tables. Main route tables/default SGs/default NACLs are removed with the VPC.
12. Delete confirmed project subnets.
13. Delete confirmed non-default project VPCs.
14. Clean up IAM separately because IAM is global: only delete IAM resources that satisfy the strict tag/name rule or are explicitly confirmed. For the tagged managed policy, delete non-default policy versions, detach it, then delete `SOC-Middleware-WebSG-Policy`. The untagged role and instance profile remain BLOCKED until confirmed.

## Post-Deletion Verification Commands

These commands are read-only checks to run after deletion:

```bash
aws sts get-caller-identity
aws ec2 describe-vpcs --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-vpcs --region ap-southeast-1 --filters Name=tag:Name,Values=soc-automation-*
aws ec2 describe-subnets --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-route-tables --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-internet-gateways --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-security-groups --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-instances --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-network-interfaces --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-addresses --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws ec2 describe-nat-gateways --region ap-southeast-1 --filter Name=tag:Project,Values=soc-automation
aws ec2 describe-vpc-endpoints --region ap-southeast-1 --filters Name=tag:Project,Values=soc-automation
aws iam get-role --role-name SOC-Middleware-Role
aws iam get-policy --policy-arn arn:aws:iam::421515025823:policy/SOC-Middleware-WebSG-Policy
```

## Notes

- Security Groups are allow-list resources only; they cannot explicitly deny a single attacker IP if a broader allow rule already permits that traffic.
- Untagged dependencies inside a project VPC are not automatically approved for cleanup.
- No executable deletion script has been created.
