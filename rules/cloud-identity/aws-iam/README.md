# Indicative Cloud Identity & AWS IAM Rule Catalog (`indicative-cloud-iam-v1.0.0`)

Deterministic, offline static analysis rules implemented in `@indicative/cloud-identity` (`packages/cloud-identity`) covering Terraform HCL (`.tf`), CloudFormation (`.yml`/`.yaml`/`.json`), raw AWS IAM Policy JSON, and cross-file GitHub Actions OIDC workflow correlation.

All rules declare `evidenceBasis: "STATIC_CONFIG"` and explicitly disclose runtime controls that cannot be verified statically (`AWS_SCP_UNKNOWN`, `LIVE_IAM_DRIFT_UNKNOWN`, `GITHUB_BRANCH_PROTECTION_UNKNOWN`, `GITHUB_ENV_APPROVAL_GATES_UNKNOWN`).

## Rule Summary

| Rule ID | Category | Default Severity | CWE | Description |
|---|---|---|---|---|
| `IAM-ADMIN-001` | Admin Access | `CRITICAL` | CWE-250 | Unrestricted `Action: "*"` on `Resource: "*"` or attached AWS managed `AdministratorAccess` / `IAMFullAccess` / `PowerUserAccess` |
| `IAM-PERM-001` | Over-Privileged Policy | `HIGH` (`MEDIUM` if conditional) | CWE-732 | Broad high-risk service wildcard (`s3:*`, `iam:*`, `ec2:*`, `rds:*`, `secretsmanager:*`, `kms:*`, `eks:*`, `lambda:*`, etc.) on `Resource: "*"` or `*FullAccess` managed policy |
| `IAM-PERM-002` | Over-Privileged Policy | `HIGH` | CWE-732 | `Allow` statement using `NotAction` or `NotResource` |
| `IAM-DATA-001` | Sensitive Data Exposure | `HIGH` | CWE-200 | Wildcard read/decrypt access (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, `s3:GetObject`) on `Resource: "*"` without a narrowing `Condition` |
| `IAM-ESC-001` | Privilege Escalation | `CRITICAL` | CWE-269 | Direct IAM policy/trust mutation (`iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`, etc.) or `iam:PassRole` + compute execution creation |
| `IAM-ESC-002` | Privilege Escalation | `HIGH` | CWE-269 | Unrestricted `sts:AssumeRole` on `Resource: "*"` enabling lateral/cross-account role chaining |
| `IAM-BOUND-001` | Permission Boundary | `MEDIUM` | CWE-269 | High-privilege IAM role lacks static `permissions_boundary` in IaC (discloses `AWS_SCP_UNKNOWN`) |
| `IAM-CORR-001` | Workflow Identity Chain | `CRITICAL` / `HIGH` | CWE-269 | Cross-file static correlation linking a GitHub Actions workflow (`id-token: write` / `configure-aws-credentials` `role-to-assume`) → AWS OIDC trust policy → over-privileged AWS IAM role |
