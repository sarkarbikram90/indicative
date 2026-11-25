import type { CloudIdentityRuleDefinition } from "../types.js";

export const CLOUD_IDENTITY_RULE_CATALOG: Record<string, CloudIdentityRuleDefinition> = {
  "IAM-ADMIN-001": {
    ruleId: "IAM-ADMIN-001",
    version: "1.0.0",
    category: "ADMIN_ACCESS",
    title: "Unrestricted AWS IAM administrator permissions granted",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-250",
    summary:
      "An AWS IAM role or policy grants full administrative access via `Action: \"*\"` on `Resource: \"*\"` or attaches an overly broad AWS managed policy such as `AdministratorAccess` or `IAMFullAccess`.",
    impact:
      "Any compromised workload, CI/CD job, or principal able to assume this role gains complete control over the AWS account, including IAM manipulation, secret exfiltration, and production infrastructure destruction.",
    remediation:
      "Replace `AdministratorAccess` / `Action: \"*\"` with explicit, least-privilege service actions restricted to exact resource ARNs required for the workload or deployment.",
    falsePositiveNotes:
      "Break-glass human emergency roles gated by MFA and strict approval workflows may intentionally hold AdministratorAccess, though CI/CD and workload roles should never hold unrestricted admin rights.",
    limitations:
      "Static IaC analysis cannot verify account-level AWS Service Control Policies (SCPs) or out-of-band runtime IAM policy edits.",
    references: [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
    ]
  },

  "IAM-PERM-001": {
    ruleId: "IAM-PERM-001",
    version: "1.0.0",
    category: "OVER_PRIVILEGED_POLICY",
    title: "Broad AWS service wildcard permissions granted on all resources",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-732",
    summary:
      "An IAM Allow statement grants all actions for a sensitive AWS service (for example `s3:*`, `iam:*`, `ec2:*`, `rds:*`, `secretsmanager:*`, `kms:*`, `eks:*`, `lambda:*`) across `Resource: \"*\"`.",
    impact:
      "Over-scoped service wildcards allow reading, modifying, or deleting resources belonging to unrelated applications, environments, or security controls across the account.",
    remediation:
      "Restrict `Action` to the minimum required operations (for example `s3:PutObject`, `s3:GetObject`) and constrain `Resource` to the exact target resource ARNs.",
    falsePositiveNotes:
      "Some AWS describe/list APIs require `Resource: \"*\"`, but write/wildcard `service:*` grants should always be scoped to specific ARNs or paired with strict `Condition` keys.",
    limitations:
      "Static analysis inspects declared statements and `Condition` keys; account-level SCPs and runtime Permission Boundaries are not verified statically.",
    references: [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
    ]
  },

  "IAM-PERM-002": {
    ruleId: "IAM-PERM-002",
    version: "1.0.0",
    category: "OVER_PRIVILEGED_POLICY",
    title: "Allow statement uses overly permissive NotAction or NotResource",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-732",
    summary:
      "An IAM `Allow` statement uses `NotAction` or `NotResource`, implicitly granting access to every AWS action or resource not explicitly listed.",
    impact:
      "Combining `Effect: \"Allow\"` with `NotAction` or `NotResource` creates implicit near-administrative access and automatically expands permissions whenever AWS launches new services or resources.",
    remediation:
      "Rewrite `Allow` statements using explicit `Action` and `Resource` allowlists; reserve `NotAction`/`NotResource` strictly for explicit `Deny` guardrails.",
    falsePositiveNotes:
      "Rarely false positive when used with `Effect: \"Allow\"`.",
    limitations: "Static configuration analysis only; runtime SCPs are not evaluated.",
    references: [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html"
    ]
  },

  "IAM-DATA-001": {
    ruleId: "IAM-DATA-001",
    version: "1.0.0",
    category: "SENSITIVE_DATA_EXPOSURE",
    title: "Wildcard read or decrypt access to secrets, KMS keys, or S3 data",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-200",
    summary:
      "An IAM policy allows reading secrets, parameters, S3 objects, or decrypting KMS ciphertext (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, `s3:GetObject`) across `Resource: \"*\"` without a narrowing condition.",
    impact:
      "A compromised CI/CD runner or workload assuming this role can bulk-exfiltrate production credentials, database passwords, API keys, and sensitive customer data across the account.",
    remediation:
      "Scope secret, KMS key, and S3 bucket access to exact application-specific ARN prefixes (for example `arn:aws:secretsmanager:us-east-1:123456789012:secret:app-prod/*`).",
    falsePositiveNotes:
      "Backup or central secret-auditing services may require broad read scope, in which case strict resource-tag conditions (`aws:ResourceTag/*`) and isolated accounts should be enforced.",
    limitations:
      "KMS key policies and Secrets Manager resource policies may further restrict access at runtime (`UNKNOWN` statically).",
    references: [
      "https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html"
    ]
  },

  "IAM-ESC-001": {
    ruleId: "IAM-ESC-001",
    version: "1.0.0",
    category: "PRIVILEGE_ESCALATION",
    title: "AWS IAM privilege-escalation primitive granted",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-269",
    summary:
      "The IAM policy grants permissions known to allow direct or indirect privilege escalation — such as mutating IAM policies/trust relationships (`iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`) or combining `iam:PassRole` with compute/deployment creation.",
    impact:
      "An attacker who compromises this identity can self-grant AdministratorAccess, attach a higher-privileged role to a new Lambda/EC2/ECS task, or modify trust policies to persist across the account.",
    remediation:
      "Remove IAM policy-mutation actions from application and deployment roles. Where `iam:PassRole` is required, restrict its `Resource` to exact target role ARNs and enforce `iam:PassedToService` conditions plus a mandatory `permissions_boundary`.",
    falsePositiveNotes:
      "Infrastructure-provisioning Terraform roles may legitimately manage IAM resources, but should be strictly gated by protected GitHub environments, approvals, and AWS Permission Boundaries.",
    limitations:
      "Static analysis flags known escalation primitives; account-level SCPs or Permission Boundaries attached outside this repository are not verified statically.",
    references: [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
    ]
  },

  "IAM-ESC-002": {
    ruleId: "IAM-ESC-002",
    version: "1.0.0",
    category: "PRIVILEGE_ESCALATION",
    title: "Unrestricted sts:AssumeRole allows lateral or cross-account role chaining",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-269",
    summary:
      "An IAM policy allows `sts:AssumeRole` on `Resource: \"*\"`, permitting the principal to attempt assuming any reachable IAM role in the current or external AWS accounts.",
    impact:
      "If any higher-privileged role trusts the account root or has a permissive trust policy, this role can pivot laterally or escalate privileges across environments.",
    remediation:
      "Restrict `sts:AssumeRole` `Resource` strictly to the explicit list of target role ARNs that this workload or pipeline is authorized to assume.",
    falsePositiveNotes:
      "Cross-account orchestration roles must still maintain an explicit target role ARN allowlist rather than `*`.",
    limitations:
      "Actual lateral movement also depends on target roles' trust policies (`UNKNOWN` unless defined in the same repository).",
    references: [
      "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html"
    ]
  },

  "IAM-BOUND-001": {
    ruleId: "IAM-BOUND-001",
    version: "1.0.0",
    category: "PERMISSION_BOUNDARY",
    title: "High-privilege AWS IAM role missing static permissions boundary",
    defaultSeverity: "MEDIUM",
    defaultConfidence: "MEDIUM",
    cwe: "CWE-269",
    summary:
      "A high-privilege AWS IAM role (granting admin, privilege-escalation, or broad wildcard access) does not configure `permissions_boundary` in static IaC.",
    impact:
      "Without a permissions boundary, accidental policy drift or IAM privilege-escalation primitives can expand effective permissions to full account control.",
    remediation:
      "Attach an explicit `permissions_boundary` ARN on high-privilege CI/CD and workload roles to cap maximum effective permissions.",
    falsePositiveNotes:
      "Organizations enforcing strict account-level AWS Service Control Policies (SCPs) or out-of-band boundary automation reduce this risk, though explicit IaC boundaries remain recommended defense-in-depth.",
    limitations:
      "Static analysis cannot verify account-level AWS SCPs (`AWS_SCP_UNKNOWN`).",
    references: [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
    ]
  },

  "IAM-CORR-001": {
    ruleId: "IAM-CORR-001",
    version: "1.0.0",
    category: "WORKFLOW_IDENTITY_CHAIN",
    title: "Correlated CI/CD-to-Cloud attack path: workflow linked to over-privileged AWS IAM role",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-269",
    summary:
      "Cross-file static correlation links a GitHub Actions workflow requesting AWS OIDC credentials to a repository-defined AWS IAM role holding excessive permissions (admin, privilege escalation, or wildcard service/secret access).",
    impact:
      "Compromising the workflow (or exploiting a broad OIDC trust policy / untrusted trigger) directly yields temporary AWS STS credentials for an over-privileged IAM role, bridging code/CI delivery into cloud infrastructure compromise.",
    remediation:
      "Break the attack chain at every hop: (1) scope `id-token: write` strictly to a protected deployment job with a GitHub `environment:`, (2) restrict the AWS IAM OIDC `sub` claim to exact repo + protected branch/environment, and (3) reduce the IAM role's permissions to least-privilege resource ARNs.",
    falsePositiveNotes:
      "Even when a deployment workflow intentionally deploys infrastructure, linking `id-token: write` to wildcard OIDC trust or unrestricted Admin/escalation IAM permissions represents material blast-radius risk.",
    limitations:
      "All hops reflect deterministic static configuration evidence (`VERIFIED_STATIC` / `INFERRED`). Live GitHub branch protection, GitHub environment required reviewers, AWS SCPs, and live IAM drift are explicitly reported as `UNKNOWN`.",
    references: [
      "https://docs.github.com/en/actions/concepts/security/openid-connect",
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html"
    ]
  }
};

export function getCloudIdentityRule(ruleId: string): CloudIdentityRuleDefinition {
  const rule = CLOUD_IDENTITY_RULE_CATALOG[ruleId];
  if (!rule) {
    throw new Error(`Unknown Cloud Identity rule ID: ${ruleId}`);
  }
  return rule;
}
