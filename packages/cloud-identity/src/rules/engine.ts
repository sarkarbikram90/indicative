import crypto from "node:crypto";
import type { FindingSeverity, RawScannerFinding } from "@indicative/contracts";
import type { OidcTrustPolicy, ParsedWorkflow } from "@indicative/cicd-security";
import { redactSecretsInText } from "@indicative/security";
import {
  CLOUD_IDENTITY_RULESET_VERSION,
  CLOUD_IDENTITY_SCANNER_NAME,
  CLOUD_IDENTITY_SCANNER_VERSION,
  type CloudIamRole,
  type CorrelatedIdentityChain,
  type CorrelatedIdentityChainHop,
  type IamPolicyStatement,
  type RoleCapabilityTier,
  type StandaloneIamPolicy,
  type WorkflowCloudIdentityRef
} from "../types.js";
import { getCloudIdentityRule } from "./registry.js";

const ADMIN_MANAGED_POLICIES = new Set([
  "administratoraccess",
  "iamfullaccess",
  "poweruseraccess"
]);

const HIGH_RISK_SERVICE_WILDCARDS = new Set([
  "s3",
  "iam",
  "ec2",
  "rds",
  "secretsmanager",
  "kms",
  "eks",
  "ecs",
  "ecr",
  "lambda",
  "sts",
  "dynamodb",
  "ssm",
  "cloudformation",
  "organizations",
  "route53"
]);

const SENSITIVE_DATA_ACTIONS = [
  "secretsmanager:getsecretvalue",
  "secretsmanager:batchgetsecretvalue",
  "ssm:getparameter",
  "ssm:getparameters",
  "ssm:getparametersbypath",
  "kms:decrypt",
  "s3:getobject"
];

const DIRECT_IAM_ESCALATION_ACTIONS = new Set([
  "iam:putrolepolicy",
  "iam:attachrolepolicy",
  "iam:createpolicyversion",
  "iam:setdefaultpolicyversion",
  "iam:updateassumerolepolicy",
  "iam:putuserpolicy",
  "iam:attachuserpolicy",
  "iam:putgrouppolicy",
  "iam:attachgrouppolicy",
  "iam:addusertogroup",
  "iam:createaccesskey",
  "iam:createloginprofile",
  "iam:updateloginprofile"
]);

const PASSROLE_COMPUTE_ACTIONS = new Set([
  "lambda:createfunction",
  "lambda:updatefunctioncode",
  "lambda:invokefunction",
  "ec2:runinstances",
  "ecs:runtask",
  "ecs:registertaskdefinition",
  "cloudformation:createstack",
  "cloudformation:updatestack",
  "glue:createdevendpoint",
  "codebuild:createproject",
  "datapipeline:createpipeline"
]);

const DEFAULT_UNKNOWN_CONTROLS = [
  "GITHUB_BRANCH_PROTECTION_UNKNOWN",
  "GITHUB_ENV_APPROVAL_GATES_UNKNOWN",
  "AWS_SCP_UNKNOWN",
  "LIVE_IAM_DRIFT_UNKNOWN"
];

function isWildcardResource(resources: string[]): boolean {
  return resources.some((r) => {
    const trimmed = r.trim();
    return trimmed === "*" || /^arn:aws[^:]*:[^:]*:[^:]*:[^:]*:\*$/i.test(trimmed);
  });
}

function actionMatches(pattern: string, target: string): boolean {
  const p = pattern.trim().toLowerCase();
  const t = target.trim().toLowerCase();
  if (p === "*" || p === "*:*") return true;
  if (p === t) return true;
  if (p.endsWith("*")) {
    const prefix = p.slice(0, -1);
    return t.startsWith(prefix);
  }
  return false;
}

function extractManagedPolicyName(arn: string): string {
  const idx = arn.lastIndexOf("/");
  return (idx >= 0 ? arn.slice(idx + 1) : arn).trim();
}

function buildFinding(params: {
  ruleId: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  titleSuffix: string;
  description: string;
  codeSnippet: string;
  severityOverride?: FindingSeverity;
  identityAnchor: string;
  rawMetadata?: Record<string, string | number | boolean>;
}): RawScannerFinding {
  const rule = getCloudIdentityRule(params.ruleId);
  const severity = params.severityOverride ?? rule.defaultSeverity;

  return {
    scanner: CLOUD_IDENTITY_SCANNER_NAME,
    scannerVersion: CLOUD_IDENTITY_SCANNER_VERSION,
    rulesetVersion: CLOUD_IDENTITY_RULESET_VERSION,
    ruleId: rule.ruleId,
    category: "CLOUD_IDENTITY",
    title: redactSecretsInText(`${rule.title} (${params.titleSuffix})`),
    description: redactSecretsInText(
      `${params.description} Impact: ${rule.impact} Limitations: ${rule.limitations}`
    ),
    originalSeverity: severity,
    severity,
    confidence: rule.defaultConfidence,
    filePath: params.filePath,
    lineStart: params.lineStart,
    lineEnd: params.lineEnd,
    codeSnippet: redactSecretsInText(params.codeSnippet),
    references: rule.references,
    remediationHint: `${rule.remediation}\n\nFalse-positive considerations: ${rule.falsePositiveNotes}`,
    rawMetadata: {
      cwe: rule.cwe,
      ruleCategory: rule.category,
      ruleVersion: rule.version,
      identityAnchor: params.identityAnchor,
      evidenceBasis: "STATIC_CONFIG",
      ...(params.rawMetadata ?? {})
    }
  };
}

interface StatementEvaluationSummary {
  hasAdmin: boolean;
  hasEscalation: boolean;
  hasSensitiveDataWildcard: boolean;
  hasBroadServiceWildcard: boolean;
  triggeredCapabilities: string[];
  targetResources: string[];
}

function evaluateStatements(params: {
  ownerLabel: string;
  ownerAnchorPrefix: string;
  statements: IamPolicyStatement[];
  disabledRules: Set<string>;
  findings: RawScannerFinding[];
}): StatementEvaluationSummary {
  const summary: StatementEvaluationSummary = {
    hasAdmin: false,
    hasEscalation: false,
    hasSensitiveDataWildcard: false,
    hasBroadServiceWildcard: false,
    triggeredCapabilities: [],
    targetResources: []
  };

  const allowStatements = params.statements.filter((s) => s.effect === "Allow");
  const allAllowActions = new Set<string>();
  let passRoleStmt: IamPolicyStatement | undefined;

  for (const stmt of allowStatements) {
    const wildcardRes = isWildcardResource(stmt.resources);
    for (const r of stmt.resources) {
      if (!summary.targetResources.includes(r)) summary.targetResources.push(r);
    }
    for (const a of stmt.actions) {
      allAllowActions.add(a.toLowerCase());
      if (actionMatches(a, "iam:passrole")) {
        passRoleStmt = stmt;
      }
    }

    // 1. IAM-ADMIN-001: Action "*" on Resource "*"
    const hasFullWildcardAction = stmt.actions.some((a) => a === "*" || a === "*:*");
    if (hasFullWildcardAction && wildcardRes) {
      summary.hasAdmin = true;
      summary.triggeredCapabilities.push("Action:* on Resource:*");
      if (!params.disabledRules.has("IAM-ADMIN-001")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-ADMIN-001",
            filePath: stmt.sourceFilePath,
            lineStart: stmt.lineStart,
            lineEnd: stmt.lineEnd,
            titleSuffix: `${params.ownerLabel} (${stmt.policyName})`,
            description: `Policy "${stmt.policyName}" on ${params.ownerLabel} grants unrestricted "Action: *" on "Resource: *"${
              stmt.hasCondition
                ? ` (conditional on: ${stmt.conditionKeys.join(", ")})`
                : ""
            }.`,
            codeSnippet: stmt.snippet,
            severityOverride: stmt.hasCondition ? "HIGH" : "CRITICAL",
            identityAnchor: `${params.ownerAnchorPrefix}:admin-wildcard:${stmt.policyName}`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              policyName: stmt.policyName,
              hasCondition: stmt.hasCondition,
              conditionKeys: stmt.conditionKeys.join(",")
            }
          })
        );
      }
      continue;
    }

    // 2. IAM-PERM-002: Allow + NotAction / NotResource
    if (stmt.notActions.length > 0 || stmt.notResources.length > 0) {
      summary.hasBroadServiceWildcard = true;
      summary.triggeredCapabilities.push(
        stmt.notActions.length > 0 ? "Allow+NotAction" : "Allow+NotResource"
      );
      if (!params.disabledRules.has("IAM-PERM-002")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-PERM-002",
            filePath: stmt.sourceFilePath,
            lineStart: stmt.lineStart,
            lineEnd: stmt.lineEnd,
            titleSuffix: `${params.ownerLabel} (${stmt.policyName})`,
            description: `Allow statement in "${stmt.policyName}" on ${params.ownerLabel} uses ${
              stmt.notActions.length > 0 ? "NotAction" : "NotResource"
            }, implicitly granting broad access outside the excluded list.`,
            codeSnippet: stmt.snippet,
            identityAnchor: `${params.ownerAnchorPrefix}:not-action-resource:${stmt.policyName}`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              policyName: stmt.policyName
            }
          })
        );
      }
    }

    // 3. IAM-PERM-001: Service wildcards (s3:*, iam:*, secretsmanager:*, etc.) on Resource: "*"
    const matchedServiceWildcards = stmt.actions.filter((a) => {
      const m = a.toLowerCase().match(/^([a-z0-9-]+):\*$/);
      return Boolean(m?.[1] && HIGH_RISK_SERVICE_WILDCARDS.has(m[1]));
    });
    if (matchedServiceWildcards.length > 0 && wildcardRes) {
      summary.hasBroadServiceWildcard = true;
      summary.triggeredCapabilities.push(...matchedServiceWildcards);
      if (!params.disabledRules.has("IAM-PERM-001")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-PERM-001",
            filePath: stmt.sourceFilePath,
            lineStart: stmt.lineStart,
            lineEnd: stmt.lineEnd,
            titleSuffix: `${params.ownerLabel}: ${matchedServiceWildcards.join(", ")}`,
            description: `Policy "${stmt.policyName}" on ${params.ownerLabel} grants broad service wildcard(s) (${matchedServiceWildcards.join(", ")}) on "Resource: *"${
              stmt.hasCondition
                ? ` with Condition (${stmt.conditionKeys.join(", ")})`
                : " without narrowing resource ARN or Condition"
            }.`,
            codeSnippet: stmt.snippet,
            severityOverride: stmt.hasCondition ? "MEDIUM" : "HIGH",
            identityAnchor: `${params.ownerAnchorPrefix}:service-wildcard:${matchedServiceWildcards.sort().join(",")}`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              policyName: stmt.policyName,
              wildcardActions: matchedServiceWildcards.join(","),
              hasCondition: stmt.hasCondition
            }
          })
        );
      }
    }

    // 4. IAM-DATA-001: Sensitive secret/key/S3 read on Resource: "*" without Condition
    const matchedSensitiveData = stmt.actions.filter((a) => {
      const lower = a.toLowerCase();
      if (lower.endsWith(":*")) return false; // Already captured as service wildcard above
      return SENSITIVE_DATA_ACTIONS.some((target) => actionMatches(lower, target));
    });
    if (matchedSensitiveData.length > 0 && wildcardRes && !stmt.hasCondition) {
      summary.hasSensitiveDataWildcard = true;
      summary.triggeredCapabilities.push(...matchedSensitiveData);
      if (!params.disabledRules.has("IAM-DATA-001")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-DATA-001",
            filePath: stmt.sourceFilePath,
            lineStart: stmt.lineStart,
            lineEnd: stmt.lineEnd,
            titleSuffix: `${params.ownerLabel}: ${matchedSensitiveData.join(", ")}`,
            description: `Policy "${stmt.policyName}" on ${params.ownerLabel} permits sensitive secret/data read (${matchedSensitiveData.join(", ")}) on wildcard "Resource: *" without a Condition.`,
            codeSnippet: stmt.snippet,
            identityAnchor: `${params.ownerAnchorPrefix}:sensitive-data:${matchedSensitiveData.sort().join(",")}`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              policyName: stmt.policyName,
              sensitiveActions: matchedSensitiveData.join(",")
            }
          })
        );
      }
    }

    // 5. IAM-ESC-001 (Direct IAM escalation actions)
    const directEsc = stmt.actions.filter((a) => {
      const lower = a.toLowerCase();
      if (lower === "iam:*") return true;
      for (const esc of DIRECT_IAM_ESCALATION_ACTIONS) {
        if (actionMatches(lower, esc)) return true;
      }
      return false;
    });
    if (directEsc.length > 0) {
      summary.hasEscalation = true;
      summary.triggeredCapabilities.push(...directEsc);
      if (!params.disabledRules.has("IAM-ESC-001")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-ESC-001",
            filePath: stmt.sourceFilePath,
            lineStart: stmt.lineStart,
            lineEnd: stmt.lineEnd,
            titleSuffix: `${params.ownerLabel}: ${directEsc.join(", ")}`,
            description: `Policy "${stmt.policyName}" on ${params.ownerLabel} grants IAM privilege-escalation action(s) (${directEsc.join(", ")}).`,
            codeSnippet: stmt.snippet,
            severityOverride: stmt.hasCondition && !wildcardRes ? "HIGH" : "CRITICAL",
            identityAnchor: `${params.ownerAnchorPrefix}:iam-esc-direct:${directEsc.sort().join(",")}`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              policyName: stmt.policyName,
              escalationPrimitives: directEsc.join(",")
            }
          })
        );
      }
    }

    // 6. IAM-ESC-002: Unrestricted sts:AssumeRole on Resource: "*"
    const hasAssumeRole = stmt.actions.some(
      (a) => actionMatches(a, "sts:assumerole") && a.toLowerCase() !== "sts:assumerolewithwebidentity"
    );
    if (hasAssumeRole && wildcardRes) {
      summary.hasEscalation = true;
      summary.triggeredCapabilities.push("sts:AssumeRole on *");
      if (!params.disabledRules.has("IAM-ESC-002")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-ESC-002",
            filePath: stmt.sourceFilePath,
            lineStart: stmt.lineStart,
            lineEnd: stmt.lineEnd,
            titleSuffix: `${params.ownerLabel} (${stmt.policyName})`,
            description: `Policy "${stmt.policyName}" on ${params.ownerLabel} grants "sts:AssumeRole" on "Resource: *", allowing unrestricted lateral or cross-account role chaining.`,
            codeSnippet: stmt.snippet,
            identityAnchor: `${params.ownerAnchorPrefix}:sts-assume-wildcard:${stmt.policyName}`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              policyName: stmt.policyName
            }
          })
        );
      }
    }
  }

  // Cross-statement escalation check: iam:PassRole + compute creation
  if (passRoleStmt) {
    const matchedCompute: string[] = [];
    for (const action of allAllowActions) {
      for (const target of PASSROLE_COMPUTE_ACTIONS) {
        if (actionMatches(action, target)) {
          matchedCompute.push(action);
          break;
        }
      }
    }
    if (matchedCompute.length > 0) {
      summary.hasEscalation = true;
      summary.triggeredCapabilities.push(`iam:PassRole+${matchedCompute[0]}`);
      if (!params.disabledRules.has("IAM-ESC-001")) {
        params.findings.push(
          buildFinding({
            ruleId: "IAM-ESC-001",
            filePath: passRoleStmt.sourceFilePath,
            lineStart: passRoleStmt.lineStart,
            lineEnd: passRoleStmt.lineEnd,
            titleSuffix: `${params.ownerLabel}: iam:PassRole + ${matchedCompute.slice(0, 2).join(", ")}`,
            description: `${params.ownerLabel} combines "iam:PassRole" with execution/compute creation (${matchedCompute.slice(0, 3).join(", ")}), enabling privilege escalation by launching workloads under a higher-privileged role.`,
            codeSnippet: passRoleStmt.snippet,
            identityAnchor: `${params.ownerAnchorPrefix}:iam-passrole-compute`,
            rawMetadata: {
              evidenceType: "IAM_POLICY",
              escalationPrimitives: `iam:PassRole,${matchedCompute.slice(0, 3).join(",")}`
            }
          })
        );
      }
    }
  }

  return summary;
}

function determineCapabilityTier(summary: StatementEvaluationSummary): RoleCapabilityTier {
  if (summary.hasAdmin) return "ADMIN";
  if (summary.hasEscalation) return "PRIVILEGE_ESCALATION";
  if (summary.hasSensitiveDataWildcard) return "SENSITIVE_DATA_WILDCARD";
  if (summary.hasBroadServiceWildcard) return "BROAD_SERVICE_WILDCARD";
  return "SCOPED";
}

function attachOidcPoliciesToRoles(
  roles: CloudIamRole[],
  oidcPolicies: OidcTrustPolicy[]
): void {
  const awsOidc = oidcPolicies.filter((p) => p.provider === "aws");
  for (const role of roles) {
    const exact = awsOidc.find(
      (p) =>
        p.filePath === role.filePath &&
        (p.resourceName === role.resourceId || p.resourceName === role.roleName)
    );
    if (exact) {
      role.oidcTrust = exact;
      continue;
    }
    // Fallback: match by resourceName across files (e.g. data.aws_iam_policy_document linked to role)
    const byName = awsOidc.find(
      (p) =>
        p.resourceName.toLowerCase() === role.resourceId.toLowerCase() ||
        p.resourceName.toLowerCase() === role.roleName.toLowerCase()
    );
    if (byName) {
      role.oidcTrust = byName;
      continue;
    }
    // Single AWS OIDC trust policy in the same file as this role
    const sameFileAwsOidc = awsOidc.filter((p) => p.filePath === role.filePath);
    if (sameFileAwsOidc.length === 1 && roles.filter((r) => r.filePath === role.filePath).length === 1) {
      role.oidcTrust = sameFileAwsOidc[0];
    }
  }
}

export interface CloudIdentityEvaluationResult {
  findings: RawScannerFinding[];
  correlatedChains: CorrelatedIdentityChain[];
}

export function evaluateCloudIdentityRules(params: {
  workflows: ParsedWorkflow[];
  workflowIdentityRefs: WorkflowCloudIdentityRef[];
  iamRoles: CloudIamRole[];
  standalonePolicies: StandaloneIamPolicy[];
  oidcTrustPolicies: OidcTrustPolicy[];
  disabledRules?: string[];
}): CloudIdentityEvaluationResult {
  const disabled = new Set((params.disabledRules ?? []).map((r) => r.toUpperCase()));
  const findings: RawScannerFinding[] = [];
  const correlatedChains: CorrelatedIdentityChain[] = [];

  attachOidcPoliciesToRoles(params.iamRoles, params.oidcTrustPolicies);

  const roleTiers = new Map<string, { tier: RoleCapabilityTier; summary: StatementEvaluationSummary }>();

  // 1. Evaluate every AWS IAM Role
  for (const role of params.iamRoles) {
    const summary = evaluateStatements({
      ownerLabel: `IAM role "${role.roleName}"`,
      ownerAnchorPrefix: `role:${role.resourceId}`,
      statements: role.statements,
      disabledRules: disabled,
      findings
    });

    // Check high-privilege AWS managed policy attachments (AdministratorAccess, IAMFullAccess, PowerUserAccess)
    for (const arn of role.managedPolicyArns) {
      const policyName = extractManagedPolicyName(arn);
      const lower = policyName.toLowerCase();
      if (ADMIN_MANAGED_POLICIES.has(lower)) {
        summary.hasAdmin = true;
        summary.triggeredCapabilities.push(`ManagedPolicy:${policyName}`);
        if (!disabled.has("IAM-ADMIN-001")) {
          findings.push(
            buildFinding({
              ruleId: "IAM-ADMIN-001",
              filePath: role.filePath,
              lineStart: role.lineStart,
              lineEnd: role.lineEnd,
              titleSuffix: `${role.roleName} -> ${policyName}`,
              description: `AWS IAM role "${role.roleName}" attaches high-privilege AWS managed policy "${policyName}" (${arn}).`,
              codeSnippet: role.snippet,
              severityOverride: lower === "poweruseraccess" ? "HIGH" : "CRITICAL",
              identityAnchor: `role:${role.resourceId}:managed:${lower}`,
              rawMetadata: {
                evidenceType: "IAM_POLICY",
                roleName: role.roleName,
                managedPolicyArn: arn
              }
            })
          );
        }
      } else if (/fullaccess$/i.test(lower) && !lower.includes("readonly")) {
        summary.hasBroadServiceWildcard = true;
        summary.triggeredCapabilities.push(`ManagedPolicy:${policyName}`);
        if (!disabled.has("IAM-PERM-001")) {
          findings.push(
            buildFinding({
              ruleId: "IAM-PERM-001",
              filePath: role.filePath,
              lineStart: role.lineStart,
              lineEnd: role.lineEnd,
              titleSuffix: `${role.roleName} -> ${policyName}`,
              description: `AWS IAM role "${role.roleName}" attaches overly broad FullAccess managed policy "${policyName}" (${arn}).`,
              codeSnippet: role.snippet,
              identityAnchor: `role:${role.resourceId}:managed:${lower}`,
              rawMetadata: {
                evidenceType: "IAM_POLICY",
                roleName: role.roleName,
                managedPolicyArn: arn
              }
            })
          );
        }
      }
    }

    const tier = determineCapabilityTier(summary);
    roleTiers.set(role.id, { tier, summary });

    // IAM-BOUND-001: High-privilege role lacking permissions_boundary
    if (
      !disabled.has("IAM-BOUND-001") &&
      !role.hasPermissionsBoundary &&
      (tier === "ADMIN" || tier === "PRIVILEGE_ESCALATION" || tier === "BROAD_SERVICE_WILDCARD")
    ) {
      findings.push(
        buildFinding({
          ruleId: "IAM-BOUND-001",
          filePath: role.filePath,
          lineStart: role.lineStart,
          lineEnd: role.lineEnd,
          titleSuffix: role.roleName,
          description: `High-privilege AWS IAM role "${role.roleName}" (${tier}) does not define a static permissions_boundary in IaC. Account-level SCPs are not verifiable statically (AWS_SCP_UNKNOWN).`,
          codeSnippet: role.snippet,
          identityAnchor: `role:${role.resourceId}:missing-boundary`,
          rawMetadata: {
            evidenceType: "IAM_POLICY",
            roleName: role.roleName,
            capabilityTier: tier
          }
        })
      );
    }
  }

  // 2. Evaluate standalone IAM policies
  for (const policy of params.standalonePolicies) {
    evaluateStatements({
      ownerLabel: `IAM policy "${policy.policyName}"`,
      ownerAnchorPrefix: `policy:${policy.policyName}`,
      statements: policy.statements,
      disabledRules: disabled,
      findings
    });
  }

  // 3. Flagship Cross-Boundary Correlation (IAM-CORR-001):
  //    GitHub Actions Workflow -> OIDC Trust Policy -> Over-Privileged AWS IAM Role
  const awsWorkflowRefs = params.workflowIdentityRefs.filter((r) => r.provider === "aws");
  const fallbackOidcWorkflows = params.workflows.filter(
    (w) => w.usesOidc && (w.oidcCloudTargets.includes("aws") || w.oidcCloudTargets.includes("generic"))
  );

  for (const role of params.iamRoles) {
    const info = roleTiers.get(role.id);
    if (!info || info.tier === "SCOPED") continue;

    // Match explicit workflow aws-actions/configure-aws-credentials references first
    const matchedRefs: Array<{ ref: WorkflowCloudIdentityRef; exact: boolean }> = [];
    for (const ref of awsWorkflowRefs) {
      const hint = ref.roleNameHint?.toLowerCase();
      const exact =
        Boolean(hint) &&
        (hint === role.roleName.toLowerCase() || hint === role.resourceId.toLowerCase());
      if (exact) {
        matchedRefs.push({ ref, exact: true });
      } else if (role.oidcTrust && ref.hasIdTokenWrite) {
        matchedRefs.push({ ref, exact: false });
      }
    }

    // If no explicit configure-aws-credentials step matched, correlate via OIDC workflow + OIDC-trusting role
    if (matchedRefs.length === 0 && role.oidcTrust && fallbackOidcWorkflows.length > 0) {
      const wf = fallbackOidcWorkflows[0]!;
      matchedRefs.push({
        exact: false,
        ref: {
          provider: "aws",
          workflowFilePath: wf.filePath,
          workflowName: wf.name,
          jobId: wf.jobs[0]?.jobId ?? "default",
          environment: wf.jobs[0]?.environment,
          action: "id-token: write",
          hasIdTokenWrite: true,
          hasUntrustedTrigger: wf.triggers.some((t) =>
            ["pull_request_target", "workflow_run", "issue_comment"].includes(t.event)
          ),
          triggers: wf.triggers.map((t) => t.event),
          lineStart: 1,
          lineEnd: 5
        }
      });
    }

    for (const { ref, exact } of matchedRefs) {
      // Only emit chain when there is concrete linkage (exact role-to-assume match OR role trusts GitHub OIDC)
      if (!exact && !role.oidcTrust) continue;

      const broadOidc = Boolean(
        role.oidcTrust?.hasWildcardSubject || role.oidcTrust?.hasMissingSubject
      );
      const chainSeverity: FindingSeverity =
        info.tier === "ADMIN" ||
        info.tier === "PRIVILEGE_ESCALATION" ||
        broadOidc ||
        ref.hasUntrustedTrigger
          ? "CRITICAL"
          : "HIGH";

      const hops: CorrelatedIdentityChainHop[] = [
        {
          hopNumber: 1,
          domain: "CICD_WORKFLOW",
          label: `${ref.workflowFilePath} (job "${ref.jobId}")`,
          filePath: ref.workflowFilePath,
          lineStart: ref.lineStart,
          lineEnd: ref.lineEnd,
          evidenceBasis: "VERIFIED_STATIC",
          detail: `Triggers: [${ref.triggers.join(", ") || "unknown"}]; ${
            ref.hasIdTokenWrite ? "requests id-token: write" : "assumes AWS role"
          }${ref.roleToAssume ? ` targeting "${ref.roleToAssume}"` : ""}${
            ref.environment ? ` in environment "${ref.environment}"` : " (no GitHub environment gate)"
          }.`
        },
        {
          hopNumber: 2,
          domain: "OIDC_TRUST",
          label: role.oidcTrust
            ? `AWS OIDC Trust (${role.oidcTrust.resourceName})`
            : `AWS STS Role Assumption (${role.roleName})`,
          filePath: role.oidcTrust?.filePath ?? role.filePath,
          lineStart: role.oidcTrust?.lineStart ?? role.lineStart,
          lineEnd: role.oidcTrust?.lineEnd ?? role.lineEnd,
          evidenceBasis: role.oidcTrust ? "VERIFIED_STATIC" : "INFERRED",
          detail: role.oidcTrust
            ? `Subjects: [${role.oidcTrust.subjects.join(", ") || "MISSING"}]; ${
                broadOidc
                  ? "OVERLY BROAD / WILDCARD OIDC subject trust"
                  : "Scoped OIDC subject trust"
              }.`
            : `Workflow references role "${role.roleName}"; trust policy conditions defined outside matched OIDC block.`
        },
        {
          hopNumber: 3,
          domain: "CLOUD_IAM_ROLE",
          label: `AWS IAM Role "${role.roleName}" (${info.tier})`,
          filePath: role.filePath,
          lineStart: role.lineStart,
          lineEnd: role.lineEnd,
          evidenceBasis: "VERIFIED_STATIC",
          detail: `Effective static capabilities: ${
            [...new Set(info.summary.triggeredCapabilities)].slice(0, 5).join(", ") || info.tier
          }${role.hasPermissionsBoundary ? " (permissions_boundary declared)" : " (NO permissions_boundary)"}.`
        },
        {
          hopNumber: 4,
          domain: "CLOUD_RESOURCE_TARGET",
          label: info.summary.targetResources.includes("*")
            ? "Account-wide AWS resources (*)"
            : info.summary.targetResources.slice(0, 3).join(", ") || "Account AWS resources",
          evidenceBasis: "INFERRED",
          detail:
            "Actual runtime impact depends on account-level AWS SCPs, resource policies, and live IAM state (not verified statically)."
        }
      ];

      const breakpoints: string[] = [];
      if (ref.hasUntrustedTrigger || !ref.environment) {
        breakpoints.push(
          `Gate job "${ref.jobId}" in ${ref.workflowFilePath} behind a protected GitHub environment with required reviewers and disallow untrusted PR triggers.`
        );
      }
      if (broadOidc) {
        breakpoints.push(
          `Restrict AWS OIDC trust subject (sub) on "${role.roleName}" to an exact repository and protected branch or environment claim.`
        );
      }
      breakpoints.push(
        `Scope AWS IAM role "${role.roleName}" down from ${info.tier} to explicit least-privilege actions and target ARNs, and attach a permissions_boundary.`
      );

      const chainId = `chain:${crypto
        .createHash("sha256")
        .update(`${ref.workflowFilePath}|${ref.jobId}|${role.filePath}|${role.resourceId}`)
        .digest("hex")
        .slice(0, 12)}`;

      const chain: CorrelatedIdentityChain = {
        id: chainId,
        severity: chainSeverity,
        workflowFilePath: ref.workflowFilePath,
        workflowName: ref.workflowName,
        jobId: ref.jobId,
        roleResourceId: role.resourceId,
        roleName: role.roleName,
        roleFilePath: role.filePath,
        capabilityTier: info.tier,
        linkConfidence: exact ? "EXACT_ROLE_MATCH" : "REPO_OIDC_INFERRED",
        hops,
        unknownControls: [...DEFAULT_UNKNOWN_CONTROLS],
        remediationBreakpoints: breakpoints
      };
      correlatedChains.push(chain);

      if (!disabled.has("IAM-CORR-001")) {
        findings.push(
          buildFinding({
            ruleId: "IAM-CORR-001",
            filePath: role.filePath,
            lineStart: role.lineStart,
            lineEnd: role.lineEnd,
            titleSuffix: `${ref.workflowFilePath} [${ref.jobId}] -> ${role.roleName} (${info.tier})`,
            description: `Evidence-backed static chain (${chain.linkConfidence}): Workflow "${ref.workflowFilePath}" (job "${ref.jobId}", triggers: ${
              ref.triggers.join(",") || "unknown"
            }) links to AWS IAM role "${role.roleName}" (${info.tier}: ${[
              ...new Set(info.summary.triggeredCapabilities)
            ]
              .slice(0, 4)
              .join(", ")})${
              broadOidc ? " through an overly broad OIDC trust policy" : ""
            }. Unverified controls: ${DEFAULT_UNKNOWN_CONTROLS.join(", ")}.`,
            codeSnippet: role.snippet,
            severityOverride: chainSeverity,
            identityAnchor: `chain:${ref.workflowFilePath}:${ref.jobId}:${role.resourceId}`,
            rawMetadata: {
              evidenceType: "ATTACK_PATH_CHAIN",
              workflowFile: ref.workflowFilePath,
              jobId: ref.jobId,
              roleName: role.roleName,
              capabilityTier: info.tier,
              linkConfidence: chain.linkConfidence,
              broadOidcTrust: broadOidc,
              untrustedTrigger: ref.hasUntrustedTrigger,
              unknownControls: DEFAULT_UNKNOWN_CONTROLS.join(",")
            }
          })
        );
      }
    }
  }

  return { findings, correlatedChains };
}
