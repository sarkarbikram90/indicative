import type {
  FindingConfidence,
  FindingSeverity,
  RawScannerFinding,
  ScannerLimitation
} from "@indicative/contracts";

export const CICD_RULESET_VERSION = "indicative-cicd-gha-v1.0.0";
export const CICD_SCANNER_NAME = "cicd-github-actions";
export const CICD_SCANNER_VERSION = "1.0.0";

export type CicdRuleCategory =
  | "PERMISSIONS"
  | "TRIGGERS"
  | "EXPRESSION_INJECTION"
  | "SUPPLY_CHAIN"
  | "SECRETS"
  | "BUILD_INTEGRITY"
  | "OIDC_FEDERATION";

export interface CicdRuleDefinition {
  ruleId: string;
  version: string;
  category: CicdRuleCategory;
  title: string;
  defaultSeverity: FindingSeverity;
  defaultConfidence: FindingConfidence;
  cwe: string;
  owaspCicd: string;
  summary: string;
  impact: string;
  remediation: string;
  falsePositiveNotes: string;
  limitations: string;
  references: string[];
}

export type PermissionAccess = "read" | "write" | "none";

export interface WorkflowPermissionsBlock {
  mode: "write-all" | "read-all" | "scoped" | "empty";
  scopes: Record<string, PermissionAccess>;
  lineStart: number;
  lineEnd: number;
}

export interface WorkflowTrigger {
  event: string;
  branches?: string[];
  types?: string[];
  lineStart: number;
  lineEnd: number;
}

export interface WorkflowStep {
  index: number;
  id?: string;
  name?: string;
  uses?: string;
  withInputs: Record<string, string>;
  run?: string;
  env: Record<string, string>;
  shell?: string;
  lineStart: number;
  lineEnd: number;
  usesLine?: number;
  runLine?: number;
}

export interface WorkflowJob {
  jobId: string;
  name?: string;
  runsOn?: string;
  environment?: string;
  usesReusableWorkflow?: string;
  secretsInherit: boolean;
  permissions?: WorkflowPermissionsBlock;
  env: Record<string, string>;
  steps: WorkflowStep[];
  lineStart: number;
  lineEnd: number;
}

export interface ParsedWorkflow {
  filePath: string;
  name: string;
  triggers: WorkflowTrigger[];
  permissions?: WorkflowPermissionsBlock;
  env: Record<string, string>;
  jobs: WorkflowJob[];
  referencedSecrets: string[];
  thirdPartyActions: Array<{
    action: string;
    pinnedToSha: boolean;
    jobId: string;
    lineStart: number;
  }>;
  usesOidc: boolean;
  oidcCloudTargets: Array<"aws" | "azure" | "gcp" | "generic">;
  rawLines: string[];
}

export interface OidcTrustPolicy {
  id: string;
  provider: "aws" | "azure" | "gcp";
  format: "terraform" | "cloudformation-json" | "cloudformation-yaml" | "arm-json";
  filePath: string;
  resourceName: string;
  lineStart: number;
  lineEnd: number;
  subjects: string[];
  audiences: string[];
  hasWildcardSubject: boolean;
  hasMissingSubject: boolean;
  hasMissingOrWildcardAudience: boolean;
  hasBranchOrEnvRestriction: boolean;
  snippet: string;
}

export type CicdPolicyMode = "informational" | "warning" | "failure";

export interface CicdPolicyConfig {
  mode?: CicdPolicyMode;
  failOnSeverities?: FindingSeverity[];
  disabledRules?: string[];
  allowedActionOwners?: string[];
  ignorePaths?: string[];
  configPath?: string;
  disableRepoConfig?: boolean;
  baselinePath?: string;
  nowDateIso?: string;
}

export interface SuppressedFindingRecord {
  ruleId: string;
  filePath?: string;
  lineStart?: number;
  title: string;
  severity: FindingSeverity;
  source: "inline" | "config-rule" | "config-suppression";
  reason: string;
  expires?: string;
}

export interface ExpiredSuppressionRecord {
  ruleId: string;
  filePath?: string;
  lineStart?: number;
  source: "inline" | "config-suppression";
  reason: string;
  expires: string;
}

export interface BaselineDiffSummary {
  baselinePath: string;
  baselineEntriesCount: number;
  newFindingsCount: number;
  existingBaselineFindingsCount: number;
  resolvedBaselineCount: number;
}

export interface CicdPolicyEvaluation {
  mode: CicdPolicyMode;
  passed: boolean;
  exitCode: 0 | 1;
  blockingFindingsCount: number;
  warningFindingsCount: number;
  summary: string;
}

export interface CicdAnalysisReport {
  scanner: string;
  scannerVersion: string;
  rulesetVersion: string;
  analyzedAt: string;
  configPath?: string;
  workflows: ParsedWorkflow[];
  oidcTrustPolicies: OidcTrustPolicy[];
  findings: RawScannerFinding[];
  newFindings?: RawScannerFinding[];
  baselineFindings?: RawScannerFinding[];
  suppressedFindings: SuppressedFindingRecord[];
  expiredSuppressions: ExpiredSuppressionRecord[];
  baselineDiff?: BaselineDiffSummary;
  limitations: ScannerLimitation[];
  policyEvaluation: CicdPolicyEvaluation;
}
