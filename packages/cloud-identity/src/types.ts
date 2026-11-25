import type {
  FindingConfidence,
  FindingSeverity,
  RawScannerFinding,
  ScannerLimitation
} from "@indicative/contracts";
import type {
  CicdPolicyEvaluation,
  CicdPolicyMode,
  OidcTrustPolicy,
  ParsedWorkflow
} from "@indicative/cicd-security";

export const CLOUD_IDENTITY_SCANNER_NAME = "cloud-identity-iam";
export const CLOUD_IDENTITY_SCANNER_VERSION = "1.0.0";
export const CLOUD_IDENTITY_RULESET_VERSION = "indicative-cloud-iam-v1.0.0";

export type CloudIdentityRuleCategory =
  | "ADMIN_ACCESS"
  | "OVER_PRIVILEGED_POLICY"
  | "SENSITIVE_DATA_EXPOSURE"
  | "PRIVILEGE_ESCALATION"
  | "PERMISSION_BOUNDARY"
  | "WORKFLOW_IDENTITY_CHAIN";

export interface CloudIdentityRuleDefinition {
  ruleId: string;
  version: string;
  category: CloudIdentityRuleCategory;
  title: string;
  defaultSeverity: FindingSeverity;
  defaultConfidence: FindingConfidence;
  cwe: string;
  summary: string;
  impact: string;
  remediation: string;
  falsePositiveNotes: string;
  limitations: string;
  references: string[];
}

export interface IamPolicyStatement {
  sid?: string;
  effect: "Allow" | "Deny";
  actions: string[];
  notActions: string[];
  resources: string[];
  notResources: string[];
  conditionKeys: string[];
  hasCondition: boolean;
  sourceFilePath: string;
  lineStart: number;
  lineEnd: number;
  sourceKind:
    | "inline_policy"
    | "role_policy"
    | "managed_policy"
    | "policy_document"
    | "standalone_json";
  policyName: string;
  snippet: string;
}

export interface CloudIamRole {
  id: string;
  provider: "aws";
  format: "terraform" | "cloudformation-yaml" | "cloudformation-json" | "iam-json";
  filePath: string;
  resourceId: string;
  roleName: string;
  lineStart: number;
  lineEnd: number;
  hasPermissionsBoundary: boolean;
  permissionsBoundaryRef?: string;
  managedPolicyArns: string[];
  statements: IamPolicyStatement[];
  oidcTrust?: OidcTrustPolicy;
  snippet: string;
}

export interface StandaloneIamPolicy {
  id: string;
  provider: "aws";
  format: "terraform" | "cloudformation-yaml" | "cloudformation-json" | "iam-json";
  filePath: string;
  policyName: string;
  lineStart: number;
  lineEnd: number;
  statements: IamPolicyStatement[];
  snippet: string;
}

export interface WorkflowCloudIdentityRef {
  provider: "aws" | "azure" | "gcp";
  workflowFilePath: string;
  workflowName: string;
  jobId: string;
  environment?: string;
  action: string;
  roleToAssume?: string;
  roleNameHint?: string;
  clientId?: string;
  workloadIdentityProvider?: string;
  serviceAccount?: string;
  audience?: string;
  hasIdTokenWrite: boolean;
  hasUntrustedTrigger: boolean;
  triggers: string[];
  lineStart: number;
  lineEnd: number;
}

export type RoleCapabilityTier =
  | "ADMIN"
  | "PRIVILEGE_ESCALATION"
  | "SENSITIVE_DATA_WILDCARD"
  | "BROAD_SERVICE_WILDCARD"
  | "SCOPED";

export interface CorrelatedIdentityChainHop {
  hopNumber: number;
  domain: "CICD_WORKFLOW" | "OIDC_TRUST" | "CLOUD_IAM_ROLE" | "CLOUD_RESOURCE_TARGET";
  label: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  evidenceBasis: "VERIFIED_STATIC" | "INFERRED" | "UNKNOWN";
  detail: string;
}

export interface CorrelatedIdentityChain {
  id: string;
  severity: FindingSeverity;
  workflowFilePath: string;
  workflowName: string;
  jobId: string;
  roleResourceId: string;
  roleName: string;
  roleFilePath: string;
  capabilityTier: RoleCapabilityTier;
  linkConfidence: "EXACT_ROLE_MATCH" | "REPO_OIDC_INFERRED";
  hops: CorrelatedIdentityChainHop[];
  unknownControls: string[];
  remediationBreakpoints: string[];
}

export interface CloudIdentityPolicyConfig {
  mode?: CicdPolicyMode;
  failOnSeverities?: FindingSeverity[];
  disabledRules?: string[];
  ignorePaths?: string[];
}

export interface CloudIdentityAnalysisReport {
  scanner: string;
  scannerVersion: string;
  rulesetVersion: string;
  analyzedAt: string;
  workflows: ParsedWorkflow[];
  workflowIdentityRefs: WorkflowCloudIdentityRef[];
  iamRoles: CloudIamRole[];
  standalonePolicies: StandaloneIamPolicy[];
  correlatedChains: CorrelatedIdentityChain[];
  findings: RawScannerFinding[];
  limitations: ScannerLimitation[];
  policyEvaluation: CicdPolicyEvaluation;
}
