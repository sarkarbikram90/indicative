import { z } from "zod";
import { FindingCategorySchema, FindingConfidenceSchema, FindingSeveritySchema } from "./findings.js";

export const ScannerCapabilitySchema = z.enum([
  "sast",
  "sca",
  "secrets",
  "misconfiguration",
  "cicd",
  "cloud-identity"
]);
export type ScannerCapability = z.infer<typeof ScannerCapabilitySchema>;

export const ScannerNameSchema = z.enum([
  "semgrep",
  "trivy",
  "gitleaks",
  "cicd-github-actions",
  "cloud-identity-iam"
]);
export type ScannerName = z.infer<typeof ScannerNameSchema>;

export const DEFAULT_SCANNERS: readonly ScannerName[] = [
  "semgrep",
  "trivy",
  "gitleaks",
  "cicd-github-actions",
  "cloud-identity-iam"
];

export const ScannerExecutionStatusSchema = z.enum([
  "SUCCESS",
  "FAILED",
  "TIMEOUT",
  "CANCELLED",
  "PARTIAL",
  "UNAVAILABLE"
]);
export type ScannerExecutionStatus = z.infer<typeof ScannerExecutionStatusSchema>;

export const ScannerErrorClassSchema = z.enum([
  "NONE",
  "BINARY_NOT_FOUND",
  "TIMEOUT",
  "CANCELLED",
  "MALFORMED_OUTPUT",
  "RESOURCE_LIMIT",
  "INVALID_WORKSPACE",
  "EXECUTION_ERROR",
  "OFFLINE_DB_MISSING"
]);
export type ScannerErrorClass = z.infer<typeof ScannerErrorClassSchema>;

export const ScannerHealthSchema = z.object({
  scanner: z.string(),
  available: z.boolean(),
  version: z.string().optional(),
  rulesetVersion: z.string().optional(),
  message: z.string().optional(),
  checkedAt: z.string()
});
export type ScannerHealth = z.infer<typeof ScannerHealthSchema>;

export const RawScannerFindingSchema = z.object({
  scanner: z.string(),
  scannerVersion: z.string(),
  rulesetVersion: z.string().optional(),
  ruleId: z.string(),
  category: FindingCategorySchema,
  title: z.string(),
  description: z.string(),
  originalSeverity: z.string().optional(),
  severity: FindingSeveritySchema,
  confidence: FindingConfidenceSchema,
  filePath: z.string().optional(),
  lineStart: z.number().int().optional(),
  lineEnd: z.number().int().optional(),
  codeSnippet: z.string().optional(),
  packageName: z.string().optional(),
  installedVersion: z.string().optional(),
  fixedVersion: z.string().optional(),
  cve: z.string().optional(),
  cvssScore: z.number().optional(),
  references: z.array(z.string()).default([]),
  secretType: z.string().optional(),
  // Secret fields are already HMAC-fingerprinted & redacted before leaving scanner adapter
  secretFingerprint: z.string().optional(),
  redactedMatch: z.string().optional(),
  commitSha: z.string().optional(),
  commitTimestamp: z.string().optional(),
  exposureLocation: z.enum(["WORKING_TREE", "GIT_HISTORY", "BOTH"]).optional(),
  remediationHint: z.string().optional(),
  rawMetadata: z.record(z.union([z.string(), z.number(), z.boolean()])).optional()
});
export type RawScannerFinding = z.infer<typeof RawScannerFindingSchema>;

export const ScannerLimitationSchema = z.object({
  code: z.string(),
  message: z.string(),
  scopeAffected: z.string().optional()
});
export type ScannerLimitation = z.infer<typeof ScannerLimitationSchema>;

export const ScannerExecutionResultSchema = z.object({
  scanner: z.string(),
  scannerVersion: z.string(),
  rulesetVersion: z.string().optional(),
  capabilities: z.array(ScannerCapabilitySchema),
  status: ScannerExecutionStatusSchema,
  errorClass: ScannerErrorClassSchema,
  errorMessage: z.string().optional(),
  exitCode: z.number().int().nullable(),
  startedAt: z.string(),
  completedAt: z.string(),
  durationMs: z.number().int().min(0),
  limitations: z.array(ScannerLimitationSchema).default([]),
  resourceUsage: z
    .object({
      maxRssBytes: z.number().int().optional(),
      filesScanned: z.number().int().optional(),
      commitsScanned: z.number().int().optional()
    })
    .optional(),
  findings: z.array(RawScannerFindingSchema)
});
export type ScannerExecutionResult = z.infer<typeof ScannerExecutionResultSchema>;

export interface ScannerExecutionContext {
  scanId: string;
  organizationId: string;
  projectId: string;
  workspacePath: string;
  hasGitHistory: boolean;
  isShallowClone: boolean;
  maxGitHistoryCommits: number;
  maxReportBytes?: number;
  timeoutMs: number;
  secretFingerprintKey: string;
  signal?: AbortSignal;
}

export interface ScannerAdapter {
  readonly name: string;
  readonly version: string;
  readonly capabilities: ScannerCapability[];
  healthCheck(): Promise<ScannerHealth>;
  execute(context: ScannerExecutionContext): Promise<ScannerExecutionResult>;
}
