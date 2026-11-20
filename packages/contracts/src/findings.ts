import { z } from "zod";

export const FindingCategorySchema = z.enum(["SAST", "SCA", "SECRET", "IAC"]);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

export const FindingSeveritySchema = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
  "UNKNOWN"
]);
export type FindingSeverity = z.infer<typeof FindingSeveritySchema>;

export const FindingConfidenceSchema = z.enum(["HIGH", "MEDIUM", "LOW", "UNKNOWN"]);
export type FindingConfidence = z.infer<typeof FindingConfidenceSchema>;

export const SecretValiditySchema = z.enum(["UNKNOWN", "NOT_VERIFIED"]);
export type SecretValidity = z.infer<typeof SecretValiditySchema>;

export const ExposureLocationSchema = z.enum(["WORKING_TREE", "GIT_HISTORY", "BOTH"]);
export type ExposureLocation = z.infer<typeof ExposureLocationSchema>;

export const FindingStatusSchema = z.enum([
  "OPEN",
  "ACKNOWLEDGED",
  "IN_PROGRESS",
  "FALSE_POSITIVE",
  "ACCEPTED_RISK",
  "FIXED_PENDING_VERIFICATION",
  "RESOLVED_VERIFIED",
  "REOPENED"
]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const RiskPrioritySchema = z.enum([
  "IMMEDIATE",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL"
]);
export type RiskPriority = z.infer<typeof RiskPrioritySchema>;

export const VerificationStateSchema = z.enum([
  "DETECTED",
  "NOT_DETECTED_IN_LATEST_SCAN",
  "VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE",
  "VERIFICATION_INCONCLUSIVE"
]);
export type VerificationState = z.infer<typeof VerificationStateSchema>;

export const FindingEvidenceSchema = z.object({
  id: z.string(),
  type: z.enum([
    "CODE_SNIPPET",
    "PACKAGE_ADVISORY",
    "SECRET_EXPOSURE",
    "CONFIG_SNIPPET",
    "GIT_COMMIT",
    "SCANNER_REFERENCE"
  ]),
  label: z.string(),
  content: z.string(),
  filePath: z.string().optional(),
  lineStart: z.number().int().optional(),
  lineEnd: z.number().int().optional(),
  commitSha: z.string().optional(),
  commitTimestamp: z.string().optional(),
  referenceUrl: z.string().optional(),
  metadata: z.record(z.union([z.string(), z.number(), z.boolean()])).optional()
});
export type FindingEvidence = z.infer<typeof FindingEvidenceSchema>;

export const SecurityFindingSchema = z.object({
  id: z.string(),
  fingerprint: z.string(),

  organizationId: z.string(),
  projectId: z.string(),
  scanId: z.string(),

  scanner: z.string(),
  scannerVersion: z.string(),
  rulesetVersion: z.string().optional(),
  ruleId: z.string(),

  category: FindingCategorySchema,
  title: z.string(),
  description: z.string(),

  severity: FindingSeveritySchema,
  originalSeverity: z.string().optional(),
  confidence: FindingConfidenceSchema,

  riskPriority: RiskPrioritySchema,
  riskRationale: z.array(z.string()),

  filePath: z.string().optional(),
  lineStart: z.number().int().optional(),
  lineEnd: z.number().int().optional(),

  packageName: z.string().optional(),
  installedVersion: z.string().optional(),
  fixedVersion: z.string().optional(),
  cve: z.string().optional(),
  cvssScore: z.number().optional(),

  secretType: z.string().optional(),
  secretFingerprint: z.string().optional(),
  secretValidity: SecretValiditySchema.optional(),
  commitSha: z.string().optional(),
  commitTimestamp: z.string().optional(),
  exposureLocation: ExposureLocationSchema.optional(),

  evidence: z.array(FindingEvidenceSchema),
  remediation: z.string().optional(),

  status: FindingStatusSchema,
  verificationState: VerificationStateSchema.optional(),

  occurrenceCount: z.number().int().min(1).default(1),
  firstSeenAt: z.string(),
  lastSeenAt: z.string()
});
export type SecurityFinding = z.infer<typeof SecurityFindingSchema>;

export const FindingOccurrenceSchema = z.object({
  id: z.string(),
  findingId: z.string(),
  scanId: z.string(),
  filePath: z.string().optional(),
  lineStart: z.number().int().optional(),
  lineEnd: z.number().int().optional(),
  commitSha: z.string().optional(),
  commitTimestamp: z.string().optional(),
  exposureLocation: ExposureLocationSchema.optional(),
  redactedSnippet: z.string().optional(),
  detectedAt: z.string()
});
export type FindingOccurrence = z.infer<typeof FindingOccurrenceSchema>;

export const FindingStatusTransitionRequestSchema = z.object({
  status: FindingStatusSchema,
  reason: z.string().trim().min(3).max(1000)
});
export type FindingStatusTransitionRequest = z.infer<
  typeof FindingStatusTransitionRequestSchema
>;
