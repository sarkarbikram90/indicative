import { z } from "zod";
import { ScannerNameSchema } from "./scanners.js";
import { FindingSeveritySchema } from "./findings.js";

// ============================================================================
// Scheduled / Recurring Scans
// ============================================================================

export const ScheduleCadenceSchema = z.enum(["HOURLY", "DAILY", "WEEKLY", "CUSTOM_CRON"]);
export type ScheduleCadence = z.infer<typeof ScheduleCadenceSchema>;

export const CreateScanScheduleRequestSchema = z.object({
  projectId: z.string().uuid(),
  name: z.string().trim().min(2).max(120),
  cadence: ScheduleCadenceSchema.default("DAILY"),
  cronExpression: z.string().trim().min(9).max(64).optional(),
  branch: z.string().trim().min(1).max(200).optional(),
  scanners: z.array(ScannerNameSchema).min(1).optional(),
  runAiAnalysis: z.boolean().default(false),
  enabled: z.boolean().default(true)
});
export type CreateScanScheduleRequest = z.infer<typeof CreateScanScheduleRequestSchema>;

export const UpdateScanScheduleRequestSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  cadence: ScheduleCadenceSchema.optional(),
  cronExpression: z.string().trim().min(9).max(64).optional(),
  branch: z.string().trim().min(1).max(200).optional(),
  scanners: z.array(ScannerNameSchema).min(1).optional(),
  runAiAnalysis: z.boolean().optional(),
  enabled: z.boolean().optional()
});
export type UpdateScanScheduleRequest = z.infer<typeof UpdateScanScheduleRequestSchema>;

// ============================================================================
// Notification Channels (Slack, Jira, GitHub Issues)
// ============================================================================

export const NotificationChannelTypeSchema = z.enum(["SLACK", "JIRA", "GITHUB_ISSUE"]);
export type NotificationChannelType = z.infer<typeof NotificationChannelTypeSchema>;

export const NotificationEventTypeSchema = z.enum([
  "SCAN_COMPLETED",
  "NEW_CRITICAL_OR_HIGH",
  "KEV_DETECTED",
  "SCAN_FAILED"
]);
export type NotificationEventType = z.infer<typeof NotificationEventTypeSchema>;

export const NotificationMinSeveritySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
export type NotificationMinSeverity = z.infer<typeof NotificationMinSeveritySchema>;

export const SlackChannelConfigSchema = z.object({
  webhookUrl: z.string().url(),
  channelLabel: z.string().trim().max(80).optional()
});

export const JiraChannelConfigSchema = z.object({
  baseUrl: z.string().url(),
  projectKey: z
    .string()
    .trim()
    .regex(/^[A-Z][A-Z0-9_]{1,19}$/, "Jira projectKey must be uppercase letters/digits"),
  issueType: z.string().trim().min(1).max(64).default("Task"),
  email: z.string().email(),
  apiToken: z.string().min(8).max(512),
  labels: z.array(z.string().trim().min(1).max(40)).max(10).default(["indicative-security"])
});

export const GitHubIssueChannelConfigSchema = z.object({
  repositoryFullName: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "Must be owner/repo format"),
  labels: z.array(z.string().trim().min(1).max(40)).max(10).default(["indicative-security"]),
  token: z.string().min(8).max(512).optional()
});

export const CreateNotificationChannelRequestSchema = z.discriminatedUnion("channelType", [
  z.object({
    channelType: z.literal("SLACK"),
    projectId: z.string().uuid().optional().nullable(),
    name: z.string().trim().min(2).max(120),
    enabled: z.boolean().default(true),
    events: z
      .array(NotificationEventTypeSchema)
      .min(1)
      .default(["NEW_CRITICAL_OR_HIGH", "KEV_DETECTED", "SCAN_FAILED"]),
    minSeverity: NotificationMinSeveritySchema.default("HIGH"),
    onlyOnNewFindings: z.boolean().default(true),
    config: SlackChannelConfigSchema
  }),
  z.object({
    channelType: z.literal("JIRA"),
    projectId: z.string().uuid().optional().nullable(),
    name: z.string().trim().min(2).max(120),
    enabled: z.boolean().default(true),
    events: z
      .array(NotificationEventTypeSchema)
      .min(1)
      .default(["NEW_CRITICAL_OR_HIGH", "KEV_DETECTED"]),
    minSeverity: NotificationMinSeveritySchema.default("HIGH"),
    onlyOnNewFindings: z.boolean().default(true),
    config: JiraChannelConfigSchema
  }),
  z.object({
    channelType: z.literal("GITHUB_ISSUE"),
    projectId: z.string().uuid().optional().nullable(),
    name: z.string().trim().min(2).max(120),
    enabled: z.boolean().default(true),
    events: z
      .array(NotificationEventTypeSchema)
      .min(1)
      .default(["NEW_CRITICAL_OR_HIGH", "KEV_DETECTED"]),
    minSeverity: NotificationMinSeveritySchema.default("HIGH"),
    onlyOnNewFindings: z.boolean().default(true),
    config: GitHubIssueChannelConfigSchema
  })
]);
export type CreateNotificationChannelRequest = z.infer<
  typeof CreateNotificationChannelRequestSchema
>;

export const UpdateNotificationChannelRequestSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  enabled: z.boolean().optional(),
  events: z.array(NotificationEventTypeSchema).min(1).optional(),
  minSeverity: NotificationMinSeveritySchema.optional(),
  onlyOnNewFindings: z.boolean().optional()
});
export type UpdateNotificationChannelRequest = z.infer<
  typeof UpdateNotificationChannelRequestSchema
>;

// ============================================================================
// GitHub Webhook Scan Trigger Metadata
// ============================================================================

export const ScanTriggerMetadataSchema = z.object({
  webhookDeliveryId: z.string().optional(),
  githubEvent: z.string().optional(),
  githubInstallationId: z.number().int().positive().optional(),
  pullRequestNumber: z.number().int().positive().optional(),
  pullRequestUrl: z.string().optional(),
  baseBranch: z.string().optional(),
  headBranch: z.string().optional(),
  headSha: z.string().optional(),
  isForkPr: z.boolean().optional(),
  checkRunId: z.number().int().positive().optional(),
  scheduleId: z.string().uuid().optional(),
  scheduleName: z.string().optional()
});
export type ScanTriggerMetadata = z.infer<typeof ScanTriggerMetadataSchema>;

export const SEVERITY_RANK: Record<z.infer<typeof FindingSeveritySchema>, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0
};
