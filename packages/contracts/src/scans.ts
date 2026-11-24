import { z } from "zod";
import {
  ScannerLimitationSchema,
  ScannerExecutionStatusSchema,
  ScannerNameSchema
} from "./scanners.js";

export const ScanStatusSchema = z.enum([
  "QUEUED",
  "INITIALIZING",
  "CLONING",
  "SCANNING",
  "ANALYZING",
  "COMPLETED",
  "COMPLETED_WITH_ERRORS",
  "FAILED",
  "CANCELLED"
]);
export type ScanStatus = z.infer<typeof ScanStatusSchema>;

export const ScanTriggerSourceSchema = z.enum(["MANUAL", "API", "DEMO"]);
export type ScanTriggerSource = z.infer<typeof ScanTriggerSourceSchema>;

export const ScanSummaryCountsSchema = z.object({
  total: z.number().int().min(0),
  critical: z.number().int().min(0),
  high: z.number().int().min(0),
  medium: z.number().int().min(0),
  low: z.number().int().min(0),
  info: z.number().int().min(0),
  unknown: z.number().int().min(0),
  newFindings: z.number().int().min(0),
  recurringFindings: z.number().int().min(0),
  notDetectedFindings: z.number().int().min(0),
  reopenedFindings: z.number().int().min(0)
});
export type ScanSummaryCounts = z.infer<typeof ScanSummaryCountsSchema>;

export const ScannerRunSummarySchema = z.object({
  id: z.string(),
  scanner: z.string(),
  scannerVersion: z.string(),
  rulesetVersion: z.string().optional(),
  status: ScannerExecutionStatusSchema,
  exitCode: z.number().int().nullable(),
  findingsCount: z.number().int().min(0),
  durationMs: z.number().int().min(0),
  errorClass: z.string(),
  errorMessage: z.string().optional(),
  limitations: z.array(ScannerLimitationSchema).default([]),
  startedAt: z.string(),
  completedAt: z.string().optional()
});
export type ScannerRunSummary = z.infer<typeof ScannerRunSummarySchema>;

export const ScanComparisonSchema = z.object({
  currentScanId: z.string(),
  previousScanId: z.string().nullable(),
  newFindingIds: z.array(z.string()),
  recurringFindingIds: z.array(z.string()),
  notDetectedFindingIds: z.array(z.string()),
  reopenedFindingIds: z.array(z.string()),
  inconclusiveFindingIds: z.array(z.string()),
  summary: z.string()
});
export type ScanComparison = z.infer<typeof ScanComparisonSchema>;

export const CreateScanRequestSchema = z.object({
  branch: z.string().trim().min(1).max(200).optional(),
  scanners: z.array(ScannerNameSchema).min(1).optional(),
  runAiAnalysis: z.boolean().optional().default(false),
  idempotencyKey: z.string().trim().min(8).max(128).optional()
});
export type CreateScanRequest = z.infer<typeof CreateScanRequestSchema>;

export const ReportFormatSchema = z.enum(["json", "sarif", "csv"]);
export type ReportFormat = z.infer<typeof ReportFormatSchema>;
