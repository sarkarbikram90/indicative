import { z } from "zod";
import {
  FindingCategorySchema,
  FindingConfidenceSchema,
  FindingSeveritySchema,
  FindingStatusSchema,
  RiskPrioritySchema
} from "./findings.js";

export const PaginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25)
});
export type PaginationQuery = z.infer<typeof PaginationQuerySchema>;

export const FindingsFilterQuerySchema = PaginationQuerySchema.extend({
  severity: FindingSeveritySchema.optional(),
  riskPriority: RiskPrioritySchema.optional(),
  category: FindingCategorySchema.optional(),
  scanner: z.string().trim().min(1).max(64).optional(),
  status: FindingStatusSchema.optional(),
  confidence: FindingConfidenceSchema.optional(),
  projectId: z.string().uuid().optional(),
  scanId: z.string().uuid().optional(),
  fromDate: z.string().datetime().optional(),
  toDate: z.string().datetime().optional(),
  search: z.string().trim().max(200).optional()
});
export type FindingsFilterQuery = z.infer<typeof FindingsFilterQuerySchema>;

export const CreateProjectRequestSchema = z.object({
  name: z.string().trim().min(2).max(120),
  description: z.string().trim().max(500).optional(),
  githubInstallationId: z.string().uuid().optional(),
  repositoryFullName: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "Must be owner/repo format"),
  defaultBranch: z.string().trim().min(1).max(120).default("main"),
  isPrivate: z.boolean().default(true),
  externalRepoId: z.string().optional(),
  localFixturePath: z.string().optional()
});
export type CreateProjectRequest = z.infer<typeof CreateProjectRequestSchema>;

export const RegisterGitHubInstallationSchema = z.object({
  installationId: z.coerce.number().int().positive(),
  accountLogin: z.string().trim().min(1).max(100),
  accountType: z.enum(["User", "Organization"]).default("User")
});
export type RegisterGitHubInstallation = z.infer<typeof RegisterGitHubInstallationSchema>;

export const ApiErrorResponseSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    correlationId: z.string(),
    details: z.unknown().optional()
  })
});
export type ApiErrorResponse = z.infer<typeof ApiErrorResponseSchema>;
