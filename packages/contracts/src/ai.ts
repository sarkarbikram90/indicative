import { z } from "zod";

export const AiFindingAnalysisOutputSchema = z.object({
  summary: z.string().min(10).max(2000),
  whyItMatters: z.string().min(10).max(2000),
  rootCause: z.string().min(10).max(2000),
  attackScenario: z.string().min(10).max(2000),
  recommendedRemediation: z.string().min(10).max(3000),
  secureCodePattern: z.string().max(4000).optional(),
  patchSuggestion: z.string().max(4000).optional(),
  verificationSteps: z.array(z.string().min(3).max(500)).min(1).max(10),
  missingInformation: z.array(z.string().min(3).max(500)).max(10).default([]),
  uncertaintyNotes: z.string().max(1500).default(""),
  disclaimer: z
    .string()
    .default(
      "AI-generated advisory analysis based on redacted scanner context. Not verified security evidence or confirmed exploitability."
    )
});
export type AiFindingAnalysisOutput = z.infer<typeof AiFindingAnalysisOutputSchema>;

export const AiFindingAnalysisRecordSchema = z.object({
  id: z.string(),
  findingId: z.string(),
  provider: z.string(),
  model: z.string(),
  promptVersion: z.string(),
  analysis: AiFindingAnalysisOutputSchema,
  promptTokens: z.number().int().min(0).optional(),
  completionTokens: z.number().int().min(0).optional(),
  totalTokens: z.number().int().min(0).optional(),
  latencyMs: z.number().int().min(0),
  createdAt: z.string()
});
export type AiFindingAnalysisRecord = z.infer<typeof AiFindingAnalysisRecordSchema>;

export const AiAdvisorQuestionRequestSchema = z.object({
  scope: z.enum(["project", "scan", "finding"]),
  projectId: z.string().uuid(),
  scanId: z.string().uuid().optional(),
  findingId: z.string().uuid().optional(),
  question: z.string().trim().min(3).max(1500)
});
export type AiAdvisorQuestionRequest = z.infer<typeof AiAdvisorQuestionRequestSchema>;

export const AiAdvisorAnswerSchema = z.object({
  answer: z.string().min(5).max(4000),
  referencedFindingIds: z.array(z.string()).default([]),
  caveats: z.array(z.string()).default([]),
  model: z.string(),
  promptVersion: z.string(),
  aiGenerated: z.literal(true),
  disclaimer: z.string()
});
export type AiAdvisorAnswer = z.infer<typeof AiAdvisorAnswerSchema>;
