import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { RawScannerFinding } from "@indicative/contracts";
import { redactSecretsInText } from "@indicative/security";
import type { BaselineDiffSummary } from "./types.js";

const MAX_BASELINE_BYTES = 2 * 1024 * 1024;

export const BaselineEntrySchema = z.object({
  key: z.string().min(16).max(128),
  ruleId: z.string().min(1),
  filePath: z.string().optional(),
  severity: z.string().min(1),
  title: z.string().min(1)
});

export const IndicativeBaselineSchema = z.object({
  version: z.literal(1),
  generatedAt: z.string().min(1),
  scanner: z.string().min(1),
  entries: z.array(BaselineEntrySchema)
});

export type BaselineEntry = z.infer<typeof BaselineEntrySchema>;
export type IndicativeBaseline = z.infer<typeof IndicativeBaselineSchema>;

/**
 * Computes a stable, line-number-independent finding key for differential / ratchet mode.
 * Survives unrelated edits above or below a workflow job or IaC block.
 */
export function computeStableFindingKey(finding: RawScannerFinding): string {
  const normalizedPath = (finding.filePath ?? "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .toLowerCase();
  const anchor =
    typeof finding.rawMetadata?.workflowAnchor === "string"
      ? finding.rawMetadata.workflowAnchor
      : typeof finding.rawMetadata?.identityAnchor === "string"
        ? finding.rawMetadata.identityAnchor
        : finding.title.trim().toLowerCase();

  return crypto
    .createHash("sha256")
    .update(["v1", finding.ruleId.toUpperCase(), normalizedPath, anchor].join("|"), "utf8")
    .digest("hex");
}

export function createBaselineFromFindings(
  findings: RawScannerFinding[],
  scanner: string
): IndicativeBaseline {
  const seen = new Set<string>();
  const entries: BaselineEntry[] = [];

  for (const f of findings) {
    const key = computeStableFindingKey(f);
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({
      key,
      ruleId: f.ruleId,
      filePath: f.filePath?.replace(/\\/g, "/"),
      severity: f.severity,
      title: redactSecretsInText(f.title)
    });
  }

  entries.sort((a, b) => a.key.localeCompare(b.key));

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    scanner,
    entries
  };
}

export async function writeBaselineFile(
  filePath: string,
  findings: RawScannerFinding[],
  scanner: string
): Promise<IndicativeBaseline> {
  const baseline = createBaselineFromFindings(findings, scanner);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  return baseline;
}

export async function readBaselineFile(filePath: string): Promise<IndicativeBaseline> {
  const stat = await fs.lstat(filePath);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`Baseline path "${filePath}" is not a regular file.`);
  }
  if (stat.size > MAX_BASELINE_BYTES) {
    throw new Error(`Baseline file "${filePath}" exceeds ${MAX_BASELINE_BYTES} bytes limit.`);
  }
  const raw = await fs.readFile(filePath, "utf8");
  const parsed = JSON.parse(raw);
  const validated = IndicativeBaselineSchema.safeParse(parsed);
  if (!validated.success) {
    throw new Error(`Invalid Indicative baseline file "${filePath}".`);
  }
  return validated.data;
}

export interface BaselineDiffResult {
  newFindings: RawScannerFinding[];
  baselineFindings: RawScannerFinding[];
  summary: BaselineDiffSummary;
}

export function diffFindingsAgainstBaseline(
  findings: RawScannerFinding[],
  baseline: IndicativeBaseline,
  baselinePath: string
): BaselineDiffResult {
  const baselineKeys = new Set(baseline.entries.map((e) => e.key));
  const matchedBaselineKeys = new Set<string>();
  const newFindings: RawScannerFinding[] = [];
  const baselineFindings: RawScannerFinding[] = [];

  for (const f of findings) {
    const key = computeStableFindingKey(f);
    if (baselineKeys.has(key)) {
      matchedBaselineKeys.add(key);
      baselineFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  const resolvedBaselineCount = Math.max(0, baselineKeys.size - matchedBaselineKeys.size);

  return {
    newFindings,
    baselineFindings,
    summary: {
      baselinePath,
      baselineEntriesCount: baselineKeys.size,
      newFindingsCount: newFindings.length,
      existingBaselineFindingsCount: baselineFindings.length,
      resolvedBaselineCount
    }
  };
}
