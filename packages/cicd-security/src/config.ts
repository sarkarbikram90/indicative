import fs from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { FindingSeverity, RawScannerFinding } from "@indicative/contracts";
import { redactSecretsInText, validateSafePathWithinRoot } from "@indicative/security";
import type {
  CicdPolicyMode,
  ExpiredSuppressionRecord,
  SuppressedFindingRecord
} from "./types.js";

const MAX_CONFIG_FILE_BYTES = 128 * 1024;
const DEFAULT_CONFIG_FILENAMES = [
  ".indicative.yml",
  ".indicative.yaml",
  ".indicative.json"
] as const;

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const RuleOverrideValueSchema = z
  .string()
  .transform((v) => v.trim().toUpperCase())
  .pipe(z.enum(["OFF", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]));

const SuppressionRuleSchema = z.object({
  ruleId: z.string().trim().min(1).max(120),
  path: z.string().trim().min(1).max(400).optional(),
  reason: z.string().trim().min(3).max(500),
  expires: z
    .string()
    .trim()
    .regex(ISO_DATE_RE, "Expiration date must use YYYY-MM-DD format")
    .optional()
});

const PolicyModeInputSchema = z
  .string()
  .transform((v) => {
    const lower = v.trim().toLowerCase();
    if (lower === "info" || lower === "informational") return "informational" as const;
    if (lower === "warn" || lower === "warning") return "warning" as const;
    if (lower === "fail" || lower === "failure") return "failure" as const;
    return lower;
  })
  .pipe(z.enum(["informational", "warning", "failure"]));

const SeverityInputSchema = z
  .string()
  .transform((v) => v.trim().toUpperCase())
  .pipe(z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]));

export const IndicativeRepoConfigSchema = z
  .object({
    version: z.literal(1).default(1),
    policy: PolicyModeInputSchema.optional(),
    failOnSeverities: z.array(SeverityInputSchema).min(1).optional(),
    ignore: z.array(z.string().trim().min(1).max(400)).default([]),
    rules: z.record(z.string().trim().min(1).max(120), RuleOverrideValueSchema).default({}),
    suppressions: z.array(SuppressionRuleSchema).default([]),
    baseline: z.string().trim().min(1).max(400).optional()
  })
  .strict();

export type IndicativeSuppressionRule = z.infer<typeof SuppressionRuleSchema>;

export interface IndicativeRepoConfig {
  version: 1;
  policy?: CicdPolicyMode;
  failOnSeverities?: FindingSeverity[];
  ignore: string[];
  rules: Record<string, "OFF" | FindingSeverity>;
  suppressions: IndicativeSuppressionRule[];
  baseline?: string;
  configPath?: string;
}

export interface LoadedConfigResult {
  config: IndicativeRepoConfig | null;
  error?: string;
}

function normalizeRelPath(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
}

function isIsoDateExpired(expires: string | undefined, nowDateIso: string): boolean {
  if (!expires || !ISO_DATE_RE.test(expires)) return false;
  return expires < nowDateIso;
}

/**
 * Loads and strictly validates `.indicative.yml` / `.indicative.yaml` / `.indicative.json`
 * from the workspace root (or an explicit path within the workspace).
 */
export async function loadIndicativeRepoConfig(
  workspacePath: string,
  explicitConfigPath?: string
): Promise<LoadedConfigResult> {
  const resolvedRoot = path.resolve(workspacePath);
  let targetFile: string | null = null;
  let displayPath: string | undefined;

  if (explicitConfigPath) {
    const candidate = path.isAbsolute(explicitConfigPath)
      ? explicitConfigPath
      : path.resolve(resolvedRoot, explicitConfigPath);
    try {
      const stat = await fs.lstat(candidate);
      if (stat.isSymbolicLink() || !stat.isFile()) {
        return { config: null, error: `Config path "${explicitConfigPath}" is not a regular file.` };
      }
      if (stat.size > MAX_CONFIG_FILE_BYTES) {
        return {
          config: null,
          error: `Config file "${explicitConfigPath}" exceeds ${MAX_CONFIG_FILE_BYTES} bytes safety limit.`
        };
      }
      targetFile = candidate;
      displayPath = path.relative(resolvedRoot, candidate).replace(/\\/g, "/") || explicitConfigPath;
    } catch {
      return { config: null, error: `Config file "${explicitConfigPath}" could not be read.` };
    }
  } else {
    for (const filename of DEFAULT_CONFIG_FILENAMES) {
      const candidate = path.join(resolvedRoot, filename);
      try {
        validateSafePathWithinRoot(resolvedRoot, candidate);
        const stat = await fs.lstat(candidate);
        if (stat.isSymbolicLink() || !stat.isFile()) continue;
        if (stat.size > MAX_CONFIG_FILE_BYTES) {
          return {
            config: null,
            error: `Config file "${filename}" exceeds ${MAX_CONFIG_FILE_BYTES} bytes safety limit.`
          };
        }
        targetFile = candidate;
        displayPath = filename;
        break;
      } catch {
        // Not found; try next filename
      }
    }
  }

  if (!targetFile) {
    return { config: null };
  }

  try {
    const raw = await fs.readFile(targetFile, "utf8");
    const parsed = targetFile.toLowerCase().endsWith(".json")
      ? JSON.parse(raw)
      : parseYaml(raw, { maxAliasCount: 25, strict: false });

    const validated = IndicativeRepoConfigSchema.safeParse(parsed ?? {});
    if (!validated.success) {
      const issue = validated.error.issues
        .slice(0, 3)
        .map((i) => `${i.path.join(".") || "root"}: ${i.message}`)
        .join("; ");
      return {
        config: null,
        error: `Invalid Indicative config (${displayPath}): ${issue}`
      };
    }

    return {
      config: {
        ...validated.data,
        configPath: displayPath
      }
    };
  } catch (err) {
    return {
      config: null,
      error: `Failed to parse Indicative config (${displayPath}): ${(err as Error).message}`
    };
  }
}

export interface InlineSuppressionDirective {
  ruleIds: string[];
  reason: string;
  expires?: string;
  lineNumber: number;
}

const INLINE_DIRECTIVE_RE =
  /(?:#|\/\/)\s*indicative-ignore:\s*([A-Za-z0-9_*, -]+?)(?=\s+(?:reason|expires)=|\s*$)(.*)$/i;

/**
 * Parses an inline suppression comment such as:
 *   # indicative-ignore: GHA-ACT-001 reason="pinned via internal mirror" expires=2027-06-01
 */
export function parseInlineSuppressionComment(
  line: string,
  lineNumber: number
): InlineSuppressionDirective | null {
  if (!line.toLowerCase().includes("indicative-ignore:")) return null;
  const bounded = line.slice(0, 1000);
  const match = INLINE_DIRECTIVE_RE.exec(bounded);
  if (!match) return null;

  const rawRules = match[1] ?? "";
  const rest = match[2] ?? "";
  const ruleIds = rawRules
    .split(/[,\s]+/)
    .map((r) => r.trim().toUpperCase())
    .filter((r) => r.length > 0 && (r === "*" || /^[A-Z0-9]+-[A-Z0-9-]+$/.test(r)));

  if (ruleIds.length === 0) return null;

  let reason = "Inline suppression comment";
  const reasonQuoted = rest.match(/reason\s*=\s*(?:"([^"\r\n]{1,300})"|'([^'\r\n]{1,300})')/i);
  if (reasonQuoted) {
    reason = (reasonQuoted[1] ?? reasonQuoted[2] ?? reason).trim();
  } else {
    const reasonBare = rest.match(/reason\s*=\s*([^\s#]{1,200})/i);
    if (reasonBare?.[1]) reason = reasonBare[1].trim();
  }

  let expires: string | undefined;
  const expiresMatch = rest.match(/expires\s*=\s*(\d{4}-\d{2}-\d{2})/i);
  if (expiresMatch?.[1]) {
    expires = expiresMatch[1];
  }

  return { ruleIds, reason, expires, lineNumber };
}

function findInlineSuppression(
  lines: string[] | undefined,
  lineStart: number | undefined,
  ruleId: string
): InlineSuppressionDirective | null {
  if (!lines || !lineStart || lineStart < 1) return null;
  const upperRule = ruleId.toUpperCase();
  const candidates = [lineStart, lineStart - 1].filter((n) => n >= 1 && n <= lines.length);

  for (const lineNum of candidates) {
    const directive = parseInlineSuppressionComment(lines[lineNum - 1] ?? "", lineNum);
    if (!directive) continue;
    if (directive.ruleIds.includes("*") || directive.ruleIds.includes(upperRule)) {
      return directive;
    }
  }
  return null;
}

function matchesConfigSuppression(
  finding: RawScannerFinding,
  rule: IndicativeSuppressionRule
): boolean {
  const targetRule = rule.ruleId.toUpperCase();
  if (targetRule !== "*" && targetRule !== finding.ruleId.toUpperCase()) {
    return false;
  }
  if (!rule.path) return true;
  const findingPath = normalizeRelPath(finding.filePath ?? "");
  const rulePath = normalizeRelPath(rule.path).replace(/\/+$/, "");
  return findingPath === rulePath || findingPath.startsWith(`${rulePath}/`);
}

export interface SuppressionApplicationResult {
  activeFindings: RawScannerFinding[];
  suppressedFindings: SuppressedFindingRecord[];
  expiredSuppressions: ExpiredSuppressionRecord[];
}

/**
 * Applies `.indicative.yml` rule overrides, repo-level suppressions, and inline YAML/IaC
 * suppression comments (`# indicative-ignore: ...`). Expired suppressions are rejected and
 * reported transparently rather than silently applied or silently dropped.
 */
export function applyConfigAndSuppressions(params: {
  findings: RawScannerFinding[];
  fileLinesByPath: Map<string, string[]>;
  config: IndicativeRepoConfig | null;
  nowDateIso?: string;
}): SuppressionApplicationResult {
  const nowDateIso = params.nowDateIso ?? new Date().toISOString().slice(0, 10);
  const activeFindings: RawScannerFinding[] = [];
  const suppressedFindings: SuppressedFindingRecord[] = [];
  const expiredSuppressions: ExpiredSuppressionRecord[] = [];
  const seenExpiredKeys = new Set<string>();

  const normalizedRules = new Map<string, "OFF" | FindingSeverity>();
  if (params.config) {
    for (const [ruleId, val] of Object.entries(params.config.rules)) {
      normalizedRules.set(ruleId.toUpperCase(), val);
    }
  }

  for (const rawFinding of params.findings) {
    const upperRule = rawFinding.ruleId.toUpperCase();
    const normalizedPath = normalizeRelPath(rawFinding.filePath ?? "");

    // 1. Config rule toggle / severity override
    const ruleOverride = normalizedRules.get(upperRule);
    if (ruleOverride === "OFF") {
      suppressedFindings.push({
        ruleId: rawFinding.ruleId,
        filePath: rawFinding.filePath,
        lineStart: rawFinding.lineStart,
        title: redactSecretsInText(rawFinding.title),
        severity: rawFinding.severity,
        source: "config-rule",
        reason: `Rule ${rawFinding.ruleId} disabled via ${params.config?.configPath ?? ".indicative.yml"}`
      });
      continue;
    }

    const finding: RawScannerFinding =
      ruleOverride && ruleOverride !== rawFinding.severity
        ? {
            ...rawFinding,
            originalSeverity: rawFinding.originalSeverity ?? rawFinding.severity,
            severity: ruleOverride,
            rawMetadata: {
              ...(rawFinding.rawMetadata ?? {}),
              severityOverriddenByConfig: true
            }
          }
        : rawFinding;

    // 2. Inline suppression comment on finding line or immediately preceding line
    const fileLines = params.fileLinesByPath.get(normalizedPath);
    const inlineDirective = findInlineSuppression(fileLines, finding.lineStart, finding.ruleId);
    if (inlineDirective) {
      if (isIsoDateExpired(inlineDirective.expires, nowDateIso)) {
        const expKey = `inline:${finding.ruleId}:${normalizedPath}:${inlineDirective.lineNumber}`;
        if (!seenExpiredKeys.has(expKey)) {
          seenExpiredKeys.add(expKey);
          expiredSuppressions.push({
            ruleId: finding.ruleId,
            filePath: finding.filePath,
            lineStart: inlineDirective.lineNumber,
            source: "inline",
            reason: redactSecretsInText(inlineDirective.reason),
            expires: inlineDirective.expires!
          });
        }
      } else {
        suppressedFindings.push({
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          title: redactSecretsInText(finding.title),
          severity: finding.severity,
          source: "inline",
          reason: redactSecretsInText(inlineDirective.reason),
          expires: inlineDirective.expires
        });
        continue;
      }
    }

    // 3. Config-level suppression rules
    let suppressedByConfig = false;
    if (params.config) {
      for (const suppRule of params.config.suppressions) {
        if (!matchesConfigSuppression(finding, suppRule)) continue;

        if (isIsoDateExpired(suppRule.expires, nowDateIso)) {
          const expKey = `config:${suppRule.ruleId}:${suppRule.path ?? "*"}:${suppRule.expires}`;
          if (!seenExpiredKeys.has(expKey)) {
            seenExpiredKeys.add(expKey);
            expiredSuppressions.push({
              ruleId: suppRule.ruleId,
              filePath: suppRule.path ?? finding.filePath,
              source: "config-suppression",
              reason: redactSecretsInText(suppRule.reason),
              expires: suppRule.expires!
            });
          }
          continue;
        }

        suppressedFindings.push({
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          title: redactSecretsInText(finding.title),
          severity: finding.severity,
          source: "config-suppression",
          reason: redactSecretsInText(suppRule.reason),
          expires: suppRule.expires
        });
        suppressedByConfig = true;
        break;
      }
    }

    if (!suppressedByConfig) {
      activeFindings.push(finding);
    }
  }

  return { activeFindings, suppressedFindings, expiredSuppressions };
}
