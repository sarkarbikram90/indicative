import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import type {
  FindingConfidence,
  FindingSeverity,
  RawScannerFinding,
  ScannerAdapter,
  ScannerCapability,
  ScannerExecutionContext,
  ScannerExecutionResult,
  ScannerHealth
} from "@indicative/contracts";
import { normalizeRepoRelativePath, redactSecretsInText } from "@indicative/security";
import { classifyProcessError, safeSpawnBinary } from "./process.js";

export interface SemgrepAdapterConfig {
  binaryPath: string;
  rulesDir: string;
  rulesetVersion?: string;
}

interface SemgrepJsonResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      confidence?: string;
      impact?: string;
      remediation?: string;
      references?: string[];
    };
  };
}

interface SemgrepJsonReport {
  version?: string;
  results?: SemgrepJsonResult[];
  errors?: Array<{ message?: string; type?: string; path?: string }>;
}

export function mapSemgrepSeverity(
  originalSeverity?: string,
  impact?: string,
  confidence?: string
): FindingSeverity {
  const sev = (originalSeverity ?? "").toUpperCase();
  const imp = (impact ?? "").toUpperCase();
  const conf = (confidence ?? "").toUpperCase();

  if (sev === "CRITICAL") return "CRITICAL";
  if (sev === "ERROR" || sev === "HIGH") {
    if (imp === "HIGH" && conf === "HIGH") return "HIGH";
    return "HIGH";
  }
  if (sev === "WARNING" || sev === "MEDIUM") return "MEDIUM";
  if (sev === "INFO" || sev === "LOW") return "LOW";
  return "UNKNOWN";
}

export function mapSemgrepConfidence(confidence?: string): FindingConfidence {
  const c = (confidence ?? "").toUpperCase();
  if (c === "HIGH") return "HIGH";
  if (c === "MEDIUM") return "MEDIUM";
  if (c === "LOW") return "LOW";
  return "MEDIUM";
}

function normalizeSemgrepRuleId(rawCheckId: string): string {
  const idx = rawCheckId.indexOf("indicative.");
  if (idx >= 0) {
    return rawCheckId.slice(idx);
  }
  return rawCheckId;
}

export function parseSemgrepOutput(
  rawJson: string,
  workspacePath: string,
  fallbackVersion: string,
  rulesetVersion: string
): { findings: RawScannerFinding[]; version: string; errors: string[] } {
  const parsed = JSON.parse(rawJson) as SemgrepJsonReport;
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.results)) {
    throw new Error("Semgrep output JSON is missing required 'results' array.");
  }

  const version = parsed.version || fallbackVersion;
  const findings: RawScannerFinding[] = [];

  for (const item of parsed.results) {
    if (!item.check_id || !item.path) continue;
    const ruleId = normalizeSemgrepRuleId(item.check_id);
    let relPath: string;
    try {
      relPath = normalizeRepoRelativePath(workspacePath, item.path);
    } catch {
      continue;
    }

    const meta = item.extra?.metadata;
    const origSev = item.extra?.severity ?? "WARNING";
    const severity = mapSemgrepSeverity(origSev, meta?.impact, meta?.confidence);
    const confidence = mapSemgrepConfidence(meta?.confidence);
    const snippet = item.extra?.lines ? redactSecretsInText(item.extra.lines) : undefined;
    const cweText = Array.isArray(meta?.cwe) ? meta.cwe.join(", ") : meta?.cwe;
    const owaspText = Array.isArray(meta?.owasp) ? meta.owasp.join(", ") : meta?.owasp;

    const ruleParts = ruleId.split(".");
    const shortRule = ruleParts[ruleParts.length - 1] ?? ruleId;
    const title = `SAST: ${shortRule.replace(/[-_]/g, " ")} in ${path.posix.basename(relPath)}`;

    const rawMetadata: Record<string, string | number | boolean> = {};
    if (cweText) rawMetadata.cwe = cweText;
    if (owaspText) rawMetadata.owasp = owaspText;
    if (meta?.impact) rawMetadata.impact = meta.impact;

    findings.push({
      scanner: "semgrep",
      scannerVersion: version,
      rulesetVersion,
      ruleId,
      category: "SAST",
      title,
      description: redactSecretsInText(item.extra?.message ?? `Rule ${ruleId} matched.`),
      originalSeverity: origSev,
      severity,
      confidence,
      filePath: relPath,
      lineStart: item.start?.line,
      lineEnd: item.end?.line,
      codeSnippet: snippet,
      references: Array.isArray(meta?.references) ? meta.references : [],
      remediationHint: meta?.remediation,
      rawMetadata
    });
  }

  const errors = (parsed.errors ?? [])
    .map((e) => e.message || e.type || "Unknown Semgrep parse warning")
    .filter(Boolean);

  return { findings, version, errors };
}

export class SemgrepScannerAdapter implements ScannerAdapter {
  public readonly name = "semgrep";
  public version = "1.186.0";
  public readonly capabilities: ScannerCapability[] = ["sast"];
  private readonly binaryPath: string;
  private readonly rulesDir: string;
  private readonly rulesetVersion: string;

  constructor(config: SemgrepAdapterConfig) {
    this.binaryPath = config.binaryPath;
    this.rulesDir = path.resolve(config.rulesDir);
    this.rulesetVersion = config.rulesetVersion ?? "indicative-sast-v1.0.0";
  }

  async healthCheck(): Promise<ScannerHealth> {
    const checkedAt = new Date().toISOString();
    try {
      await fs.access(this.rulesDir);
    } catch {
      return {
        scanner: this.name,
        available: false,
        message: `Pinned ruleset directory not found: ${this.rulesDir}`,
        checkedAt
      };
    }

    const res = await safeSpawnBinary({
      binary: this.binaryPath,
      args: ["--version"],
      timeoutMs: 15_000
    });

    if (res.exitCode === 0 && res.stdout.trim()) {
      this.version = res.stdout.trim().split(/\r?\n/)[0]!.trim();
      return {
        scanner: this.name,
        available: true,
        version: this.version,
        rulesetVersion: this.rulesetVersion,
        checkedAt
      };
    }

    return {
      scanner: this.name,
      available: false,
      message: res.spawnErrorMessage || res.stderr.trim() || "Semgrep unavailable",
      checkedAt
    };
  }

  async execute(context: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const startedAt = new Date().toISOString();
    const tmpReport = path.join(
      os.tmpdir(),
      `indicative-semgrep-${context.scanId}-${crypto.randomBytes(6).toString("hex")}.json`
    );

    try {
      const args = [
        "scan",
        "--json",
        "--metrics=off",
        "--no-git-ignore",
        "--config",
        this.rulesDir,
        "--output",
        tmpReport,
        context.workspacePath
      ];

      const execRes = await safeSpawnBinary({
        binary: this.binaryPath,
        args,
        timeoutMs: context.timeoutMs,
        signal: context.signal
      });

      const completedAt = new Date().toISOString();

      if (execRes.cancelled) {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: this.rulesetVersion,
          capabilities: this.capabilities,
          status: "CANCELLED",
          errorClass: "CANCELLED",
          errorMessage: "Semgrep execution was cancelled.",
          exitCode: execRes.exitCode,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations: [],
          findings: []
        };
      }

      if (execRes.timedOut) {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: this.rulesetVersion,
          capabilities: this.capabilities,
          status: "TIMEOUT",
          errorClass: "TIMEOUT",
          errorMessage: `Semgrep timed out after ${context.timeoutMs}ms.`,
          exitCode: execRes.exitCode,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations: [],
          findings: []
        };
      }

      if (execRes.spawnErrorCode === "ENOENT") {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: this.rulesetVersion,
          capabilities: this.capabilities,
          status: "UNAVAILABLE",
          errorClass: "BINARY_NOT_FOUND",
          errorMessage: `Semgrep binary not found: ${this.binaryPath}`,
          exitCode: null,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations: [],
          findings: []
        };
      }

      // Semgrep returns 0 on success (even with findings unless --error is passed)
      if (execRes.exitCode !== 0 && execRes.exitCode !== 1) {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: this.rulesetVersion,
          capabilities: this.capabilities,
          status: "FAILED",
          errorClass: classifyProcessError(execRes),
          errorMessage: redactSecretsInText(
            execRes.stderr.trim() || `Semgrep exited with code ${execRes.exitCode}`
          ),
          exitCode: execRes.exitCode,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations: [],
          findings: []
        };
      }

      let rawJson: string;
      try {
        rawJson = await fs.readFile(tmpReport, "utf8");
      } catch {
        rawJson = execRes.stdout;
      }

      try {
        const parsed = parseSemgrepOutput(
          rawJson,
          context.workspacePath,
          this.version,
          this.rulesetVersion
        );
        this.version = parsed.version;

        const limitations = parsed.errors.map((msg) => ({
          code: "SEMGREP_PARSE_WARNING",
          message: redactSecretsInText(msg)
        }));

        return {
          scanner: this.name,
          scannerVersion: parsed.version,
          rulesetVersion: this.rulesetVersion,
          capabilities: this.capabilities,
          status: parsed.errors.length > 0 && parsed.findings.length === 0 ? "PARTIAL" : "SUCCESS",
          errorClass: "NONE",
          exitCode: execRes.exitCode,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations,
          findings: parsed.findings
        };
      } catch (err) {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: this.rulesetVersion,
          capabilities: this.capabilities,
          status: "FAILED",
          errorClass: "MALFORMED_OUTPUT",
          errorMessage: `Failed to parse Semgrep JSON output: ${(err as Error).message}`,
          exitCode: execRes.exitCode,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations: [],
          findings: []
        };
      }
    } finally {
      await fs.rm(tmpReport, { force: true }).catch(() => {});
    }
  }
}
