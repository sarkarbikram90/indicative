import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import type {
  FindingSeverity,
  RawScannerFinding,
  ScannerAdapter,
  ScannerCapability,
  ScannerExecutionContext,
  ScannerExecutionResult,
  ScannerHealth,
  ScannerLimitation
} from "@indicative/contracts";
import {
  computeSecretFingerprint,
  maskSecretValue,
  normalizeRepoRelativePath,
  redactSecretsInText
} from "@indicative/security";
import { classifyProcessError, safeSpawnBinary } from "./process.js";

export interface GitleaksAdapterConfig {
  binaryPath: string;
  configPath?: string;
}

interface GitleaksJsonFinding {
  RuleID?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  Commit?: string;
  Author?: string;
  Date?: string;
  Message?: string;
  Entropy?: number;
  Fingerprint?: string;
}

const CRITICAL_SECRET_RULES = [
  "aws-access-token",
  "aws-secret",
  "private-key",
  "github-pat",
  "github-fine-grained-pat",
  "github-oauth",
  "github-app-token",
  "stripe-access-token",
  "gcp-api-key",
  "postgres",
  "mysql",
  "database"
];

export function mapGitleaksSeverity(ruleId: string): FindingSeverity {
  const lower = ruleId.toLowerCase();
  if (CRITICAL_SECRET_RULES.some((r) => lower.includes(r))) {
    return "CRITICAL";
  }
  return "HIGH";
}

/**
 * Parses raw Gitleaks JSON output and IMMEDIATELY:
 * 1. Computes tenant-keyed HMAC-SHA256 secretFingerprint
 * 2. Replaces all raw Secret/Match substrings with safe masked values
 * 3. Never returns any plaintext credential field
 */
export function parseAndRedactGitleaksOutput(
  rawJson: string,
  options: {
    workspacePath: string;
    scannerVersion: string;
    organizationId: string;
    secretFingerprintKey: string;
    exposureLocation: "WORKING_TREE" | "GIT_HISTORY";
  }
): RawScannerFinding[] {
  const trimmed = rawJson.trim();
  if (!trimmed || trimmed === "null") return [];

  const parsed = JSON.parse(trimmed) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error("Gitleaks JSON output must be an array.");
  }

  const findings: RawScannerFinding[] = [];

  for (const raw of parsed as GitleaksJsonFinding[]) {
    if (!raw || typeof raw !== "object" || !raw.RuleID) continue;

    const secretMaterial = raw.Secret || raw.Match || "";
    if (!secretMaterial) continue;

    // Tenant-keyed HMAC-SHA256 fingerprint (plaintext never stored!)
    const secretFingerprint = computeSecretFingerprint(
      secretMaterial,
      options.secretFingerprintKey,
      options.organizationId
    );
    const maskedSecret = maskSecretValue(secretMaterial, raw.RuleID);

    const knownSecrets = [raw.Secret, raw.Match].filter(
      (s): s is string => typeof s === "string" && s.length > 0
    );

    const safeSnippet = raw.Match
      ? redactSecretsInText(raw.Match, knownSecrets)
      : maskedSecret;

    let relPath: string | undefined;
    if (raw.File) {
      try {
        relPath = normalizeRepoRelativePath(options.workspacePath, raw.File);
      } catch {
        relPath = raw.File.replace(/\\/g, "/");
      }
    }

    const commitSha = raw.Commit && raw.Commit.trim().length > 0 ? raw.Commit.trim() : undefined;
    const commitTimestamp =
      raw.Date && raw.Date.trim().length > 0 ? raw.Date.trim() : undefined;

    const locationLabel =
      options.exposureLocation === "GIT_HISTORY" && commitSha
        ? `Git commit ${commitSha.slice(0, 10)}`
        : "current repository working tree";

    findings.push({
      scanner: "gitleaks",
      scannerVersion: options.scannerVersion,
      rulesetVersion: "gitleaks-v8-default",
      ruleId: raw.RuleID,
      category: "SECRET",
      title: `Exposed ${raw.Description || raw.RuleID} in ${relPath ?? "repository"}`,
      description:
        `Potential ${raw.Description || raw.RuleID} detected in ${locationLabel}. ` +
        `Credential validity is NOT_VERIFIED. Removing a secret from repository files does not revoke the credential.`,
      originalSeverity: "HIGH",
      severity: mapGitleaksSeverity(raw.RuleID),
      confidence: typeof raw.Entropy === "number" && raw.Entropy >= 3.5 ? "HIGH" : "MEDIUM",
      filePath: relPath,
      lineStart: raw.StartLine,
      lineEnd: raw.EndLine,
      codeSnippet: safeSnippet,
      references: ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
      secretType: raw.RuleID,
      secretFingerprint,
      redactedMatch: maskedSecret,
      commitSha,
      commitTimestamp,
      exposureLocation: options.exposureLocation,
      remediationHint:
        "1. Immediately revoke and rotate the exposed credential with the issuing provider (repository removal alone is insufficient). " +
        "2. Remove the secret from current files and scrub Git history if appropriate. " +
        "3. Move secrets to environment variables or a dedicated secret manager.",
      rawMetadata: {
        secretValidity: "NOT_VERIFIED",
        ...(typeof raw.Entropy === "number" ? { entropy: Math.round(raw.Entropy * 100) / 100 } : {})
      }
    });
  }

  return findings;
}

export class GitleaksScannerAdapter implements ScannerAdapter {
  public readonly name = "gitleaks";
  public version = "8.30.1";
  public readonly capabilities: ScannerCapability[] = ["secrets"];
  private readonly binaryPath: string;
  private readonly configPath?: string;

  constructor(config: GitleaksAdapterConfig) {
    this.binaryPath = config.binaryPath;
    this.configPath = config.configPath;
  }

  async healthCheck(): Promise<ScannerHealth> {
    const checkedAt = new Date().toISOString();
    const res = await safeSpawnBinary({
      binary: this.binaryPath,
      args: ["version"],
      timeoutMs: 10_000
    });

    if (res.exitCode === 0 && res.stdout.trim()) {
      this.version = res.stdout.trim().replace(/^v/i, "").split(/\r?\n/)[0]!.trim();
      return {
        scanner: this.name,
        available: true,
        version: this.version,
        rulesetVersion: "gitleaks-v8-default",
        checkedAt
      };
    }

    return {
      scanner: this.name,
      available: false,
      message: res.spawnErrorMessage || res.stderr.trim() || "Gitleaks unavailable",
      checkedAt
    };
  }

  private async runMode(
    mode: "git" | "dir",
    context: ScannerExecutionContext
  ): Promise<{
    ok: boolean;
    status: ScannerExecutionResult["status"];
    errorClass: ScannerExecutionResult["errorClass"];
    errorMessage?: string;
    exitCode: number | null;
    durationMs: number;
    findings: RawScannerFinding[];
  }> {
    const tmpReport = path.join(
      os.tmpdir(),
      `indicative-gitleaks-${mode}-${context.scanId}-${crypto.randomBytes(6).toString("hex")}.json`
    );

    try {
      const args: string[] = [
        mode,
        context.workspacePath,
        "--report-format",
        "json",
        "--report-path",
        tmpReport,
        "--exit-code",
        "0",
        "--no-banner"
      ];

      if (mode === "git" && context.maxGitHistoryCommits > 0) {
        args.push("--log-opts", `--max-count=${context.maxGitHistoryCommits}`);
      }

      if (this.configPath) {
        args.push("--config", this.configPath);
      }

      const execRes = await safeSpawnBinary({
        binary: this.binaryPath,
        args,
        timeoutMs: context.timeoutMs,
        signal: context.signal
      });

      if (execRes.cancelled) {
        return {
          ok: false,
          status: "CANCELLED",
          errorClass: "CANCELLED",
          errorMessage: `Gitleaks (${mode}) cancelled.`,
          exitCode: execRes.exitCode,
          durationMs: execRes.durationMs,
          findings: []
        };
      }
      if (execRes.timedOut) {
        return {
          ok: false,
          status: "TIMEOUT",
          errorClass: "TIMEOUT",
          errorMessage: `Gitleaks (${mode}) timed out after ${context.timeoutMs}ms.`,
          exitCode: execRes.exitCode,
          durationMs: execRes.durationMs,
          findings: []
        };
      }
      if (execRes.spawnErrorCode === "ENOENT") {
        return {
          ok: false,
          status: "UNAVAILABLE",
          errorClass: "BINARY_NOT_FOUND",
          errorMessage: `Gitleaks binary not found: ${this.binaryPath}`,
          exitCode: null,
          durationMs: execRes.durationMs,
          findings: []
        };
      }
      if (execRes.exitCode !== 0 && execRes.exitCode !== 1) {
        return {
          ok: false,
          status: "FAILED",
          errorClass: classifyProcessError(execRes),
          errorMessage: redactSecretsInText(
            execRes.stderr.trim() || `Gitleaks (${mode}) exited with code ${execRes.exitCode}`
          ),
          exitCode: execRes.exitCode,
          durationMs: execRes.durationMs,
          findings: []
        };
      }

      let rawJson = "[]";
      try {
        rawJson = await fs.readFile(tmpReport, "utf8");
      } catch {
        // Gitleaks writes no report file or empty array when zero leaks found
        rawJson = "[]";
      }

      try {
        const findings = parseAndRedactGitleaksOutput(rawJson, {
          workspacePath: context.workspacePath,
          scannerVersion: this.version,
          organizationId: context.organizationId,
          secretFingerprintKey: context.secretFingerprintKey,
          exposureLocation: mode === "git" ? "GIT_HISTORY" : "WORKING_TREE"
        });
        return {
          ok: true,
          status: "SUCCESS",
          errorClass: "NONE",
          exitCode: execRes.exitCode,
          durationMs: execRes.durationMs,
          findings
        };
      } catch (err) {
        return {
          ok: false,
          status: "FAILED",
          errorClass: "MALFORMED_OUTPUT",
          errorMessage: `Failed to parse Gitleaks (${mode}) output: ${(err as Error).message}`,
          exitCode: execRes.exitCode,
          durationMs: execRes.durationMs,
          findings: []
        };
      }
    } finally {
      // CRITICAL: Immediately destroy unredacted raw Gitleaks JSON output from disk
      await fs.rm(tmpReport, { force: true }).catch(() => {});
    }
  }

  async execute(context: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const startedAt = new Date().toISOString();
    const limitations: ScannerLimitation[] = [];
    const allFindings: RawScannerFinding[] = [];
    let totalDuration = 0;

    // 1. Scan current working tree
    const dirRes = await this.runMode("dir", context);
    totalDuration += dirRes.durationMs;
    if (!dirRes.ok) {
      return {
        scanner: this.name,
        scannerVersion: this.version,
        rulesetVersion: "gitleaks-v8-default",
        capabilities: this.capabilities,
        status: dirRes.status,
        errorClass: dirRes.errorClass,
        errorMessage: dirRes.errorMessage,
        exitCode: dirRes.exitCode,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: totalDuration,
        limitations,
        findings: []
      };
    }
    allFindings.push(...dirRes.findings);

    // 2. Scan Git commit history when available — never silently pretend shallow/no-git is full history
    if (!context.hasGitHistory) {
      limitations.push({
        code: "NO_GIT_HISTORY",
        message:
          "Target workspace did not contain a .git directory; only current working tree files were scanned.",
        scopeAffected: "git_history"
      });
    } else {
      if (context.isShallowClone) {
        limitations.push({
          code: "SHALLOW_CLONE_HISTORY_TRUNCATED",
          message:
            "Repository clone was shallow; historical commits prior to clone depth could not be scanned for secrets.",
          scopeAffected: "git_history"
        });
      }

      const gitRes = await this.runMode("git", context);
      totalDuration += gitRes.durationMs;

      if (!gitRes.ok) {
        limitations.push({
          code: "GIT_HISTORY_SCAN_FAILED",
          message: gitRes.errorMessage || "Git history secret scan failed.",
          scopeAffected: "git_history"
        });
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: "gitleaks-v8-default",
          capabilities: this.capabilities,
          status: "PARTIAL",
          errorClass: gitRes.errorClass,
          errorMessage: gitRes.errorMessage,
          exitCode: gitRes.exitCode,
          startedAt,
          completedAt: new Date().toISOString(),
          durationMs: totalDuration,
          limitations,
          findings: allFindings
        };
      }

      // Mark secrets found in BOTH working tree and git history accurately
      const workingTreeFps = new Set(
        dirRes.findings.map((f) => f.secretFingerprint).filter(Boolean)
      );
      for (const gitFinding of gitRes.findings) {
        if (gitFinding.secretFingerprint && workingTreeFps.has(gitFinding.secretFingerprint)) {
          gitFinding.exposureLocation = "BOTH";
        }
        allFindings.push(gitFinding);
      }
    }

    return {
      scanner: this.name,
      scannerVersion: this.version,
      rulesetVersion: "gitleaks-v8-default",
      capabilities: this.capabilities,
      status: "SUCCESS",
      errorClass: "NONE",
      exitCode: 0,
      startedAt,
      completedAt: new Date().toISOString(),
      durationMs: totalDuration,
      limitations,
      findings: allFindings
    };
  }
}
