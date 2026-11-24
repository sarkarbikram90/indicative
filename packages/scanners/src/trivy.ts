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
  ScannerHealth
} from "@indicative/contracts";
import { normalizeRepoRelativePath, redactSecretsInText } from "@indicative/security";
import { readBoundedTextFile, ScannerReportSizeExceededError } from "./boundedReader.js";
import { classifyProcessError, safeSpawnBinary } from "./process.js";

export interface TrivyAdapterConfig {
  binaryPath: string;
  cacheDir: string;
  offlineMode?: boolean;
  maxDbAgeDays?: number;
}

export interface TrivyDbFreshness {
  present: boolean;
  updatedAt?: string;
  ageDays?: number;
  stale: boolean;
}

export async function inspectTrivyOfflineDbFreshness(
  cacheDir: string,
  maxDbAgeDays = 14
): Promise<TrivyDbFreshness> {
  const dbPath = path.join(cacheDir, "db", "trivy.db");
  try {
    await fs.access(dbPath);
  } catch {
    return { present: false, stale: true };
  }

  const metaPath = path.join(cacheDir, "db", "metadata.json");
  try {
    const raw = await fs.readFile(metaPath, "utf8");
    const meta = JSON.parse(raw) as { UpdatedAt?: string };
    if (meta.UpdatedAt) {
      const updatedMs = Date.parse(meta.UpdatedAt);
      if (!Number.isNaN(updatedMs)) {
        const ageDays = Math.max(0, (Date.now() - updatedMs) / (1000 * 60 * 60 * 24));
        return {
          present: true,
          updatedAt: meta.UpdatedAt,
          ageDays: Math.round(ageDays * 10) / 10,
          stale: ageDays > maxDbAgeDays
        };
      }
    }
  } catch {
    // metadata.json missing or unreadable; fall back to file mtime
    try {
      const stat = await fs.stat(dbPath);
      const ageDays = Math.max(0, (Date.now() - stat.mtimeMs) / (1000 * 60 * 60 * 24));
      return {
        present: true,
        updatedAt: stat.mtime.toISOString(),
        ageDays: Math.round(ageDays * 10) / 10,
        stale: ageDays > maxDbAgeDays
      };
    } catch {
      return { present: true, stale: false };
    }
  }

  return { present: true, stale: false };
}

interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  PrimaryURL?: string;
  References?: string[];
  CVSS?: Record<string, { V3Score?: number; V2Score?: number }>;
}

interface TrivyMisconfiguration {
  ID?: string;
  AVDID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: string;
  Status?: string;
  PrimaryURL?: string;
  References?: string[];
  CauseMetadata?: {
    Resource?: string;
    StartLine?: number;
    EndLine?: number;
    Code?: {
      Lines?: Array<{ Number?: number; Content?: string; IsCause?: boolean }>;
    };
  };
}

interface TrivyResultBlock {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

interface TrivyJsonReport {
  SchemaVersion?: number;
  Results?: TrivyResultBlock[];
}

export function mapTrivySeverity(sev?: string): FindingSeverity {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH" || s === "MEDIUM" || s === "LOW") return s;
  return "UNKNOWN";
}

function extractCvssScore(
  cvss?: Record<string, { V3Score?: number; V2Score?: number }>
): number | undefined {
  if (!cvss) return undefined;
  let best: number | undefined;
  for (const entry of Object.values(cvss)) {
    const score = entry.V3Score ?? entry.V2Score;
    if (typeof score === "number" && (best === undefined || score > best)) {
      best = score;
    }
  }
  return best;
}

export function parseTrivyOutput(
  rawJson: string,
  workspacePath: string,
  scannerVersion: string
): RawScannerFinding[] {
  const parsed = JSON.parse(rawJson) as TrivyJsonReport;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Trivy JSON output is not an object.");
  }

  const findings: RawScannerFinding[] = [];
  const results = Array.isArray(parsed.Results) ? parsed.Results : [];

  for (const block of results) {
    let relPath: string | undefined;
    if (block.Target) {
      try {
        relPath = normalizeRepoRelativePath(workspacePath, block.Target);
      } catch {
        relPath = block.Target;
      }
    }

    // 1. SCA dependency vulnerabilities
    for (const vuln of block.Vulnerabilities ?? []) {
      if (!vuln.VulnerabilityID || !vuln.PkgName) continue;
      const refs = [
        ...(vuln.PrimaryURL ? [vuln.PrimaryURL] : []),
        ...(vuln.References ?? [])
      ].slice(0, 8);
      const cvssScore = extractCvssScore(vuln.CVSS);

      findings.push({
        scanner: "trivy",
        scannerVersion,
        rulesetVersion: "trivy-offline-db-v2",
        ruleId: vuln.VulnerabilityID,
        category: "SCA",
        title:
          vuln.Title ||
          `${vuln.VulnerabilityID} in ${vuln.PkgName}@${vuln.InstalledVersion ?? "unknown"}`,
        description: redactSecretsInText(
          vuln.Description ||
            `Known vulnerability ${vuln.VulnerabilityID} affects ${vuln.PkgName} (${vuln.InstalledVersion ?? "unknown"}).`
        ),
        originalSeverity: vuln.Severity,
        severity: mapTrivySeverity(vuln.Severity),
        confidence: "HIGH",
        filePath: relPath,
        packageName: vuln.PkgName,
        installedVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion || undefined,
        cve: vuln.VulnerabilityID,
        cvssScore,
        references: refs,
        remediationHint: vuln.FixedVersion
          ? `Upgrade ${vuln.PkgName} from ${vuln.InstalledVersion ?? "current"} to ${vuln.FixedVersion} (or later patched release) and regenerate lockfiles.`
          : `No upstream fixed version reported yet for ${vuln.PkgName}. Review vendor advisory and apply compensating controls or evaluate alternative packages.`,
        rawMetadata: {
          ecosystem: block.Type ?? "unknown",
          resultClass: block.Class ?? "lang-pkgs"
        }
      });
    }

    // 2. IaC / Configuration misconfigurations
    for (const misconf of block.Misconfigurations ?? []) {
      if (misconf.Status && misconf.Status.toUpperCase() !== "FAIL") continue;
      const ruleId = misconf.AVDID || misconf.ID;
      if (!ruleId) continue;

      const snippetLines = misconf.CauseMetadata?.Code?.Lines?.map(
        (l) => `${l.Number ?? ""}: ${l.Content ?? ""}`
      ).join("\n");

      const refs = [
        ...(misconf.PrimaryURL ? [misconf.PrimaryURL] : []),
        ...(misconf.References ?? [])
      ].slice(0, 8);

      findings.push({
        scanner: "trivy",
        scannerVersion,
        rulesetVersion: "trivy-offline-checks",
        ruleId,
        category: "IAC",
        title: misconf.Title || `Misconfiguration ${ruleId}`,
        description: redactSecretsInText(
          [misconf.Description, misconf.Message].filter(Boolean).join(" — ") ||
            `Configuration weakness ${ruleId}`
        ),
        originalSeverity: misconf.Severity,
        severity: mapTrivySeverity(misconf.Severity),
        confidence: "HIGH",
        filePath: relPath,
        lineStart: misconf.CauseMetadata?.StartLine,
        lineEnd: misconf.CauseMetadata?.EndLine,
        codeSnippet: snippetLines ? redactSecretsInText(snippetLines) : undefined,
        references: refs,
        remediationHint: misconf.Resolution,
        rawMetadata: {
          configType: block.Type ?? "config",
          ...(misconf.CauseMetadata?.Resource
            ? { resource: misconf.CauseMetadata.Resource }
            : {})
        }
      });
    }
  }

  return findings;
}

export class TrivyScannerAdapter implements ScannerAdapter {
  public readonly name = "trivy";
  public version = "0.76.2";
  public readonly capabilities: ScannerCapability[] = ["sca", "misconfiguration"];
  private readonly binaryPath: string;
  private readonly cacheDir: string;
  private readonly offlineMode: boolean;
  private readonly maxDbAgeDays: number;

  constructor(config: TrivyAdapterConfig) {
    this.binaryPath = config.binaryPath;
    this.cacheDir = path.resolve(config.cacheDir);
    this.offlineMode = config.offlineMode ?? true;
    this.maxDbAgeDays = config.maxDbAgeDays ?? 14;
  }

  async healthCheck(): Promise<ScannerHealth> {
    const checkedAt = new Date().toISOString();
    const res = await safeSpawnBinary({
      binary: this.binaryPath,
      args: ["--version"],
      timeoutMs: 10_000
    });

    if (res.exitCode !== 0) {
      return {
        scanner: this.name,
        available: false,
        message: res.spawnErrorMessage || res.stderr.trim() || "Trivy unavailable",
        checkedAt
      };
    }

    const versionMatch = res.stdout.match(/Version:\s*([^\s]+)/i);
    if (versionMatch?.[1]) {
      this.version = versionMatch[1];
    }

    // Verify offline vulnerability DB exists and inspect freshness when running offline
    if (this.offlineMode) {
      const freshness = await inspectTrivyOfflineDbFreshness(this.cacheDir, this.maxDbAgeDays);
      if (!freshness.present) {
        const dbPath = path.join(this.cacheDir, "db", "trivy.db");
        return {
          scanner: this.name,
          available: false,
          version: this.version,
          message: `Offline Trivy DB missing at ${dbPath}. Run trivy fs --download-db-only --cache-dir <dir>.`,
          checkedAt
        };
      }
      if (freshness.stale) {
        return {
          scanner: this.name,
          available: true,
          version: this.version,
          rulesetVersion: `trivy-offline-db-v2 (updated ${freshness.updatedAt ?? "unknown"})`,
          message: `Offline Trivy vulnerability DB is ${freshness.ageDays} days old (threshold: ${this.maxDbAgeDays} days). Refresh via infrastructure/scripts/update-trivy-db.sh.`,
          checkedAt
        };
      }
    }

    return {
      scanner: this.name,
      available: true,
      version: this.version,
      rulesetVersion: "trivy-offline-db-v2",
      checkedAt
    };
  }

  async execute(context: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const startedAt = new Date().toISOString();
    const tmpReport = path.join(
      os.tmpdir(),
      `indicative-trivy-${context.scanId}-${crypto.randomBytes(6).toString("hex")}.json`
    );

    try {
      const args = [
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig",
        "--cache-dir",
        this.cacheDir,
        "--quiet",
        "--output",
        tmpReport
      ];

      if (this.offlineMode) {
        args.push("--skip-db-update", "--skip-check-update", "--offline-scan");
      }

      args.push(context.workspacePath);

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
          rulesetVersion: "trivy-offline-db-v2",
          capabilities: this.capabilities,
          status: "CANCELLED",
          errorClass: "CANCELLED",
          errorMessage: "Trivy execution was cancelled.",
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
          rulesetVersion: "trivy-offline-db-v2",
          capabilities: this.capabilities,
          status: "TIMEOUT",
          errorClass: "TIMEOUT",
          errorMessage: `Trivy timed out after ${context.timeoutMs}ms.`,
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
          rulesetVersion: "trivy-offline-db-v2",
          capabilities: this.capabilities,
          status: "UNAVAILABLE",
          errorClass: "BINARY_NOT_FOUND",
          errorMessage: `Trivy binary not found: ${this.binaryPath}`,
          exitCode: null,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations: [],
          findings: []
        };
      }

      if (execRes.exitCode !== 0) {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: "trivy-offline-db-v2",
          capabilities: this.capabilities,
          status: "FAILED",
          errorClass: classifyProcessError(execRes),
          errorMessage: redactSecretsInText(
            execRes.stderr.trim() || `Trivy exited with code ${execRes.exitCode}`
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
        const read = await readBoundedTextFile(tmpReport, context.maxReportBytes);
        rawJson = read.content;
      } catch (err) {
        if (err instanceof ScannerReportSizeExceededError) {
          return {
            scanner: this.name,
            scannerVersion: this.version,
            rulesetVersion: "trivy-offline-db-v2",
            capabilities: this.capabilities,
            status: "FAILED",
            errorClass: "RESOURCE_LIMIT",
            errorMessage: err.message,
            exitCode: execRes.exitCode,
            startedAt,
            completedAt,
            durationMs: execRes.durationMs,
            limitations: [],
            findings: []
          };
        }
        rawJson = execRes.stdout;
      }

      try {
        const findings = parseTrivyOutput(rawJson, context.workspacePath, this.version);
        const limitations = [];
        let rulesetVersion = "trivy-offline-db-v2";
        if (this.offlineMode) {
          const freshness = await inspectTrivyOfflineDbFreshness(
            this.cacheDir,
            this.maxDbAgeDays
          );
          if (freshness.updatedAt) {
            rulesetVersion = `trivy-offline-db-v2@${freshness.updatedAt.slice(0, 10)}`;
          }
          if (freshness.stale) {
            limitations.push({
              code: "TRIVY_DB_STALE",
              message: `Offline Trivy vulnerability DB is ${freshness.ageDays ?? "unknown"} days old (updated ${freshness.updatedAt ?? "unknown"}); recent CVEs may not be detected.`,
              scopeAffected: "sca_vulnerability_db"
            });
          }
        }
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion,
          capabilities: this.capabilities,
          status: "SUCCESS",
          errorClass: "NONE",
          exitCode: execRes.exitCode,
          startedAt,
          completedAt,
          durationMs: execRes.durationMs,
          limitations,
          findings
        };
      } catch (err) {
        return {
          scanner: this.name,
          scannerVersion: this.version,
          rulesetVersion: "trivy-offline-db-v2",
          capabilities: this.capabilities,
          status: "FAILED",
          errorClass: "MALFORMED_OUTPUT",
          errorMessage: `Failed to parse Trivy JSON output: ${(err as Error).message}`,
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
