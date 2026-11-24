import fs from "node:fs/promises";
import path from "node:path";
import type {
  ScannerAdapter,
  ScannerCapability,
  ScannerExecutionContext,
  ScannerExecutionResult,
  ScannerHealth,
  ScannerLimitation
} from "@indicative/contracts";
import {
  normalizeRepoRelativePath,
  validateSafePathWithinRoot
} from "@indicative/security";
import {
  analyzeStructuredOidcPolicies,
  analyzeTerraformOidcPolicies
} from "./oidc/oidcAnalyzer.js";
import {
  MAX_WORKFLOW_FILE_BYTES,
  parseGitHubWorkflowYaml
} from "./parser/workflowParser.js";
import { DEFAULT_CICD_POLICY, evaluateCicdPolicy } from "./policy.js";
import { evaluateCicdSecurityRules } from "./rules/engine.js";
import {
  CICD_RULESET_VERSION,
  CICD_SCANNER_NAME,
  CICD_SCANNER_VERSION,
  type CicdAnalysisReport,
  type CicdPolicyConfig,
  type OidcTrustPolicy,
  type ParsedWorkflow
} from "./types.js";

const MAX_WORKFLOW_FILES = 500;
const MAX_IAC_FILES = 1500;
const MAX_IAC_FILE_BYTES = 512 * 1024;
const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".trivy-cache",
  "vendor",
  "target"
]);

async function collectFilesRecursive(
  workspaceRoot: string,
  dir: string,
  predicate: (relPath: string) => boolean,
  maxFiles: number,
  out: Array<{ fullPath: string; relPath: string }>,
  state: { truncated: boolean }
): Promise<void> {
  if (out.length >= maxFiles) {
    state.truncated = true;
    return;
  }

  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (out.length >= maxFiles) {
      state.truncated = true;
      return;
    }

    const fullPath = path.join(dir, entry.name);
    let stat;
    try {
      stat = await fs.lstat(fullPath);
    } catch {
      continue;
    }

    // Never follow symlinks during static analysis (CICD-T3)
    if (stat.isSymbolicLink()) continue;

    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await collectFilesRecursive(workspaceRoot, fullPath, predicate, maxFiles, out, state);
    } else if (stat.isFile()) {
      let relPath: string;
      try {
        validateSafePathWithinRoot(workspaceRoot, fullPath);
        relPath = normalizeRepoRelativePath(workspaceRoot, fullPath);
      } catch {
        continue;
      }
      if (predicate(relPath)) {
        out.push({ fullPath, relPath });
      }
    }
  }
}

export async function analyzeWorkspaceCicdSecurity(
  workspacePath: string,
  policy: CicdPolicyConfig = DEFAULT_CICD_POLICY
): Promise<CicdAnalysisReport> {
  const resolvedRoot = path.resolve(workspacePath);
  const workflows: ParsedWorkflow[] = [];
  const oidcTrustPolicies: OidcTrustPolicy[] = [];
  const limitations: ScannerLimitation[] = [];

  // 1. Discover .github/workflows/**/*.{yml,yaml}
  const workflowsDir = path.join(resolvedRoot, ".github", "workflows");
  const workflowFiles: Array<{ fullPath: string; relPath: string }> = [];
  const wfState = { truncated: false };

  try {
    const wfStat = await fs.lstat(workflowsDir);
    if (wfStat.isDirectory() && !wfStat.isSymbolicLink()) {
      await collectFilesRecursive(
        resolvedRoot,
        workflowsDir,
        (rel) => /\.(?:yml|yaml)$/i.test(rel),
        MAX_WORKFLOW_FILES,
        workflowFiles,
        wfState
      );
    }
  } catch {
    // No .github/workflows directory present
  }

  if (wfState.truncated) {
    limitations.push({
      code: "WORKFLOW_FILE_LIMIT_REACHED",
      message: `Repository exceeded ${MAX_WORKFLOW_FILES} workflow files; remaining workflow files were not scanned.`,
      scopeAffected: "cicd_workflows"
    });
  }

  for (const wfFile of workflowFiles) {
    try {
      const stat = await fs.stat(wfFile.fullPath);
      if (stat.size > MAX_WORKFLOW_FILE_BYTES) {
        limitations.push({
          code: "WORKFLOW_FILE_TOO_LARGE",
          message: `Skipped workflow "${wfFile.relPath}" (${stat.size} bytes > ${MAX_WORKFLOW_FILE_BYTES} byte safety limit).`,
          scopeAffected: wfFile.relPath
        });
        continue;
      }
      const content = await fs.readFile(wfFile.fullPath, "utf8");
      const parsed = parseGitHubWorkflowYaml(wfFile.relPath, content);
      if (parsed.error || !parsed.workflow) {
        limitations.push({
          code: "WORKFLOW_YAML_PARSE_ERROR",
          message: parsed.error ?? `Unable to parse workflow "${wfFile.relPath}".`,
          scopeAffected: wfFile.relPath
        });
      } else {
        workflows.push(parsed.workflow);
      }
    } catch (err) {
      limitations.push({
        code: "WORKFLOW_READ_ERROR",
        message: `Unable to read workflow "${wfFile.relPath}": ${(err as Error).message}`,
        scopeAffected: wfFile.relPath
      });
    }
  }

  const normalizedIgnorePrefixes = (policy.ignorePaths ?? [])
    .map((p) => p.replace(/\\/g, "/").replace(/^\/+|\/+$/g, ""))
    .filter(Boolean);
  const isIgnored = (relPath: string): boolean => {
    const clean = relPath.replace(/\\/g, "/");
    return normalizedIgnorePrefixes.some(
      (prefix) => clean === prefix || clean.startsWith(`${prefix}/`)
    );
  };

  // 2. Discover static cloud OIDC trust policies (.tf, CloudFormation/IAM .json/.yaml/.yml)
  const iacFiles: Array<{ fullPath: string; relPath: string }> = [];
  const iacState = { truncated: false };
  await collectFilesRecursive(
    resolvedRoot,
    resolvedRoot,
    (rel) => {
      const lower = rel.toLowerCase();
      if (isIgnored(rel)) return false;
      if (lower.startsWith(".github/workflows/")) return false;
      if (lower.endsWith("package-lock.json") || lower.endsWith("tsconfig.json")) return false;
      return lower.endsWith(".tf") || lower.endsWith(".json") || lower.endsWith(".yaml") || lower.endsWith(".yml");
    },
    MAX_IAC_FILES,
    iacFiles,
    iacState
  );

  for (const iacFile of iacFiles) {
    try {
      const stat = await fs.stat(iacFile.fullPath);
      if (stat.size > MAX_IAC_FILE_BYTES) continue;
      const content = await fs.readFile(iacFile.fullPath, "utf8");
      if (!content.includes("token.actions.githubusercontent.com")) continue;

      if (iacFile.relPath.toLowerCase().endsWith(".tf")) {
        oidcTrustPolicies.push(...analyzeTerraformOidcPolicies(iacFile.relPath, content));
      } else {
        oidcTrustPolicies.push(...analyzeStructuredOidcPolicies(iacFile.relPath, content));
      }
    } catch {
      // Skip unreadable non-workflow files silently unless workflow parsing failed
    }
  }

  const findings = evaluateCicdSecurityRules({
    workflows,
    oidcTrustPolicies,
    disabledRules: policy.disabledRules
  });

  const policyEvaluation = evaluateCicdPolicy(findings, policy);

  return {
    scanner: CICD_SCANNER_NAME,
    scannerVersion: CICD_SCANNER_VERSION,
    rulesetVersion: CICD_RULESET_VERSION,
    analyzedAt: new Date().toISOString(),
    workflows,
    oidcTrustPolicies,
    findings,
    limitations,
    policyEvaluation
  };
}

/**
 * ScannerAdapter implementation integrating Indicative's deterministic GitHub Actions
 * and static OIDC federation analyzer directly into scanner-runner and the canonical pipeline.
 */
export class CicdGitHubActionsAdapter implements ScannerAdapter {
  public readonly name = CICD_SCANNER_NAME;
  public readonly version = CICD_SCANNER_VERSION;
  public readonly capabilities: ScannerCapability[] = ["cicd"];
  private readonly policy: CicdPolicyConfig;

  constructor(policy: CicdPolicyConfig = DEFAULT_CICD_POLICY) {
    this.policy = policy;
  }

  async healthCheck(): Promise<ScannerHealth> {
    return {
      scanner: this.name,
      available: true,
      version: this.version,
      rulesetVersion: CICD_RULESET_VERSION,
      message: "Built-in deterministic GitHub Actions & static OIDC analyzer ready (offline).",
      checkedAt: new Date().toISOString()
    };
  }

  async execute(context: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const startedAt = new Date().toISOString();
    const startMs = Date.now();

    if (context.signal?.aborted) {
      return {
        scanner: this.name,
        scannerVersion: this.version,
        rulesetVersion: CICD_RULESET_VERSION,
        capabilities: this.capabilities,
        status: "CANCELLED",
        errorClass: "CANCELLED",
        errorMessage: "CI/CD analyzer cancelled prior to execution.",
        exitCode: null,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: Date.now() - startMs,
        limitations: [],
        findings: []
      };
    }

    try {
      const report = await analyzeWorkspaceCicdSecurity(context.workspacePath, this.policy);
      const hasParseFailure = report.limitations.some(
        (l) =>
          l.code === "WORKFLOW_YAML_PARSE_ERROR" ||
          l.code === "WORKFLOW_FILE_TOO_LARGE" ||
          l.code === "WORKFLOW_FILE_LIMIT_REACHED"
      );

      return {
        scanner: this.name,
        scannerVersion: this.version,
        rulesetVersion: CICD_RULESET_VERSION,
        capabilities: this.capabilities,
        status: hasParseFailure ? "PARTIAL" : "SUCCESS",
        errorClass: hasParseFailure ? "MALFORMED_OUTPUT" : "NONE",
        errorMessage: hasParseFailure
          ? report.limitations.map((l) => l.message).join(" ")
          : undefined,
        exitCode: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: Date.now() - startMs,
        limitations: report.limitations,
        resourceUsage: {
          filesScanned: report.workflows.length + report.oidcTrustPolicies.length
        },
        findings: report.findings
      };
    } catch (err) {
      return {
        scanner: this.name,
        scannerVersion: this.version,
        rulesetVersion: CICD_RULESET_VERSION,
        capabilities: this.capabilities,
        status: "FAILED",
        errorClass: "EXECUTION_ERROR",
        errorMessage: (err as Error).message,
        exitCode: 1,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: Date.now() - startMs,
        limitations: [],
        findings: []
      };
    }
  }
}
