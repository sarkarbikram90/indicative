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
  analyzeStructuredOidcPolicies,
  analyzeTerraformOidcPolicies,
  MAX_WORKFLOW_FILE_BYTES,
  parseGitHubWorkflowYaml,
  type OidcTrustPolicy,
  type ParsedWorkflow
} from "@indicative/cicd-security";
import {
  normalizeRepoRelativePath,
  validateSafePathWithinRoot
} from "@indicative/security";
import {
  parseStructuredAwsIamFile,
  parseTerraformIamFiles
} from "./parser/awsIamParser.js";
import { extractWorkflowCloudIdentityRefs } from "./parser/workflowIdentityExtractor.js";
import {
  DEFAULT_CLOUD_IDENTITY_POLICY,
  evaluateCloudIdentityPolicy
} from "./policy.js";
import { evaluateCloudIdentityRules } from "./rules/engine.js";
import {
  CLOUD_IDENTITY_RULESET_VERSION,
  CLOUD_IDENTITY_SCANNER_NAME,
  CLOUD_IDENTITY_SCANNER_VERSION,
  type CloudIamRole,
  type CloudIdentityAnalysisReport,
  type CloudIdentityPolicyConfig,
  type StandaloneIamPolicy
} from "./types.js";

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
  "target",
  "action-dist"
]);

async function collectFiles(
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
    if (stat.isSymbolicLink()) continue;

    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await collectFiles(workspaceRoot, fullPath, predicate, maxFiles, out, state);
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

export async function analyzeWorkspaceCloudIdentity(
  workspacePath: string,
  policy: CloudIdentityPolicyConfig = DEFAULT_CLOUD_IDENTITY_POLICY
): Promise<CloudIdentityAnalysisReport> {
  const resolvedRoot = path.resolve(workspacePath);
  const workflows: ParsedWorkflow[] = [];
  const oidcTrustPolicies: OidcTrustPolicy[] = [];
  const iamRoles: CloudIamRole[] = [];
  const standalonePolicies: StandaloneIamPolicy[] = [];
  const limitations: ScannerLimitation[] = [];

  const normalizedIgnorePrefixes = (policy.ignorePaths ?? [])
    .map((p) => p.replace(/\\/g, "/").replace(/^\/+|\/+$/g, ""))
    .filter(Boolean);
  const isIgnored = (relPath: string): boolean => {
    const clean = relPath.replace(/\\/g, "/");
    return normalizedIgnorePrefixes.some(
      (prefix) => clean === prefix || clean.startsWith(`${prefix}/`)
    );
  };

  // 1. Parse GitHub Actions workflows for cloud role references
  const workflowsDir = path.join(resolvedRoot, ".github", "workflows");
  const workflowFiles: Array<{ fullPath: string; relPath: string }> = [];
  try {
    const wfStat = await fs.lstat(workflowsDir);
    if (wfStat.isDirectory() && !wfStat.isSymbolicLink()) {
      await collectFiles(
        resolvedRoot,
        workflowsDir,
        (rel) => /\.(?:yml|yaml)$/i.test(rel) && !isIgnored(rel),
        500,
        workflowFiles,
        { truncated: false }
      );
    }
  } catch {
    // No workflows directory
  }

  for (const wfFile of workflowFiles) {
    try {
      const stat = await fs.stat(wfFile.fullPath);
      if (stat.size > MAX_WORKFLOW_FILE_BYTES) continue;
      const content = await fs.readFile(wfFile.fullPath, "utf8");
      const parsed = parseGitHubWorkflowYaml(wfFile.relPath, content);
      if (parsed.workflow) workflows.push(parsed.workflow);
    } catch {
      // Non-fatal here; CicdGitHubActionsAdapter reports workflow parse errors
    }
  }

  const workflowIdentityRefs = extractWorkflowCloudIdentityRefs(workflows);

  // 2. Discover Terraform (.tf), CloudFormation (.yml/.yaml/.json), and standalone IAM JSON files
  const iacFiles: Array<{ fullPath: string; relPath: string }> = [];
  const iacState = { truncated: false };
  await collectFiles(
    resolvedRoot,
    resolvedRoot,
    (rel) => {
      const lower = rel.toLowerCase();
      if (isIgnored(rel)) return false;
      if (lower.startsWith(".github/workflows/")) return false;
      if (
        lower.endsWith("package.json") ||
        lower.endsWith("package-lock.json") ||
        lower.endsWith("tsconfig.json") ||
        lower.endsWith(".sarif")
      ) {
        return false;
      }
      return (
        lower.endsWith(".tf") ||
        lower.endsWith(".json") ||
        lower.endsWith(".yaml") ||
        lower.endsWith(".yml")
      );
    },
    MAX_IAC_FILES,
    iacFiles,
    iacState
  );

  if (iacState.truncated) {
    limitations.push({
      code: "CLOUD_IDENTITY_IAC_FILE_LIMIT_REACHED",
      message: `Repository exceeded ${MAX_IAC_FILES} IaC/policy files; remaining files were not scanned.`,
      scopeAffected: "cloud_identity_iac"
    });
  }

  const terraformFiles: Array<{ relPath: string; content: string }> = [];
  for (const iacFile of iacFiles) {
    try {
      const stat = await fs.stat(iacFile.fullPath);
      if (stat.size > MAX_IAC_FILE_BYTES) continue;
      const content = await fs.readFile(iacFile.fullPath, "utf8");
      const lower = iacFile.relPath.toLowerCase();

      if (lower.endsWith(".tf")) {
        if (
          content.includes("aws_iam_") ||
          content.includes("token.actions.githubusercontent.com")
        ) {
          terraformFiles.push({ relPath: iacFile.relPath, content });
          if (content.includes("token.actions.githubusercontent.com")) {
            oidcTrustPolicies.push(...analyzeTerraformOidcPolicies(iacFile.relPath, content));
          }
        }
      } else {
        if (content.includes("token.actions.githubusercontent.com")) {
          oidcTrustPolicies.push(...analyzeStructuredOidcPolicies(iacFile.relPath, content));
        }
        if (
          content.includes("AWS::IAM::") ||
          (content.includes('"Statement"') && content.includes('"Version"'))
        ) {
          const parsed = parseStructuredAwsIamFile(iacFile.relPath, content);
          iamRoles.push(...parsed.roles);
          standalonePolicies.push(...parsed.standalonePolicies);
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  if (terraformFiles.length > 0) {
    const tfArtifacts = parseTerraformIamFiles(terraformFiles);
    iamRoles.push(...tfArtifacts.roles);
    standalonePolicies.push(...tfArtifacts.standalonePolicies);
  }

  const { findings, correlatedChains } = evaluateCloudIdentityRules({
    workflows,
    workflowIdentityRefs,
    iamRoles,
    standalonePolicies,
    oidcTrustPolicies,
    disabledRules: policy.disabledRules
  });

  const policyEvaluation = evaluateCloudIdentityPolicy(findings, policy);

  return {
    scanner: CLOUD_IDENTITY_SCANNER_NAME,
    scannerVersion: CLOUD_IDENTITY_SCANNER_VERSION,
    rulesetVersion: CLOUD_IDENTITY_RULESET_VERSION,
    analyzedAt: new Date().toISOString(),
    workflows,
    workflowIdentityRefs,
    iamRoles,
    standalonePolicies,
    correlatedChains,
    findings,
    limitations,
    policyEvaluation
  };
}

/**
 * ScannerAdapter implementation integrating static AWS IAM Policy & CI/CD-to-Cloud
 * identity correlation into scanner-runner and the canonical Indicative pipeline.
 */
export class CloudIdentityIamAdapter implements ScannerAdapter {
  public readonly name = CLOUD_IDENTITY_SCANNER_NAME;
  public readonly version = CLOUD_IDENTITY_SCANNER_VERSION;
  public readonly capabilities: ScannerCapability[] = ["cloud-identity"];
  private readonly policy: CloudIdentityPolicyConfig;

  constructor(policy: CloudIdentityPolicyConfig = DEFAULT_CLOUD_IDENTITY_POLICY) {
    this.policy = policy;
  }

  async healthCheck(): Promise<ScannerHealth> {
    return {
      scanner: this.name,
      available: true,
      version: this.version,
      rulesetVersion: CLOUD_IDENTITY_RULESET_VERSION,
      message:
        "Built-in deterministic static AWS IAM policy & workflow-to-role correlator ready (offline).",
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
        rulesetVersion: CLOUD_IDENTITY_RULESET_VERSION,
        capabilities: this.capabilities,
        status: "CANCELLED",
        errorClass: "CANCELLED",
        errorMessage: "Cloud identity analyzer cancelled prior to execution.",
        exitCode: null,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: Date.now() - startMs,
        limitations: [],
        findings: []
      };
    }

    try {
      const report = await analyzeWorkspaceCloudIdentity(context.workspacePath, this.policy);
      return {
        scanner: this.name,
        scannerVersion: this.version,
        rulesetVersion: CLOUD_IDENTITY_RULESET_VERSION,
        capabilities: this.capabilities,
        status: "SUCCESS",
        errorClass: "NONE",
        exitCode: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: Date.now() - startMs,
        limitations: report.limitations,
        resourceUsage: {
          filesScanned: report.iamRoles.length + report.standalonePolicies.length
        },
        findings: report.findings
      };
    } catch (err) {
      return {
        scanner: this.name,
        scannerVersion: this.version,
        rulesetVersion: CLOUD_IDENTITY_RULESET_VERSION,
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
