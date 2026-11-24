import type { RawScannerFinding } from "@indicative/contracts";
import { redactSecretsInText } from "@indicative/security";
import {
  CICD_RULESET_VERSION,
  CICD_SCANNER_NAME,
  CICD_SCANNER_VERSION,
  type OidcTrustPolicy,
  type ParsedWorkflow,
  type WorkflowJob,
  type WorkflowPermissionsBlock
} from "../types.js";
import { isActionPinnedToSha } from "../parser/workflowParser.js";
import { getCicdRule } from "./registry.js";

const UNTRUSTED_TRIGGER_EVENTS = new Set([
  "pull_request_target",
  "issue_comment",
  "issues",
  "discussion",
  "discussion_comment",
  "workflow_run"
]);

const SENSITIVE_WRITE_SCOPES = new Set([
  "contents",
  "packages",
  "actions",
  "security-events",
  "deployments",
  "pages"
]);

/**
 * Attacker-controlled GitHub Actions expression paths that cause command/script
 * injection when interpolated directly inside `run:` or `actions/github-script`.
 */
const UNTRUSTED_GITHUB_CONTEXTS: RegExp[] = [
  /^github\.event\.pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.full_name|head\.repo\.default_branch)$/i,
  /^github\.event\.issue\.(?:title|body)$/i,
  /^github\.event\.comment\.body$/i,
  /^github\.event\.review\.body$/i,
  /^github\.event\.review_comment\.body$/i,
  /^github\.event\.discussion\.(?:title|body)$/i,
  /^github\.event\.pages\[\d+\]\.page_name$/i,
  /^github\.event\.commits(?:\[\d+\]|\.\*)\.(?:message|author\.name|author\.email)$/i,
  /^github\.event\.head_commit\.(?:message|author\.name|author\.email)$/i,
  /^github\.event\.workflow_run\.(?:head_branch|head_commit\.message|display_title)$/i,
  /^github\.head_ref$/i
];

const EXPRESSION_BLOCK_REGEX = /\$\{\{([^}]{1,300})\}\}/g;

function extractSnippet(lines: string[], lineStart: number, lineEnd: number): string {
  const s = Math.max(0, lineStart - 1);
  const e = Math.min(lines.length, Math.max(lineEnd, lineStart + 2), s + 12);
  return redactSecretsInText(
    lines
      .slice(s, e)
      .map((l, i) => `${s + i + 1}: ${l}`)
      .join("\n")
  );
}

function hasAnyWritePermission(perms?: WorkflowPermissionsBlock): boolean {
  if (!perms) return false;
  if (perms.mode === "write-all") return true;
  return Object.values(perms.scopes).some((v) => v === "write");
}

function getWriteScopes(perms?: WorkflowPermissionsBlock): string[] {
  if (!perms) return [];
  if (perms.mode === "write-all") return ["write-all"];
  return Object.entries(perms.scopes)
    .filter(([, access]) => access === "write")
    .map(([scope]) => scope);
}

function isUntrustedExpression(exprContent: string): string | null {
  const cleaned = exprContent.trim();
  // Extract individual github.* tokens from compound expressions safely (linear time)
  const tokens = cleaned.match(/github\.[A-Za-z0-9_.*[\]-]{1,120}/g);
  if (!tokens) return null;
  for (const token of tokens) {
    if (UNTRUSTED_GITHUB_CONTEXTS.some((re) => re.test(token))) {
      return token;
    }
  }
  return null;
}

function buildFinding(params: {
  ruleId: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  titleSuffix: string;
  description: string;
  codeSnippet: string;
  severityOverride?: RawScannerFinding["severity"];
  confidenceOverride?: RawScannerFinding["confidence"];
  workflowAnchor: string;
  rawMetadata?: Record<string, string | number | boolean>;
}): RawScannerFinding {
  const rule = getCicdRule(params.ruleId);
  const severity = params.severityOverride ?? rule.defaultSeverity;
  const confidence = params.confidenceOverride ?? rule.defaultConfidence;

  return {
    scanner: CICD_SCANNER_NAME,
    scannerVersion: CICD_SCANNER_VERSION,
    rulesetVersion: CICD_RULESET_VERSION,
    ruleId: rule.ruleId,
    category: "CICD",
    title: redactSecretsInText(`${rule.title} (${params.titleSuffix})`),
    description: redactSecretsInText(
      `${params.description} Impact: ${rule.impact} Limitations: ${rule.limitations}`
    ),
    originalSeverity: severity,
    severity,
    confidence,
    filePath: params.filePath,
    lineStart: params.lineStart,
    lineEnd: params.lineEnd,
    codeSnippet: redactSecretsInText(params.codeSnippet),
    references: rule.references,
    remediationHint: `${rule.remediation}\n\nFalse-positive considerations: ${rule.falsePositiveNotes}`,
    rawMetadata: {
      cwe: rule.cwe,
      owaspCicd: rule.owaspCicd,
      ruleCategory: rule.category,
      ruleVersion: rule.version,
      workflowAnchor: params.workflowAnchor,
      evidenceBasis: "STATIC_CONFIG",
      ...(params.rawMetadata ?? {})
    }
  };
}

function evaluateWorkflow(
  wf: ParsedWorkflow,
  disabledRules: Set<string>
): RawScannerFinding[] {
  const findings: RawScannerFinding[] = [];
  const triggerNames = new Set(wf.triggers.map((t) => t.event));
  const hasUntrustedTrigger = [...triggerNames].some((t) => UNTRUSTED_TRIGGER_EVENTS.has(t));
  const hasPrTarget = triggerNames.has("pull_request_target");
  const hasWorkflowRun = triggerNames.has("workflow_run");
  const workflowHasWrite = hasAnyWritePermission(wf.permissions);
  const allJobsDeclarePermissions =
    wf.jobs.length > 0 && wf.jobs.every((j) => j.permissions !== undefined);

  // --------------------------------------------------------------------------
  // 1. Permissions Rules (GHA-PERM-001 .. GHA-PERM-004)
  // --------------------------------------------------------------------------
  if (!disabledRules.has("GHA-PERM-001") && !wf.permissions && !allJobsDeclarePermissions) {
    findings.push(
      buildFinding({
        ruleId: "GHA-PERM-001",
        filePath: wf.filePath,
        lineStart: 1,
        lineEnd: Math.min(5, wf.rawLines.length),
        titleSuffix: wf.name,
        description: `Workflow "${wf.name}" does not declare a top-level permissions block and one or more jobs omit job-level permissions.`,
        codeSnippet: extractSnippet(wf.rawLines, 1, 5),
        workflowAnchor: `workflow:${wf.name}:missing-permissions`,
        rawMetadata: {
          workflowName: wf.name,
          triggers: [...triggerNames].join(","),
          untrustedTrigger: hasUntrustedTrigger
        }
      })
    );
  }

  if (!disabledRules.has("GHA-PERM-002") && wf.permissions?.mode === "write-all") {
    findings.push(
      buildFinding({
        ruleId: "GHA-PERM-002",
        filePath: wf.filePath,
        lineStart: wf.permissions.lineStart,
        lineEnd: wf.permissions.lineEnd,
        titleSuffix: `${wf.name} (root)`,
        description: `Workflow "${wf.name}" declares top-level "permissions: write-all", granting full GITHUB_TOKEN write access to every job and action.`,
        codeSnippet: extractSnippet(wf.rawLines, wf.permissions.lineStart, wf.permissions.lineEnd),
        workflowAnchor: `workflow:${wf.name}:root-write-all`,
        rawMetadata: {
          workflowName: wf.name,
          untrustedTrigger: hasUntrustedTrigger,
          hasWritePermissions: true
        }
      })
    );
  }

  if (
    !disabledRules.has("GHA-PERM-003") &&
    wf.permissions &&
    wf.permissions.mode === "scoped"
  ) {
    const sensitiveRootWrites = getWriteScopes(wf.permissions).filter((s) =>
      SENSITIVE_WRITE_SCOPES.has(s)
    );
    // Flag when sensitive write scopes are granted at workflow root across multiple jobs
    // OR combined with any untrusted trigger
    if (sensitiveRootWrites.length > 0 && (wf.jobs.length > 1 || hasUntrustedTrigger)) {
      findings.push(
        buildFinding({
          ruleId: "GHA-PERM-003",
          filePath: wf.filePath,
          lineStart: wf.permissions.lineStart,
          lineEnd: wf.permissions.lineEnd,
          titleSuffix: `${wf.name}: ${sensitiveRootWrites.join(", ")}`,
          description: `Workflow "${wf.name}" grants sensitive write permissions (${sensitiveRootWrites.join(", ")}) at workflow root${
            hasUntrustedTrigger ? " alongside an untrusted event trigger" : ` across ${wf.jobs.length} jobs`
          }.`,
          codeSnippet: extractSnippet(wf.rawLines, wf.permissions.lineStart, wf.permissions.lineEnd),
          workflowAnchor: `workflow:${wf.name}:root-excessive-write`,
          rawMetadata: {
            workflowName: wf.name,
            writeScopes: sensitiveRootWrites.join(","),
            untrustedTrigger: hasUntrustedTrigger,
            hasWritePermissions: true
          }
        })
      );
    }
  }

  if (
    !disabledRules.has("GHA-PERM-004") &&
    wf.permissions &&
    wf.permissions.scopes["id-token"] === "write" &&
    (wf.jobs.length > 1 || hasUntrustedTrigger || triggerNames.has("pull_request"))
  ) {
    findings.push(
      buildFinding({
        ruleId: "GHA-PERM-004",
        filePath: wf.filePath,
        lineStart: wf.permissions.lineStart,
        lineEnd: wf.permissions.lineEnd,
        titleSuffix: `${wf.name} (root id-token: write)`,
        description: `Workflow "${wf.name}" grants "id-token: write" at the workflow root${
          hasUntrustedTrigger || triggerNames.has("pull_request")
            ? " on a pull-request/untrusted trigger"
            : ` across ${wf.jobs.length} jobs`
        }, allowing non-deployment steps to mint GitHub OIDC JWTs.`,
        codeSnippet: extractSnippet(wf.rawLines, wf.permissions.lineStart, wf.permissions.lineEnd),
        severityOverride: hasPrTarget ? "CRITICAL" : "HIGH",
        workflowAnchor: `workflow:${wf.name}:root-id-token-write`,
        rawMetadata: {
          workflowName: wf.name,
          untrustedTrigger: hasUntrustedTrigger || triggerNames.has("pull_request"),
          hasWritePermissions: true
        }
      })
    );
  }

  // --------------------------------------------------------------------------
  // 2. Per-Job & Per-Step Rules
  // --------------------------------------------------------------------------
  for (const job of wf.jobs) {
    evaluateJob(wf, job, {
      hasUntrustedTrigger,
      hasPrTarget,
      hasWorkflowRun,
      triggerNames,
      workflowHasWrite,
      disabledRules,
      findings
    });
  }

  return findings;
}

function evaluateJob(
  wf: ParsedWorkflow,
  job: WorkflowJob,
  ctx: {
    hasUntrustedTrigger: boolean;
    hasPrTarget: boolean;
    hasWorkflowRun: boolean;
    triggerNames: Set<string>;
    workflowHasWrite: boolean;
    disabledRules: Set<string>;
    findings: RawScannerFinding[];
  }
): void {
  const effectivePerms = job.permissions ?? wf.permissions;
  const jobHasWrite = hasAnyWritePermission(effectivePerms);
  const jobImplicitPerms = !effectivePerms;

  // Job-level write-all
  if (!ctx.disabledRules.has("GHA-PERM-002") && job.permissions?.mode === "write-all") {
    ctx.findings.push(
      buildFinding({
        ruleId: "GHA-PERM-002",
        filePath: wf.filePath,
        lineStart: job.permissions.lineStart,
        lineEnd: job.permissions.lineEnd,
        titleSuffix: `job "${job.jobId}"`,
        description: `Job "${job.jobId}" in workflow "${wf.name}" declares "permissions: write-all".`,
        codeSnippet: extractSnippet(wf.rawLines, job.permissions.lineStart, job.permissions.lineEnd),
        workflowAnchor: `job:${job.jobId}:write-all`,
        rawMetadata: {
          workflowName: wf.name,
          jobId: job.jobId,
          untrustedTrigger: ctx.hasUntrustedTrigger,
          hasWritePermissions: true
        }
      })
    );
  }

  // Job-level id-token: write on untrusted trigger (e.g., pull_request_target / pull_request without environment)
  if (
    !ctx.disabledRules.has("GHA-PERM-004") &&
    job.permissions?.scopes["id-token"] === "write" &&
    (ctx.hasPrTarget || (ctx.triggerNames.has("pull_request") && !job.environment))
  ) {
    ctx.findings.push(
      buildFinding({
        ruleId: "GHA-PERM-004",
        filePath: wf.filePath,
        lineStart: job.permissions.lineStart,
        lineEnd: job.permissions.lineEnd,
        titleSuffix: `job "${job.jobId}" on PR trigger`,
        description: `Job "${job.jobId}" requests "id-token: write" on a pull-request trigger${
          job.environment ? "" : " without GitHub environment protection"
        }.`,
        codeSnippet: extractSnippet(wf.rawLines, job.permissions.lineStart, job.permissions.lineEnd),
        severityOverride: ctx.hasPrTarget ? "CRITICAL" : "HIGH",
        workflowAnchor: `job:${job.jobId}:pr-id-token-write`,
        rawMetadata: {
          workflowName: wf.name,
          jobId: job.jobId,
          untrustedTrigger: true,
          hasWritePermissions: true
        }
      })
    );
  }

  // Unpinned remote reusable workflow (GHA-ACT-002)
  if (
    !ctx.disabledRules.has("GHA-ACT-002") &&
    job.usesReusableWorkflow &&
    !job.usesReusableWorkflow.startsWith("./") &&
    !isActionPinnedToSha(job.usesReusableWorkflow)
  ) {
    ctx.findings.push(
      buildFinding({
        ruleId: "GHA-ACT-002",
        filePath: wf.filePath,
        lineStart: job.lineStart,
        lineEnd: Math.min(job.lineEnd, job.lineStart + 4),
        titleSuffix: `${job.jobId} -> ${job.usesReusableWorkflow}`,
        description: `Job "${job.jobId}" calls remote reusable workflow "${job.usesReusableWorkflow}" via a mutable tag or branch instead of a 40-character commit SHA.`,
        codeSnippet: extractSnippet(wf.rawLines, job.lineStart, job.lineStart + 4),
        workflowAnchor: `job:${job.jobId}:unpinned-reusable:${job.usesReusableWorkflow}`,
        rawMetadata: {
          workflowName: wf.name,
          jobId: job.jobId,
          reusableWorkflow: job.usesReusableWorkflow,
          hasWritePermissions: jobHasWrite
        }
      })
    );
  }

  // Broad secrets: inherit passed to external reusable workflow (GHA-SEC-001)
  if (
    !ctx.disabledRules.has("GHA-SEC-001") &&
    job.secretsInherit &&
    job.usesReusableWorkflow &&
    !job.usesReusableWorkflow.startsWith("./")
  ) {
    ctx.findings.push(
      buildFinding({
        ruleId: "GHA-SEC-001",
        filePath: wf.filePath,
        lineStart: job.lineStart,
        lineEnd: Math.min(job.lineEnd, job.lineStart + 6),
        titleSuffix: `secrets: inherit -> ${job.usesReusableWorkflow}`,
        description: `Job "${job.jobId}" passes all repository/organization secrets via "secrets: inherit" to external reusable workflow "${job.usesReusableWorkflow}".`,
        codeSnippet: extractSnippet(wf.rawLines, job.lineStart, job.lineStart + 6),
        workflowAnchor: `job:${job.jobId}:secrets-inherit-external`,
        rawMetadata: {
          workflowName: wf.name,
          jobId: job.jobId,
          reusableWorkflow: job.usesReusableWorkflow
        }
      })
    );
  }

  let checkedOutUntrustedPr = false;
  let downloadedArtifactInWorkflowRun = false;

  for (const step of job.steps) {
    const stepLabel = step.name || step.id || `step-${step.index + 1}`;
    const usesLower = (step.uses ?? "").toLowerCase();

    // ----------------------------------------------------------------------
    // Trigger Rule: pull_request_target + untrusted PR checkout (GHA-TRIG-001)
    // ----------------------------------------------------------------------
    if (ctx.hasPrTarget && !ctx.disabledRules.has("GHA-TRIG-001")) {
      const checkoutRef = step.withInputs.ref ?? "";
      const isCheckoutPrHead =
        usesLower.startsWith("actions/checkout") &&
        /(?:pull_request\.head|github\.head_ref|refs\/pull\/)/i.test(checkoutRef);
      const isShellPrCheckout =
        Boolean(step.run) &&
        /\b(?:gh\s+pr\s+checkout|git\s+(?:checkout|fetch)\b[^\n]{0,120}(?:pull_request\.head|head_ref|pull\/))/i.test(
          step.run ?? ""
        );

      if (isCheckoutPrHead || isShellPrCheckout) {
        checkedOutUntrustedPr = true;
        ctx.findings.push(
          buildFinding({
            ruleId: "GHA-TRIG-001",
            filePath: wf.filePath,
            lineStart: step.lineStart,
            lineEnd: step.lineEnd,
            titleSuffix: `job "${job.jobId}" / ${stepLabel}`,
            description: `Workflow "${wf.name}" triggers on "pull_request_target" and checks out untrusted pull-request head code in job "${job.jobId}". Any external PR can execute arbitrary code with base-repository secrets and write permissions.`,
            codeSnippet: extractSnippet(wf.rawLines, step.lineStart, step.lineEnd),
            workflowAnchor: `job:${job.jobId}:pwn-request-checkout`,
            rawMetadata: {
              workflowName: wf.name,
              jobId: job.jobId,
              stepName: stepLabel,
              untrustedTrigger: true,
              hasWritePermissions: jobHasWrite || jobImplicitPerms
            }
          })
        );
      }
    }

    // ----------------------------------------------------------------------
    // Trigger Rule: workflow_run consuming upstream artifacts (GHA-TRIG-002)
    // ----------------------------------------------------------------------
    if (ctx.hasWorkflowRun && !ctx.disabledRules.has("GHA-TRIG-002")) {
      const isArtifactDownload =
        usesLower.startsWith("actions/download-artifact") ||
        usesLower.startsWith("dawidd6/action-download-artifact") ||
        /\bgh\s+run\s+download\b/i.test(step.run ?? "");
      if (isArtifactDownload) {
        downloadedArtifactInWorkflowRun = true;
        ctx.findings.push(
          buildFinding({
            ruleId: "GHA-TRIG-002",
            filePath: wf.filePath,
            lineStart: step.lineStart,
            lineEnd: step.lineEnd,
            titleSuffix: `job "${job.jobId}" downloads upstream artifact`,
            description: `Privileged "workflow_run" job "${job.jobId}" downloads artifacts from an upstream workflow run. If the upstream workflow runs on external PRs, tampered artifacts can lead to script or build compromise.`,
            codeSnippet: extractSnippet(wf.rawLines, step.lineStart, step.lineEnd),
            workflowAnchor: `job:${job.jobId}:workflow-run-artifact`,
            rawMetadata: {
              workflowName: wf.name,
              jobId: job.jobId,
              stepName: stepLabel,
              untrustedTrigger: true,
              hasWritePermissions: jobHasWrite || jobImplicitPerms
            }
          })
        );
      }
    }

    // ----------------------------------------------------------------------
    // Supply Chain: Unpinned third-party action (GHA-ACT-001)
    // ----------------------------------------------------------------------
    if (
      !ctx.disabledRules.has("GHA-ACT-001") &&
      step.uses &&
      !step.uses.startsWith("./") &&
      !isActionPinnedToSha(step.uses)
    ) {
      const line = step.usesLine ?? step.lineStart;
      ctx.findings.push(
        buildFinding({
          ruleId: "GHA-ACT-001",
          filePath: wf.filePath,
          lineStart: line,
          lineEnd: line,
          titleSuffix: step.uses,
          description: `Step "${stepLabel}" in job "${job.jobId}" references external action "${step.uses}" by a mutable tag or branch instead of a 40-character commit SHA.`,
          codeSnippet: extractSnippet(wf.rawLines, line, line + 1),
          severityOverride: jobHasWrite || ctx.hasUntrustedTrigger ? "HIGH" : "MEDIUM",
          workflowAnchor: `job:${job.jobId}:unpinned-action:${step.uses}`,
          rawMetadata: {
            workflowName: wf.name,
            jobId: job.jobId,
            actionRef: step.uses,
            hasWritePermissions: jobHasWrite
          }
        })
      );
    }

    // ----------------------------------------------------------------------
    // Supply Chain: actions/checkout persist-credentials (GHA-ACT-003)
    // ----------------------------------------------------------------------
    if (
      !ctx.disabledRules.has("GHA-ACT-003") &&
      usesLower.startsWith("actions/checkout") &&
      step.withInputs["persist-credentials"]?.toLowerCase() !== "false" &&
      (jobHasWrite || jobImplicitPerms || ctx.hasUntrustedTrigger)
    ) {
      ctx.findings.push(
        buildFinding({
          ruleId: "GHA-ACT-003",
          filePath: wf.filePath,
          lineStart: step.lineStart,
          lineEnd: step.lineEnd,
          titleSuffix: `job "${job.jobId}"`,
          description: `"actions/checkout" in job "${job.jobId}" does not set "persist-credentials: false", leaving GITHUB_TOKEN persisted in .git/config during a job with write, implicit, or untrusted-trigger scope.`,
          codeSnippet: extractSnippet(wf.rawLines, step.lineStart, step.lineEnd),
          workflowAnchor: `job:${job.jobId}:checkout-persist-creds:${step.index}`,
          rawMetadata: {
            workflowName: wf.name,
            jobId: job.jobId,
            hasWritePermissions: jobHasWrite
          }
        })
      );
    }

    // ----------------------------------------------------------------------
    // Expression Injection in run: or actions/github-script (GHA-INJ-001)
    // ----------------------------------------------------------------------
    if (!ctx.disabledRules.has("GHA-INJ-001")) {
      const scriptTargets: Array<{ label: string; code: string; line: number }> = [];
      if (step.run) {
        scriptTargets.push({
          label: "run shell script",
          code: step.run,
          line: step.runLine ?? step.lineStart
        });
      }
      if (usesLower.startsWith("actions/github-script") && step.withInputs.script) {
        scriptTargets.push({
          label: "actions/github-script",
          code: step.withInputs.script,
          line: step.lineStart
        });
      }

      for (const target of scriptTargets) {
        // Bound scanned length per step for linear-time guarantee
        const boundedCode = target.code.slice(0, 32_768);
        EXPRESSION_BLOCK_REGEX.lastIndex = 0;
        const foundUntrusted = new Set<string>();
        let m: RegExpExecArray | null;
        while ((m = EXPRESSION_BLOCK_REGEX.exec(boundedCode)) !== null) {
          const badCtx = isUntrustedExpression(m[1] ?? "");
          if (badCtx) foundUntrusted.add(badCtx);
        }

        if (foundUntrusted.size > 0) {
          const contextsList = [...foundUntrusted].join(", ");
          ctx.findings.push(
            buildFinding({
              ruleId: "GHA-INJ-001",
              filePath: wf.filePath,
              lineStart: target.line,
              lineEnd: step.lineEnd,
              titleSuffix: `${contextsList} in job "${job.jobId}"`,
              description: `Untrusted GitHub expression (${contextsList}) is interpolated directly into ${target.label} in job "${job.jobId}" ("${stepLabel}"), allowing shell/script command injection before execution.`,
              codeSnippet: extractSnippet(wf.rawLines, target.line, step.lineEnd),
              severityOverride:
                ctx.hasUntrustedTrigger || jobHasWrite ? "CRITICAL" : "HIGH",
              workflowAnchor: `job:${job.jobId}:expr-injection:${contextsList}`,
              rawMetadata: {
                workflowName: wf.name,
                jobId: job.jobId,
                stepName: stepLabel,
                untrustedContexts: contextsList,
                untrustedTrigger: ctx.hasUntrustedTrigger,
                hasWritePermissions: jobHasWrite
              }
            })
          );
        }
      }
    }

    // ----------------------------------------------------------------------
    // Secrets Exposure: Printing/echoing secrets in shell (GHA-SEC-001)
    // ----------------------------------------------------------------------
    if (!ctx.disabledRules.has("GHA-SEC-001") && step.run) {
      const boundedRun = step.run.slice(0, 32_768);
      const echoesSecret =
        /\b(?:echo|printf|printenv|env)\b[^\n]{0,200}\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/i.test(
          boundedRun
        ) ||
        /\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}/i.test(boundedRun);

      if (echoesSecret) {
        const line = step.runLine ?? step.lineStart;
        ctx.findings.push(
          buildFinding({
            ruleId: "GHA-SEC-001",
            filePath: wf.filePath,
            lineStart: line,
            lineEnd: step.lineEnd,
            titleSuffix: `secret interpolated in shell output (${job.jobId})`,
            description: `Step "${stepLabel}" in job "${job.jobId}" directly interpolates GitHub secrets (or toJSON(secrets)) into shell output/commands.`,
            codeSnippet: extractSnippet(wf.rawLines, line, step.lineEnd),
            workflowAnchor: `job:${job.jobId}:secret-shell-echo:${stepLabel}`,
            rawMetadata: {
              workflowName: wf.name,
              jobId: job.jobId,
              stepName: stepLabel
            }
          })
        );
      }
    }

    // ----------------------------------------------------------------------
    // Secrets: Static long-lived cloud credentials (GHA-SEC-002)
    // ----------------------------------------------------------------------
    if (!ctx.disabledRules.has("GHA-SEC-002")) {
      const usesStaticAws =
        usesLower.startsWith("aws-actions/configure-aws-credentials") &&
        (Boolean(step.withInputs["aws-access-key-id"]) ||
          Boolean(step.withInputs["aws-secret-access-key"]));
      const usesStaticAzure =
        usesLower.startsWith("azure/login") && Boolean(step.withInputs.creds);
      const usesStaticGcp =
        usesLower.startsWith("google-github-actions/auth") &&
        Boolean(step.withInputs.credentials_json);

      const envJoined = Object.entries({ ...wf.env, ...job.env, ...step.env })
        .map(([k, v]) => `${k}=${v}`)
        .join("\n");
      const staticEnvCreds =
        /\b(?:AWS_SECRET_ACCESS_KEY|GCP_SA_KEY|GOOGLE_CREDENTIALS|AZURE_CREDENTIALS)\s*=\s*\$\{\{\s*secrets\./i.test(
          envJoined
        );

      if (usesStaticAws || usesStaticAzure || usesStaticGcp || staticEnvCreds) {
        const provider = usesStaticAws
          ? "AWS"
          : usesStaticAzure
            ? "Azure"
            : usesStaticGcp
              ? "GCP"
              : "Cloud";
        ctx.findings.push(
          buildFinding({
            ruleId: "GHA-SEC-002",
            filePath: wf.filePath,
            lineStart: step.lineStart,
            lineEnd: step.lineEnd,
            titleSuffix: `${provider} static credentials in job "${job.jobId}"`,
            description: `Step "${stepLabel}" in job "${job.jobId}" uses static long-lived ${provider} credentials from secrets instead of short-lived OIDC workload identity federation.`,
            codeSnippet: extractSnippet(wf.rawLines, step.lineStart, step.lineEnd),
            workflowAnchor: `job:${job.jobId}:static-cloud-creds:${provider.toLowerCase()}`,
            rawMetadata: {
              workflowName: wf.name,
              jobId: job.jobId,
              cloudProvider: provider
            }
          })
        );
      }
    }

    // ----------------------------------------------------------------------
    // Build Integrity: curl/wget piped directly to shell (GHA-INT-001)
    // ----------------------------------------------------------------------
    if (!ctx.disabledRules.has("GHA-INT-001") && step.run) {
      const boundedRun = step.run.slice(0, 32_768);
      if (/\b(?:curl|wget)\b[^\n|]{1,220}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?)\b/i.test(boundedRun)) {
        const line = step.runLine ?? step.lineStart;
        ctx.findings.push(
          buildFinding({
            ruleId: "GHA-INT-001",
            filePath: wf.filePath,
            lineStart: line,
            lineEnd: step.lineEnd,
            titleSuffix: `job "${job.jobId}" / ${stepLabel}`,
            description: `Step "${stepLabel}" in job "${job.jobId}" downloads a remote script and pipes it directly into a shell interpreter without checksum or signature verification.`,
            codeSnippet: extractSnippet(wf.rawLines, line, step.lineEnd),
            workflowAnchor: `job:${job.jobId}:pipe-to-shell:${stepLabel}`,
            rawMetadata: {
              workflowName: wf.name,
              jobId: job.jobId,
              stepName: stepLabel
            }
          })
        );
      }
    }

    // ----------------------------------------------------------------------
    // Build Integrity: Unpinned dependency install without lockfile (GHA-INT-002)
    // ----------------------------------------------------------------------
    if (!ctx.disabledRules.has("GHA-INT-002") && step.run) {
      const boundedRun = step.run.slice(0, 32_768);
      const hasFloatingNpmInstall =
        /(?:^|[;&\n])\s*npm\s+(?:i|install)\b(?![^\n]*--frozen-lockfile)(?![^\n]*-g\b)(?![^\n]*--global\b)/i.test(
          boundedRun
        );
      if (hasFloatingNpmInstall) {
        const line = step.runLine ?? step.lineStart;
        ctx.findings.push(
          buildFinding({
            ruleId: "GHA-INT-002",
            filePath: wf.filePath,
            lineStart: line,
            lineEnd: step.lineEnd,
            titleSuffix: `npm install without lockfile enforcement (${job.jobId})`,
            description: `Step "${stepLabel}" in job "${job.jobId}" runs "npm install" instead of "npm ci", allowing mutable lockfile resolution during CI execution.`,
            codeSnippet: extractSnippet(wf.rawLines, line, step.lineEnd),
            workflowAnchor: `job:${job.jobId}:mutable-npm-install:${stepLabel}`,
            rawMetadata: {
              workflowName: wf.name,
              jobId: job.jobId,
              stepName: stepLabel
            }
          })
        );
      }
    }
  }

  // Avoid unused local flags lint warnings while preserving clarity
  void checkedOutUntrustedPr;
  void downloadedArtifactInWorkflowRun;
}

function evaluateOidcTrustPolicies(
  workflows: ParsedWorkflow[],
  policies: OidcTrustPolicy[],
  disabledRules: Set<string>
): RawScannerFinding[] {
  const findings: RawScannerFinding[] = [];
  const oidcWorkflows = workflows.filter((w) => w.usesOidc);

  for (const policy of policies) {
    const isPermissiveSub = policy.hasMissingSubject || policy.hasWildcardSubject;

    if (!disabledRules.has("GHA-OIDC-001") && isPermissiveSub) {
      const reason = policy.hasMissingSubject
        ? "omits a GitHub OIDC subject (sub) claim restriction altogether"
        : `allows overly broad wildcard OIDC subject(s): ${policy.subjects.join(", ")}`;
      findings.push(
        buildFinding({
          ruleId: "GHA-OIDC-001",
          filePath: policy.filePath,
          lineStart: policy.lineStart,
          lineEnd: policy.lineEnd,
          titleSuffix: `${policy.provider.toUpperCase()} ${policy.resourceName}`,
          description: `Static ${policy.provider.toUpperCase()} OIDC trust policy "${policy.resourceName}" (${policy.format}) ${reason}.`,
          codeSnippet: policy.snippet,
          workflowAnchor: `oidc:${policy.provider}:${policy.resourceName}:broad-sub`,
          rawMetadata: {
            evidenceType: "OIDC_TRUST_POLICY",
            cloudProvider: policy.provider,
            resourceName: policy.resourceName,
            subjects: policy.subjects.join(",") || "NONE",
            hasWildcardSubject: policy.hasWildcardSubject,
            hasMissingSubject: policy.hasMissingSubject
          }
        })
      );
    }

    if (!disabledRules.has("GHA-OIDC-002") && policy.hasMissingOrWildcardAudience) {
      findings.push(
        buildFinding({
          ruleId: "GHA-OIDC-002",
          filePath: policy.filePath,
          lineStart: policy.lineStart,
          lineEnd: policy.lineEnd,
          titleSuffix: `${policy.provider.toUpperCase()} ${policy.resourceName}`,
          description: `Static ${policy.provider.toUpperCase()} OIDC trust policy "${policy.resourceName}" is missing strict OIDC audience (aud) validation or uses a wildcard audience.`,
          codeSnippet: policy.snippet,
          workflowAnchor: `oidc:${policy.provider}:${policy.resourceName}:missing-aud`,
          rawMetadata: {
            evidenceType: "OIDC_TRUST_POLICY",
            cloudProvider: policy.provider,
            resourceName: policy.resourceName,
            audiences: policy.audiences.join(",") || "NONE"
          }
        })
      );
    }

    // Cross-file static correlation: repository has BOTH an OIDC-requesting workflow AND a permissive trust policy
    if (
      !disabledRules.has("GHA-OIDC-003") &&
      (isPermissiveSub || policy.hasMissingOrWildcardAudience) &&
      oidcWorkflows.length > 0
    ) {
      const matchingWorkflows = oidcWorkflows.filter(
        (w) =>
          w.oidcCloudTargets.includes(policy.provider) ||
          w.oidcCloudTargets.includes("generic")
      );
      if (matchingWorkflows.length > 0) {
        const wfList = matchingWorkflows.map((w) => w.filePath).join(", ");
        findings.push(
          buildFinding({
            ruleId: "GHA-OIDC-003",
            filePath: policy.filePath,
            lineStart: policy.lineStart,
            lineEnd: policy.lineEnd,
            titleSuffix: `${matchingWorkflows[0]!.filePath} <-> ${policy.resourceName}`,
            description:
              `Static cross-file correlation identified GitHub Actions workflow(s) (${wfList}) requesting OIDC tokens alongside permissive ${policy.provider.toUpperCase()} trust policy "${policy.resourceName}" in "${policy.filePath}" (subjects: ${policy.subjects.join(", ") || "UNRESTRICTED"}; audiences: ${policy.audiences.join(", ") || "UNRESTRICTED"}). ` +
              `Note: this reflects verified static repository configuration only; live cloud role permissions and GitHub environment gates cannot be verified without live cloud assessment.`,
            codeSnippet: policy.snippet,
            workflowAnchor: `oidc-correlation:${policy.provider}:${policy.resourceName}`,
            rawMetadata: {
              evidenceType: "OIDC_TRUST_POLICY",
              cloudProvider: policy.provider,
              resourceName: policy.resourceName,
              correlatedWorkflows: wfList,
              correlatedOidcTrust: true,
              hasWritePermissions: true
            }
          })
        );
      }
    }
  }

  return findings;
}

export function evaluateCicdSecurityRules(params: {
  workflows: ParsedWorkflow[];
  oidcTrustPolicies: OidcTrustPolicy[];
  disabledRules?: string[];
}): RawScannerFinding[] {
  const disabled = new Set(params.disabledRules ?? []);
  const findings: RawScannerFinding[] = [];

  for (const wf of params.workflows) {
    findings.push(...evaluateWorkflow(wf, disabled));
  }

  findings.push(
    ...evaluateOidcTrustPolicies(params.workflows, params.oidcTrustPolicies, disabled)
  );

  return findings;
}
