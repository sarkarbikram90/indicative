import crypto from "node:crypto";
import { parse as parseYaml } from "yaml";
import { redactSecretsInText } from "@indicative/security";
import type { OidcTrustPolicy } from "../types.js";

const GITHUB_OIDC_ISSUER = "token.actions.githubusercontent.com";

export function isSubjectOverlyBroad(subject: string): boolean {
  const s = subject.trim();
  if (!s || s === "*" || s === "repo:*") return true;
  // Wildcard across entire org: repo:my-org/* or repo:my-org/*:*
  if (/^repo:[^:/]+\/\*(?::\*)?$/i.test(s)) return true;
  // Wildcard across all branches/tags/PRs of a repo: repo:org/repo:*
  if (/^repo:[^:/]+\/[^:/]+:\*$/i.test(s)) return true;
  // Wildcard on refs without restriction: repo:org/repo:ref:refs/heads/*
  if (/^repo:[^:/]+\/[^:/]+:ref:refs\/heads\/\*$/i.test(s)) return true;
  // Catch any trailing wildcard right after org or repo colon
  if (s.endsWith(":*") || s.endsWith("/*")) return true;
  return false;
}

export function hasBranchOrEnvConstraint(subject: string): boolean {
  const s = subject.trim();
  if (isSubjectOverlyBroad(s)) return false;
  return (
    /:environment:[A-Za-z0-9_.-]+$/i.test(s) ||
    /:ref:refs\/heads\/[A-Za-z0-9_./-]+$/i.test(s) ||
    /:ref:refs\/tags\/[A-Za-z0-9_./-]+$/i.test(s)
  );
}

function lineNumberAtOffset(content: string, offset: number): number {
  let line = 1;
  const max = Math.min(offset, content.length);
  for (let i = 0; i < max; i++) {
    if (content.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function extractSnippetAroundLines(
  lines: string[],
  lineStart: number,
  lineEnd: number
): string {
  const startIdx = Math.max(0, lineStart - 1);
  const endIdx = Math.min(lines.length, Math.max(lineEnd, lineStart + 10));
  return redactSecretsInText(
    lines
      .slice(startIdx, endIdx)
      .map((l, idx) => `${startIdx + idx + 1}: ${l}`)
      .join("\n")
  );
}

function extractQuotedStrings(raw: string): string[] {
  const out: string[] = [];
  const re = /"([^"\r\n]{1,300})"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    if (m[1]) out.push(m[1]);
  }
  return out;
}

/**
 * Extracts static AWS IAM, Azure FIC, and GCP WIF OIDC trust policies from Terraform (.tf) files.
 */
export function analyzeTerraformOidcPolicies(
  filePath: string,
  content: string
): OidcTrustPolicy[] {
  if (!content.includes(GITHUB_OIDC_ISSUER)) return [];

  const policies: OidcTrustPolicy[] = [];
  const lines = content.split(/\r?\n/);

  // 1. AWS IAM assume role policy or aws_iam_policy_document referencing GitHub OIDC
  const awsBlockRegex =
    /(?:resource\s+"aws_iam_role"\s+"([^"]+)"|data\s+"aws_iam_policy_document"\s+"([^"]+)")/g;
  let match: RegExpExecArray | null;
  while ((match = awsBlockRegex.exec(content)) !== null) {
    const resourceName = match[1] || match[2] || "aws_iam_oidc_role";
    const blockStart = match.index;
    // Bound window to next top-level resource/data/module/output block or +6000 chars
    const nextBlock = content.slice(blockStart + 20).search(/\n(?:resource|data|module|output|variable|locals)\s+"/);
    const blockEnd =
      nextBlock >= 0
        ? Math.min(content.length, blockStart + 20 + nextBlock)
        : Math.min(content.length, blockStart + 6000);
    const block = content.slice(blockStart, blockEnd);

    if (
      !block.includes(GITHUB_OIDC_ISSUER) &&
      !block.includes("AssumeRoleWithWebIdentity") &&
      !block.includes("token.actions.githubusercontent.com")
    ) {
      continue;
    }

    const lineStart = lineNumberAtOffset(content, blockStart);
    const lineEnd = lineNumberAtOffset(content, blockEnd);

    const subjects: string[] = [];
    const audiences: string[] = [];

    // Pattern A: JSON inside jsonencode(...) or heredoc inside Terraform
    const subJsonRegex = /"token\.actions\.githubusercontent\.com:sub"\s*(?:=|:)\s*(\[[^\]]{1,600}\]|"[^"\r\n]{1,300}")/g;
    let sm: RegExpExecArray | null;
    while ((sm = subJsonRegex.exec(block)) !== null) {
      if (sm[1]) subjects.push(...extractQuotedStrings(sm[1]));
    }

    // Pattern B: HCL condition { variable = "token.actions.githubusercontent.com:sub" values = [...] }
    const hclCondRegex = /condition\s*\{[^}]{0,800}\}/g;
    let cm: RegExpExecArray | null;
    while ((cm = hclCondRegex.exec(block)) !== null) {
      const condBlock = cm[0];
      const valuesMatch = condBlock.match(/values\s*=\s*\[([^\]]{1,600})\]/);
      const vals = valuesMatch?.[1] ? extractQuotedStrings(valuesMatch[1]) : [];
      if (condBlock.includes("token.actions.githubusercontent.com:sub")) {
        subjects.push(...vals);
      } else if (condBlock.includes("token.actions.githubusercontent.com:aud")) {
        audiences.push(...vals);
      }
    }

    const audJsonRegex = /"token\.actions\.githubusercontent\.com:aud"\s*(?:=|:)\s*(\[[^\]]{1,300}\]|"[^"\r\n]{1,200}")/g;
    let am: RegExpExecArray | null;
    while ((am = audJsonRegex.exec(block)) !== null) {
      if (am[1]) audiences.push(...extractQuotedStrings(am[1]));
    }

    // Only emit if this block actually defines a web identity trust policy
    if (
      block.includes("AssumeRoleWithWebIdentity") ||
      block.includes("token.actions.githubusercontent.com:sub") ||
      block.includes("token.actions.githubusercontent.com:aud")
    ) {
      const uniqueSubs = [...new Set(subjects)];
      const uniqueAuds = [...new Set(audiences)];
      const hasMissingSubject = uniqueSubs.length === 0;
      const hasWildcardSubject = uniqueSubs.some(isSubjectOverlyBroad);
      const hasMissingOrWildcardAudience =
        uniqueAuds.length === 0 ||
        uniqueAuds.some((a) => a.includes("*") || a.trim().length === 0);
      const hasBranchOrEnvRestriction =
        uniqueSubs.length > 0 && uniqueSubs.every(hasBranchOrEnvConstraint);

      policies.push({
        id: `oidc:aws:${crypto.createHash("sha256").update(`${filePath}:${resourceName}:${lineStart}`).digest("hex").slice(0, 12)}`,
        provider: "aws",
        format: "terraform",
        filePath,
        resourceName,
        lineStart,
        lineEnd,
        subjects: uniqueSubs,
        audiences: uniqueAuds,
        hasWildcardSubject,
        hasMissingSubject,
        hasMissingOrWildcardAudience,
        hasBranchOrEnvRestriction,
        snippet: extractSnippetAroundLines(lines, lineStart, Math.min(lineEnd, lineStart + 20))
      });
    }
  }

  // 2. Azure Federated Identity Credential in Terraform
  const azureRegex =
    /resource\s+"(?:azuread_application_federated_identity_credential|azurerm_federated_identity_credential)"\s+"([^"]+)"/g;
  while ((match = azureRegex.exec(content)) !== null) {
    const resourceName = match[1] || "azure_federated_identity";
    const blockStart = match.index;
    const nextBlock = content.slice(blockStart + 20).search(/\n(?:resource|data|module|output)\s+"/);
    const blockEnd =
      nextBlock >= 0
        ? Math.min(content.length, blockStart + 20 + nextBlock)
        : Math.min(content.length, blockStart + 3000);
    const block = content.slice(blockStart, blockEnd);
    if (!block.includes(GITHUB_OIDC_ISSUER)) continue;

    const lineStart = lineNumberAtOffset(content, blockStart);
    const lineEnd = lineNumberAtOffset(content, blockEnd);
    const subMatch = block.match(/subject\s*=\s*"([^"\r\n]{1,300})"/);
    const audMatch = block.match(/audiences?\s*=\s*(?:\[([^\]]{1,300})\]|"([^"\r\n]{1,200})")/);
    const subjects = subMatch?.[1] ? [subMatch[1]] : [];
    const audiences = audMatch?.[1]
      ? extractQuotedStrings(audMatch[1])
      : audMatch?.[2]
        ? [audMatch[2]]
        : [];

    policies.push({
      id: `oidc:azure:${crypto.createHash("sha256").update(`${filePath}:${resourceName}:${lineStart}`).digest("hex").slice(0, 12)}`,
      provider: "azure",
      format: "terraform",
      filePath,
      resourceName,
      lineStart,
      lineEnd,
      subjects,
      audiences,
      hasWildcardSubject: subjects.some(isSubjectOverlyBroad),
      hasMissingSubject: subjects.length === 0,
      hasMissingOrWildcardAudience:
        audiences.length === 0 || audiences.some((a) => a.includes("*")),
      hasBranchOrEnvRestriction:
        subjects.length > 0 && subjects.every(hasBranchOrEnvConstraint),
      snippet: extractSnippetAroundLines(lines, lineStart, Math.min(lineEnd, lineStart + 18))
    });
  }

  // 3. GCP Workload Identity Pool Provider in Terraform
  const gcpRegex = /resource\s+"google_iam_workload_identity_pool_provider"\s+"([^"]+)"/g;
  while ((match = gcpRegex.exec(content)) !== null) {
    const resourceName = match[1] || "gcp_wif_provider";
    const blockStart = match.index;
    const nextBlock = content.slice(blockStart + 20).search(/\n(?:resource|data|module|output)\s+"/);
    const blockEnd =
      nextBlock >= 0
        ? Math.min(content.length, blockStart + 20 + nextBlock)
        : Math.min(content.length, blockStart + 4000);
    const block = content.slice(blockStart, blockEnd);
    if (!block.includes(GITHUB_OIDC_ISSUER)) continue;

    const lineStart = lineNumberAtOffset(content, blockStart);
    const lineEnd = lineNumberAtOffset(content, blockEnd);
    const attrCondMatch = block.match(/attribute_condition\s*=\s*"([^"\r\n]{1,400})"/);
    const attrCond = attrCondMatch?.[1]?.trim();
    const subjects = attrCond ? [attrCond] : [];
    const hasMissingSubject = !attrCond;
    const hasWildcardSubject =
      Boolean(attrCond) &&
      !attrCond!.includes("repository") &&
      !attrCond!.includes("sub");
    const hasBranchOrEnvRestriction =
      Boolean(attrCond) &&
      (attrCond!.includes("ref") || attrCond!.includes("environment") || attrCond!.includes("sub"));

    policies.push({
      id: `oidc:gcp:${crypto.createHash("sha256").update(`${filePath}:${resourceName}:${lineStart}`).digest("hex").slice(0, 12)}`,
      provider: "gcp",
      format: "terraform",
      filePath,
      resourceName,
      lineStart,
      lineEnd,
      subjects,
      audiences: ["gcp-wif-default"],
      hasWildcardSubject,
      hasMissingSubject,
      hasMissingOrWildcardAudience: false,
      hasBranchOrEnvRestriction,
      snippet: extractSnippetAroundLines(lines, lineStart, Math.min(lineEnd, lineStart + 20))
    });
  }

  return policies;
}

function toStringArray(val: unknown): string[] {
  if (typeof val === "string") return [val];
  if (Array.isArray(val)) return val.filter((v): v is string => typeof v === "string");
  return [];
}

function inspectAwsPolicyDocumentObject(
  doc: unknown,
  meta: {
    filePath: string;
    format: OidcTrustPolicy["format"];
    resourceName: string;
    content: string;
  }
): OidcTrustPolicy | null {
  if (!doc || typeof doc !== "object") return null;
  const statements = (doc as { Statement?: unknown }).Statement;
  const stmtList = Array.isArray(statements) ? statements : statements ? [statements] : [];
  const lines = meta.content.split(/\r?\n/);

  for (const stmt of stmtList) {
    if (!stmt || typeof stmt !== "object") continue;
    const s = stmt as {
      Effect?: string;
      Action?: string | string[];
      Principal?: Record<string, unknown>;
      Condition?: Record<string, Record<string, unknown>>;
    };
    const actions = toStringArray(s.Action);
    const federated = s.Principal ? JSON.stringify(s.Principal) : "";
    const isGitHubOidc =
      federated.includes(GITHUB_OIDC_ISSUER) ||
      (actions.some((a) => a.toLowerCase().includes("assumerolewithwebidentity")) &&
        JSON.stringify(s.Condition ?? {}).includes(GITHUB_OIDC_ISSUER));

    if (!isGitHubOidc) continue;
    if (s.Effect && s.Effect.toLowerCase() !== "allow") continue;

    const subjects: string[] = [];
    const audiences: string[] = [];
    if (s.Condition && typeof s.Condition === "object") {
      for (const condMap of Object.values(s.Condition)) {
        if (!condMap || typeof condMap !== "object") continue;
        for (const [k, v] of Object.entries(condMap)) {
          if (k === "token.actions.githubusercontent.com:sub") {
            subjects.push(...toStringArray(v));
          } else if (k === "token.actions.githubusercontent.com:aud") {
            audiences.push(...toStringArray(v));
          }
        }
      }
    }

    const offset = meta.content.indexOf(GITHUB_OIDC_ISSUER);
    const lineStart = offset >= 0 ? lineNumberAtOffset(meta.content, offset) : 1;
    const lineEnd = Math.min(lines.length, lineStart + 18);

    const uniqueSubs = [...new Set(subjects)];
    const uniqueAuds = [...new Set(audiences)];

    return {
      id: `oidc:aws:${crypto.createHash("sha256").update(`${meta.filePath}:${meta.resourceName}:${lineStart}`).digest("hex").slice(0, 12)}`,
      provider: "aws",
      format: meta.format,
      filePath: meta.filePath,
      resourceName: meta.resourceName,
      lineStart,
      lineEnd,
      subjects: uniqueSubs,
      audiences: uniqueAuds,
      hasWildcardSubject: uniqueSubs.some(isSubjectOverlyBroad),
      hasMissingSubject: uniqueSubs.length === 0,
      hasMissingOrWildcardAudience:
        uniqueAuds.length === 0 || uniqueAuds.some((a) => a.includes("*")),
      hasBranchOrEnvRestriction:
        uniqueSubs.length > 0 && uniqueSubs.every(hasBranchOrEnvConstraint),
      snippet: extractSnippetAroundLines(lines, Math.max(1, lineStart - 2), lineEnd)
    };
  }

  return null;
}

/**
 * Extracts static AWS IAM / CloudFormation / Azure ARM OIDC trust policies from JSON or YAML IaC files.
 */
export function analyzeStructuredOidcPolicies(
  filePath: string,
  content: string
): OidcTrustPolicy[] {
  if (!content.includes(GITHUB_OIDC_ISSUER)) return [];

  let parsed: unknown;
  const isJson = filePath.toLowerCase().endsWith(".json");
  try {
    parsed = isJson
      ? JSON.parse(content)
      : parseYaml(content, { schema: "core", maxAliasCount: 32 });
  } catch {
    return [];
  }

  if (!parsed || typeof parsed !== "object") return [];
  const obj = parsed as Record<string, unknown>;
  const policies: OidcTrustPolicy[] = [];

  // Case 1: Standalone AWS IAM trust policy JSON
  if (obj.Statement) {
    const p = inspectAwsPolicyDocumentObject(obj, {
      filePath,
      format: isJson ? "cloudformation-json" : "cloudformation-yaml",
      resourceName: filePath,
      content
    });
    if (p) policies.push(p);
  }

  // Case 2: AWS CloudFormation template Resources
  if (obj.Resources && typeof obj.Resources === "object") {
    for (const [resName, resVal] of Object.entries(obj.Resources as Record<string, unknown>)) {
      if (!resVal || typeof resVal !== "object") continue;
      const r = resVal as { Type?: string; Properties?: { AssumeRolePolicyDocument?: unknown } };
      if (r.Type === "AWS::IAM::Role" && r.Properties?.AssumeRolePolicyDocument) {
        const p = inspectAwsPolicyDocumentObject(r.Properties.AssumeRolePolicyDocument, {
          filePath,
          format: isJson ? "cloudformation-json" : "cloudformation-yaml",
          resourceName: resName,
          content
        });
        if (p) policies.push(p);
      }
    }
  }

  return policies;
}
