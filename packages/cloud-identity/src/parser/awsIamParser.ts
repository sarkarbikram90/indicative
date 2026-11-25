import crypto from "node:crypto";
import { parse as parseYaml } from "yaml";
import { redactSecretsInText } from "@indicative/security";
import type {
  CloudIamRole,
  IamPolicyStatement,
  StandaloneIamPolicy
} from "../types.js";

function lineNumberAtOffset(content: string, offset: number): number {
  let line = 1;
  const max = Math.min(offset, content.length);
  for (let i = 0; i < max; i++) {
    if (content.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function extractSnippet(lines: string[], lineStart: number, lineEnd: number): string {
  const s = Math.max(0, lineStart - 1);
  const e = Math.min(lines.length, Math.max(lineEnd, lineStart + 6), s + 16);
  return redactSecretsInText(
    lines
      .slice(s, e)
      .map((l, i) => `${s + i + 1}: ${l}`)
      .join("\n")
  );
}

function toStringArray(value: unknown): string[] {
  if (typeof value === "string") return [value.trim()].filter(Boolean);
  if (Array.isArray(value)) {
    return value
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

function extractConditionKeys(conditionObj: unknown): string[] {
  if (!conditionObj || typeof conditionObj !== "object" || Array.isArray(conditionObj)) {
    return [];
  }
  const keys = new Set<string>();
  for (const opVal of Object.values(conditionObj as Record<string, unknown>)) {
    if (opVal && typeof opVal === "object" && !Array.isArray(opVal)) {
      for (const condKey of Object.keys(opVal as Record<string, unknown>)) {
        keys.add(condKey);
      }
    }
  }
  return [...keys];
}

function parseStatementsFromPolicyDocument(params: {
  doc: unknown;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  sourceKind: IamPolicyStatement["sourceKind"];
  policyName: string;
  snippet: string;
}): IamPolicyStatement[] {
  if (!params.doc || typeof params.doc !== "object" || Array.isArray(params.doc)) {
    return [];
  }
  const obj = params.doc as Record<string, unknown>;
  const rawStatements = obj.Statement ?? obj.statement;
  const list = Array.isArray(rawStatements)
    ? rawStatements
    : rawStatements && typeof rawStatements === "object"
      ? [rawStatements]
      : [];

  const statements: IamPolicyStatement[] = [];
  for (const raw of list) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const stmt = raw as Record<string, unknown>;
    const rawEffect = String(stmt.Effect ?? stmt.effect ?? "Allow").toLowerCase();
    const effect: "Allow" | "Deny" = rawEffect === "deny" ? "Deny" : "Allow";
    const actions = toStringArray(stmt.Action ?? stmt.action ?? stmt.actions);
    const notActions = toStringArray(stmt.NotAction ?? stmt.not_actions);
    const resources = toStringArray(stmt.Resource ?? stmt.resource ?? stmt.resources);
    const notResources = toStringArray(stmt.NotResource ?? stmt.not_resources);

    if (
      actions.length === 0 &&
      notActions.length === 0 &&
      resources.length === 0 &&
      notResources.length === 0
    ) {
      continue;
    }

    const conditionKeys = extractConditionKeys(stmt.Condition ?? stmt.condition);
    statements.push({
      sid: typeof (stmt.Sid ?? stmt.sid) === "string" ? String(stmt.Sid ?? stmt.sid) : undefined,
      effect,
      actions,
      notActions,
      resources,
      notResources,
      conditionKeys,
      hasCondition: conditionKeys.length > 0 || Boolean(stmt.Condition ?? stmt.condition),
      sourceFilePath: params.filePath,
      lineStart: params.lineStart,
      lineEnd: params.lineEnd,
      sourceKind: params.sourceKind,
      policyName: params.policyName,
      snippet: params.snippet
    });
  }

  return statements;
}

/**
 * Finds the closing brace matching an opening `{` at `openIdx`, ignoring quoted strings.
 */
function findMatchingBrace(content: string, openIdx: number, maxSpan = 25_000): number {
  let depth = 0;
  let inString: '"' | "'" | null = null;
  const limit = Math.min(content.length, openIdx + maxSpan);

  for (let i = openIdx; i < limit; i++) {
    const ch = content[i]!;
    if (inString) {
      if (ch === "\\" && i + 1 < limit) {
        i += 1;
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = ch;
    } else if (ch === "{") {
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return Math.min(content.length - 1, limit - 1);
}

interface HclTopBlock {
  kind: "resource" | "data";
  type: string;
  name: string;
  body: string;
  startOffset: number;
  endOffset: number;
  lineStart: number;
  lineEnd: number;
}

function extractHclTopBlocks(content: string): HclTopBlock[] {
  const blocks: HclTopBlock[] = [];
  const headerRe = /(?:^|\n)[ \t]*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
  let match: RegExpExecArray | null;
  while ((match = headerRe.exec(content)) !== null) {
    const openBraceIdx = match.index + match[0].length - 1;
    const closeBraceIdx = findMatchingBrace(content, openBraceIdx);
    const startOffset = match.index + (match[0].startsWith("\n") ? 1 : 0);
    blocks.push({
      kind: match[1] as "resource" | "data",
      type: match[2]!,
      name: match[3]!,
      body: content.slice(openBraceIdx + 1, closeBraceIdx),
      startOffset,
      endOffset: closeBraceIdx + 1,
      lineStart: lineNumberAtOffset(content, startOffset),
      lineEnd: lineNumberAtOffset(content, closeBraceIdx + 1)
    });
    headerRe.lastIndex = closeBraceIdx + 1;
  }
  return blocks;
}

function extractQuotedStrings(raw: string): string[] {
  const out: string[] = [];
  const re = /"([^"\r\n]{1,400})"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    if (m[1]) out.push(m[1]);
  }
  return out;
}

/**
 * Extracts IAM policy statements from a Terraform HCL block body — supporting:
 * 1) `statement { ... }` HCL blocks (from `data "aws_iam_policy_document"`)
 * 2) `jsonencode({ Statement = [...] })` HCL expressions
 * 3) JSON heredoc `<<EOF { "Statement": [...] } EOF`
 */
function parseTerraformPolicyStatements(params: {
  body: string;
  filePath: string;
  blockLineStart: number;
  blockLineEnd: number;
  sourceKind: IamPolicyStatement["sourceKind"];
  policyName: string;
  lines: string[];
}): IamPolicyStatement[] {
  const statements: IamPolicyStatement[] = [];
  const { body, filePath, blockLineStart, blockLineEnd, sourceKind, policyName, lines } = params;
  const defaultSnippet = extractSnippet(lines, blockLineStart, blockLineEnd);

  // Strategy A: JSON heredoc <<EOF ... EOF or <<-POLICY ... POLICY
  const heredocRe = /<<-?([A-Za-z0-9_]+)\r?\n([\s\S]{1,20000}?)\r?\n[ \t]*\1\b/g;
  let hm: RegExpExecArray | null;
  while ((hm = heredocRe.exec(body)) !== null) {
    const rawJson = hm[2]!.trim();
    if (!rawJson.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(rawJson);
      const lineOffset = lineNumberAtOffset(body, hm.index) - 1;
      const lineStart = blockLineStart + lineOffset;
      statements.push(
        ...parseStatementsFromPolicyDocument({
          doc: parsed,
          filePath,
          lineStart,
          lineEnd: Math.min(blockLineEnd, lineStart + 12),
          sourceKind,
          policyName,
          snippet: extractSnippet(lines, lineStart, lineStart + 10)
        })
      );
    } catch {
      // May contain HCL ${...} interpolation inside JSON; handled by fallback extractor below
      const sanitized = rawJson.replace(/\$\{[^}]{1,120}\}/g, "placeholder");
      try {
        const parsed = JSON.parse(sanitized);
        const lineOffset = lineNumberAtOffset(body, hm.index) - 1;
        const lineStart = blockLineStart + lineOffset;
        statements.push(
          ...parseStatementsFromPolicyDocument({
            doc: parsed,
            filePath,
            lineStart,
            lineEnd: Math.min(blockLineEnd, lineStart + 12),
            sourceKind,
            policyName,
            snippet: extractSnippet(lines, lineStart, lineStart + 10)
          })
        );
      } catch {
        // Ignore unparseable heredocs
      }
    }
  }

  // Strategy B: HCL `statement { ... }` blocks (data "aws_iam_policy_document")
  const stmtBlockRe = /\bstatement\s*\{/g;
  let sm: RegExpExecArray | null;
  while ((sm = stmtBlockRe.exec(body)) !== null) {
    const openIdx = sm.index + sm[0].length - 1;
    const closeIdx = findMatchingBrace(body, openIdx, 6000);
    const stmtBody = body.slice(openIdx + 1, closeIdx);
    const lineStart = blockLineStart + lineNumberAtOffset(body, sm.index) - 1;
    const lineEnd = blockLineStart + lineNumberAtOffset(body, closeIdx) - 1;

    const effectMatch = stmtBody.match(/\beffect\s*=\s*"(Allow|Deny)"/i);
    const effect: "Allow" | "Deny" =
      effectMatch?.[1]?.toLowerCase() === "deny" ? "Deny" : "Allow";
    const sidMatch = stmtBody.match(/\bsid\s*=\s*"([^"\r\n]{1,120})"/);

    const actionsMatch = stmtBody.match(/\bactions\s*=\s*\[([^\]]{0,4000})\]/);
    const notActionsMatch = stmtBody.match(/\bnot_actions\s*=\s*\[([^\]]{0,4000})\]/);
    const resourcesMatch = stmtBody.match(/\bresources\s*=\s*\[([^\]]{0,4000})\]/);
    const notResourcesMatch = stmtBody.match(/\bnot_resources\s*=\s*\[([^\]]{0,4000})\]/);

    const conditionKeys: string[] = [];
    const condRe = /\bcondition\s*\{([^}]{0,1000})\}/g;
    let cm: RegExpExecArray | null;
    while ((cm = condRe.exec(stmtBody)) !== null) {
      const varMatch = cm[1]!.match(/\bvariable\s*=\s*"([^"\r\n]{1,160})"/);
      if (varMatch?.[1]) conditionKeys.push(varMatch[1]);
    }

    const actions = actionsMatch ? extractQuotedStrings(actionsMatch[1]!) : [];
    const notActions = notActionsMatch ? extractQuotedStrings(notActionsMatch[1]!) : [];
    const resources = resourcesMatch ? extractQuotedStrings(resourcesMatch[1]!) : [];
    const notResources = notResourcesMatch ? extractQuotedStrings(notResourcesMatch[1]!) : [];

    if (actions.length > 0 || notActions.length > 0) {
      statements.push({
        sid: sidMatch?.[1],
        effect,
        actions,
        notActions,
        resources,
        notResources,
        conditionKeys,
        hasCondition: conditionKeys.length > 0 || /\bcondition\s*\{/.test(stmtBody),
        sourceFilePath: filePath,
        lineStart,
        lineEnd,
        sourceKind,
        policyName,
        snippet: extractSnippet(lines, lineStart, lineEnd)
      });
    }
    stmtBlockRe.lastIndex = closeIdx + 1;
  }

  // Strategy C: HCL `jsonencode({ Statement = [ { Effect = "Allow", Action = ..., Resource = ... } ] })`
  if (statements.length === 0 && /\bjsonencode\s*\(/.test(body) && /\bStatement\b/.test(body)) {
    const statementArrMatch = body.match(/\bStatement\s*=\s*\[/);
    if (statementArrMatch && statementArrMatch.index !== undefined) {
      const arrStart = statementArrMatch.index + statementArrMatch[0].length;
      const slice = body.slice(arrStart, Math.min(body.length, arrStart + 18_000));
      let pos = 0;
      while (pos < slice.length) {
        const nextOpen = slice.indexOf("{", pos);
        if (nextOpen < 0) break;
        const closeIdx = findMatchingBrace(slice, nextOpen, 6000);
        const objBody = slice.slice(nextOpen + 1, closeIdx);
        pos = closeIdx + 1;

        if (!/\b(?:Action|NotAction)\b/.test(objBody)) continue;

        const effectMatch = objBody.match(/\bEffect\s*=\s*"(Allow|Deny)"/i);
        const effect: "Allow" | "Deny" =
          effectMatch?.[1]?.toLowerCase() === "deny" ? "Deny" : "Allow";
        const sidMatch = objBody.match(/\bSid\s*=\s*"([^"\r\n]{1,120})"/);

        const parseHclValue = (key: string): string[] => {
          const arrRe = new RegExp(`\\b${key}\\s*=\\s*\\[([^\\]]{0,4000})\\]`);
          const arrM = objBody.match(arrRe);
          if (arrM?.[1]) return extractQuotedStrings(arrM[1]);
          const singleRe = new RegExp(`\\b${key}\\s*=\\s*"([^"\\r\\n]{1,400})"`);
          const singleM = objBody.match(singleRe);
          if (singleM?.[1]) return [singleM[1]];
          return [];
        };

        const actions = parseHclValue("Action");
        const notActions = parseHclValue("NotAction");
        const resources = parseHclValue("Resource");
        const notResources = parseHclValue("NotResource");
        const hasCondition = /\bCondition\s*=\s*\{/.test(objBody);

        const lineStart =
          blockLineStart + lineNumberAtOffset(body, arrStart + nextOpen) - 1;
        const lineEnd =
          blockLineStart + lineNumberAtOffset(body, arrStart + closeIdx) - 1;

        if (actions.length > 0 || notActions.length > 0) {
          statements.push({
            sid: sidMatch?.[1],
            effect,
            actions,
            notActions,
            resources,
            notResources,
            conditionKeys: hasCondition ? ["hcl_condition"] : [],
            hasCondition,
            sourceFilePath: filePath,
            lineStart,
            lineEnd,
            sourceKind,
            policyName,
            snippet: extractSnippet(lines, lineStart, lineEnd) || defaultSnippet
          });
        }
      }
    }
  }

  return statements;
}

export interface ParsedWorkspaceIamArtifacts {
  roles: CloudIamRole[];
  standalonePolicies: StandaloneIamPolicy[];
}

/**
 * Parses AWS IAM roles, inline policies, managed policy attachments, and standalone IAM policies
 * across all Terraform (.tf) files in a workspace (supporting cross-file references between
 * `aws_iam_role`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_policy`,
 * and `data "aws_iam_policy_document"`).
 */
export function parseTerraformIamFiles(
  files: Array<{ relPath: string; content: string }>
): ParsedWorkspaceIamArtifacts {
  const rolesByResourceId = new Map<string, CloudIamRole>();
  const rolesByName = new Map<string, CloudIamRole>();
  const policyDocsByName = new Map<string, IamPolicyStatement[]>();
  const managedPoliciesByResourceId = new Map<
    string,
    { policyName: string; statements: IamPolicyStatement[]; filePath: string; lineStart: number; lineEnd: number; snippet: string }
  >();
  const pendingRolePolicies: Array<{
    roleRef: string;
    policyName: string;
    statements: IamPolicyStatement[];
    policyDocRef?: string;
  }> = [];
  const pendingAttachments: Array<{
    roleRef: string;
    policyArn?: string;
    managedPolicyResourceRef?: string;
  }> = [];
  const standalonePolicies: StandaloneIamPolicy[] = [];

  // Pass 1: Extract data "aws_iam_policy_document", resource "aws_iam_role", resource "aws_iam_policy"
  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    const blocks = extractHclTopBlocks(file.content);

    for (const block of blocks) {
      if (block.kind === "data" && block.type === "aws_iam_policy_document") {
        // Skip trust-only policy documents (AssumeRoleWithWebIdentity) from permission statements
        const stmts = parseTerraformPolicyStatements({
          body: block.body,
          filePath: file.relPath,
          blockLineStart: block.lineStart,
          blockLineEnd: block.lineEnd,
          sourceKind: "policy_document",
          policyName: block.name,
          lines
        }).filter(
          (s) =>
            !s.actions.every(
              (a) =>
                a.toLowerCase() === "sts:assumerolewithwebidentity" ||
                a.toLowerCase() === "sts:assumerole"
            ) || s.resources.length > 0
        );
        policyDocsByName.set(block.name, stmts);
      } else if (block.kind === "resource" && block.type === "aws_iam_role") {
        const nameMatch = block.body.match(/\bname\s*=\s*"([^"\r\n]{1,128})"/);
        const roleName = nameMatch?.[1] ?? block.name;
        const boundaryMatch = block.body.match(/\bpermissions_boundary\s*=\s*([^\r\n#]+)/);
        const managedArnsMatch = block.body.match(
          /\bmanaged_policy_arns\s*=\s*\[([^\]]{0,4000})\]/
        );
        const managedPolicyArns = managedArnsMatch
          ? extractQuotedStrings(managedArnsMatch[1]!)
          : [];

        const statements: IamPolicyStatement[] = [];
        // Parse embedded `inline_policy { name = ... policy = ... }` blocks
        const inlineRe = /\binline_policy\s*\{/g;
        let im: RegExpExecArray | null;
        while ((im = inlineRe.exec(block.body)) !== null) {
          const openIdx = im.index + im[0].length - 1;
          const closeIdx = findMatchingBrace(block.body, openIdx, 8000);
          const inlineBody = block.body.slice(openIdx + 1, closeIdx);
          const inlineName =
            inlineBody.match(/\bname\s*=\s*"([^"\r\n]{1,128})"/)?.[1] ?? `${roleName}-inline`;
          statements.push(
            ...parseTerraformPolicyStatements({
              body: inlineBody,
              filePath: file.relPath,
              blockLineStart: block.lineStart + lineNumberAtOffset(block.body, im.index) - 1,
              blockLineEnd: block.lineStart + lineNumberAtOffset(block.body, closeIdx) - 1,
              sourceKind: "inline_policy",
              policyName: inlineName,
              lines
            })
          );
          inlineRe.lastIndex = closeIdx + 1;
        }

        const role: CloudIamRole = {
          id: `aws-role:${crypto
            .createHash("sha256")
            .update(`${file.relPath}|${block.name}`)
            .digest("hex")
            .slice(0, 12)}`,
          provider: "aws",
          format: "terraform",
          filePath: file.relPath,
          resourceId: block.name,
          roleName,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          hasPermissionsBoundary: Boolean(boundaryMatch),
          permissionsBoundaryRef: boundaryMatch?.[1]?.trim(),
          managedPolicyArns,
          statements,
          snippet: extractSnippet(lines, block.lineStart, block.lineEnd)
        };
        rolesByResourceId.set(block.name, role);
        rolesByName.set(roleName.toLowerCase(), role);
      } else if (block.kind === "resource" && block.type === "aws_iam_policy") {
        const policyName =
          block.body.match(/\bname\s*=\s*"([^"\r\n]{1,128})"/)?.[1] ?? block.name;
        const docRefMatch = block.body.match(
          /\bpolicy\s*=\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json/
        );
        const stmts = parseTerraformPolicyStatements({
          body: block.body,
          filePath: file.relPath,
          blockLineStart: block.lineStart,
          blockLineEnd: block.lineEnd,
          sourceKind: "managed_policy",
          policyName,
          lines
        });
        managedPoliciesByResourceId.set(block.name, {
          policyName,
          statements: stmts,
          filePath: file.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          snippet: extractSnippet(lines, block.lineStart, block.lineEnd)
        });
        if (docRefMatch?.[1]) {
          // Will link after Pass 1 completes
          pendingRolePolicies.push({
            roleRef: `__MANAGED_POLICY__:${block.name}`,
            policyName,
            statements: [],
            policyDocRef: docRefMatch[1]
          });
        }
      } else if (block.kind === "resource" && block.type === "aws_iam_role_policy") {
        const policyName =
          block.body.match(/\bname\s*=\s*"([^"\r\n]{1,128})"/)?.[1] ?? block.name;
        const roleRefMatch =
          block.body.match(/\brole\s*=\s*aws_iam_role\.([A-Za-z0-9_-]+)\.(?:id|name)/) ??
          block.body.match(/\brole\s*=\s*"([^"\r\n]{1,128})"/);
        const docRefMatch = block.body.match(
          /\bpolicy\s*=\s*data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json/
        );
        const stmts = parseTerraformPolicyStatements({
          body: block.body,
          filePath: file.relPath,
          blockLineStart: block.lineStart,
          blockLineEnd: block.lineEnd,
          sourceKind: "role_policy",
          policyName,
          lines
        });
        if (roleRefMatch?.[1]) {
          pendingRolePolicies.push({
            roleRef: roleRefMatch[1],
            policyName,
            statements: stmts,
            policyDocRef: docRefMatch?.[1]
          });
        }
      } else if (block.kind === "resource" && block.type === "aws_iam_role_policy_attachment") {
        const roleRefMatch =
          block.body.match(/\brole\s*=\s*aws_iam_role\.([A-Za-z0-9_-]+)\.(?:id|name)/) ??
          block.body.match(/\brole\s*=\s*"([^"\r\n]{1,128})"/);
        const arnMatch = block.body.match(/\bpolicy_arn\s*=\s*"([^"\r\n]{1,256})"/);
        const resRefMatch = block.body.match(
          /\bpolicy_arn\s*=\s*aws_iam_policy\.([A-Za-z0-9_-]+)\.arn/
        );
        if (roleRefMatch?.[1]) {
          pendingAttachments.push({
            roleRef: roleRefMatch[1],
            policyArn: arnMatch?.[1],
            managedPolicyResourceRef: resRefMatch?.[1]
          });
        }
      }
    }
  }

  // Pass 2: Resolve data.aws_iam_policy_document references & attach policies to roles
  const attachedManagedIds = new Set<string>();

  for (const p of pendingRolePolicies) {
    if (p.roleRef.startsWith("__MANAGED_POLICY__:")) {
      const mpId = p.roleRef.slice("__MANAGED_POLICY__:".length);
      const mp = managedPoliciesByResourceId.get(mpId);
      const docStmts = p.policyDocRef ? (policyDocsByName.get(p.policyDocRef) ?? []) : [];
      if (mp && docStmts.length > 0) {
        mp.statements.push(...docStmts);
      }
      continue;
    }

    const role = rolesByResourceId.get(p.roleRef) ?? rolesByName.get(p.roleRef.toLowerCase());
    const docStmts = p.policyDocRef ? (policyDocsByName.get(p.policyDocRef) ?? []) : [];
    const combined = [...p.statements, ...docStmts];
    if (role) {
      role.statements.push(...combined);
    } else if (combined.length > 0) {
      standalonePolicies.push({
        id: `aws-policy:${crypto
          .createHash("sha256")
          .update(`${p.roleRef}|${p.policyName}`)
          .digest("hex")
          .slice(0, 12)}`,
        provider: "aws",
        format: "terraform",
        filePath: combined[0]!.sourceFilePath,
        policyName: p.policyName,
        lineStart: combined[0]!.lineStart,
        lineEnd: combined[0]!.lineEnd,
        statements: combined,
        snippet: combined[0]!.snippet
      });
    }
  }

  for (const att of pendingAttachments) {
    const role = rolesByResourceId.get(att.roleRef) ?? rolesByName.get(att.roleRef.toLowerCase());
    if (!role) continue;
    if (att.policyArn) {
      if (!role.managedPolicyArns.includes(att.policyArn)) {
        role.managedPolicyArns.push(att.policyArn);
      }
    }
    if (att.managedPolicyResourceRef) {
      const mp = managedPoliciesByResourceId.get(att.managedPolicyResourceRef);
      if (mp) {
        attachedManagedIds.add(att.managedPolicyResourceRef);
        role.statements.push(...mp.statements);
      }
    }
  }

  // Unattached aws_iam_policy resources become standalone policies so they are still audited
  for (const [resId, mp] of managedPoliciesByResourceId.entries()) {
    if (attachedManagedIds.has(resId) || mp.statements.length === 0) continue;
    standalonePolicies.push({
      id: `aws-policy:${crypto
        .createHash("sha256")
        .update(`${mp.filePath}|${resId}`)
        .digest("hex")
        .slice(0, 12)}`,
      provider: "aws",
      format: "terraform",
      filePath: mp.filePath,
      policyName: mp.policyName,
      lineStart: mp.lineStart,
      lineEnd: mp.lineEnd,
      statements: mp.statements,
      snippet: mp.snippet
    });
  }

  return {
    roles: [...rolesByResourceId.values()],
    standalonePolicies
  };
}

/**
 * Parses CloudFormation (.yml/.yaml/.json) AWS::IAM::Role / Policy resources
 * and standalone AWS IAM Policy JSON documents.
 */
export function parseStructuredAwsIamFile(
  filePath: string,
  content: string
): ParsedWorkspaceIamArtifacts {
  const roles: CloudIamRole[] = [];
  const standalonePolicies: StandaloneIamPolicy[] = [];
  const lines = content.split(/\r?\n/);
  const isJson = filePath.toLowerCase().endsWith(".json");

  let parsed: unknown;
  try {
    parsed = isJson
      ? JSON.parse(content)
      : parseYaml(content, { maxAliasCount: 25, strict: false });
  } catch {
    return { roles, standalonePolicies };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { roles, standalonePolicies };
  }

  const root = parsed as Record<string, unknown>;

  // Case 1: CloudFormation template with Resources
  if (root.Resources && typeof root.Resources === "object" && !Array.isArray(root.Resources)) {
    const format: CloudIamRole["format"] = isJson
      ? "cloudformation-json"
      : "cloudformation-yaml";

    for (const [logicalId, rawRes] of Object.entries(root.Resources as Record<string, unknown>)) {
      if (!rawRes || typeof rawRes !== "object" || Array.isArray(rawRes)) continue;
      const res = rawRes as Record<string, unknown>;
      const resType = String(res.Type ?? "");
      const props = (res.Properties ?? {}) as Record<string, unknown>;
      const lineIdx = lines.findIndex((l) => l.includes(logicalId));
      const lineStart = lineIdx >= 0 ? lineIdx + 1 : 1;
      const lineEnd = Math.min(lines.length, lineStart + 15);
      const snippet = extractSnippet(lines, lineStart, lineEnd);

      if (resType === "AWS::IAM::Role") {
        const roleName =
          typeof props.RoleName === "string" && props.RoleName.trim()
            ? props.RoleName.trim()
            : logicalId;
        const managedPolicyArns = toStringArray(props.ManagedPolicyArns);
        const statements: IamPolicyStatement[] = [];

        if (Array.isArray(props.Policies)) {
          for (const inline of props.Policies) {
            if (!inline || typeof inline !== "object") continue;
            const ip = inline as Record<string, unknown>;
            const policyName = String(ip.PolicyName ?? `${roleName}-inline`);
            statements.push(
              ...parseStatementsFromPolicyDocument({
                doc: ip.PolicyDocument,
                filePath,
                lineStart,
                lineEnd,
                sourceKind: "inline_policy",
                policyName,
                snippet
              })
            );
          }
        }

        roles.push({
          id: `aws-role:${crypto
            .createHash("sha256")
            .update(`${filePath}|${logicalId}`)
            .digest("hex")
            .slice(0, 12)}`,
          provider: "aws",
          format,
          filePath,
          resourceId: logicalId,
          roleName,
          lineStart,
          lineEnd,
          hasPermissionsBoundary: Boolean(props.PermissionsBoundary),
          permissionsBoundaryRef:
            typeof props.PermissionsBoundary === "string"
              ? props.PermissionsBoundary
              : undefined,
          managedPolicyArns,
          statements,
          snippet
        });
      } else if (resType === "AWS::IAM::Policy" || resType === "AWS::IAM::ManagedPolicy") {
        const policyName =
          typeof props.PolicyName === "string" ? props.PolicyName : logicalId;
        const stmts = parseStatementsFromPolicyDocument({
          doc: props.PolicyDocument,
          filePath,
          lineStart,
          lineEnd,
          sourceKind: "managed_policy",
          policyName,
          snippet
        });
        if (stmts.length > 0) {
          standalonePolicies.push({
            id: `aws-policy:${crypto
              .createHash("sha256")
              .update(`${filePath}|${logicalId}`)
              .digest("hex")
              .slice(0, 12)}`,
            provider: "aws",
            format,
            filePath,
            policyName,
            lineStart,
            lineEnd,
            statements: stmts,
            snippet
          });
        }
      }
    }
    return { roles, standalonePolicies };
  }

  // Case 2: Standalone AWS IAM Policy JSON (`Version` + `Statement`, NOT a trust-only AssumeRole doc)
  if (isJson && Array.isArray(root.Statement) && typeof root.Version === "string") {
    const stmts = parseStatementsFromPolicyDocument({
      doc: root,
      filePath,
      lineStart: 1,
      lineEnd: Math.min(lines.length, 25),
      sourceKind: "standalone_json",
      policyName: filePath,
      snippet: extractSnippet(lines, 1, 20)
    }).filter((s) => s.resources.length > 0 || s.notResources.length > 0);

    if (stmts.length > 0) {
      standalonePolicies.push({
        id: `aws-policy:${crypto
          .createHash("sha256")
          .update(filePath)
          .digest("hex")
          .slice(0, 12)}`,
        provider: "aws",
        format: "iam-json",
        filePath,
        policyName: filePath,
        lineStart: 1,
        lineEnd: Math.min(lines.length, 25),
        statements: stmts,
        snippet: extractSnippet(lines, 1, 20)
      });
    }
  }

  return { roles, standalonePolicies };
}
