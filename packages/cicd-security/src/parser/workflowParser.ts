import {
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  LineCounter,
  parseDocument,
  visit,
  type Node,
  type YAMLMap
} from "yaml";
import type {
  ParsedWorkflow,
  PermissionAccess,
  WorkflowJob,
  WorkflowPermissionsBlock,
  WorkflowStep,
  WorkflowTrigger
} from "../types.js";

export const MAX_WORKFLOW_FILE_BYTES = 512 * 1024; // 512 KB cap per workflow YAML
export const MAX_YAML_ALIASES = 32; // Mitigate Billion Laughs YAML alias expansion DoS

const SHA_PIN_REGEX = /@[0-9a-f]{40}$/i;
const SECRET_REF_REGEX = /\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b/g;

function getLineRange(
  node: Node | null | undefined,
  lineCounter: LineCounter,
  fallback = 1
): { lineStart: number; lineEnd: number } {
  const range = (node as { range?: [number, number, number] } | null | undefined)?.range;
  if (!range || typeof range[0] !== "number") {
    return { lineStart: fallback, lineEnd: fallback };
  }
  const startPos = lineCounter.linePos(range[0]);
  const endOffset = Math.max(range[0], (range[1] ?? range[0]) - 1);
  const endPos = lineCounter.linePos(endOffset);
  return {
    lineStart: startPos?.line ?? fallback,
    lineEnd: endPos?.line ?? startPos?.line ?? fallback
  };
}

function getMapPair(map: YAMLMap, keyName: string) {
  for (const item of map.items) {
    if (!isPair(item)) continue;
    const k = isScalar(item.key) ? String(item.key.value) : "";
    if (k === keyName) {
      return item;
    }
  }
  return undefined;
}

function getMapValue(map: YAMLMap, keyName: string): Node | undefined {
  const pair = getMapPair(map, keyName);
  return (pair?.value as Node | undefined) ?? undefined;
}

function scalarToString(node: Node | undefined): string | undefined {
  if (!node || !isScalar(node) || node.value === null || node.value === undefined) {
    return undefined;
  }
  return String(node.value);
}

function parseStringRecord(node: Node | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!node || !isMap(node)) return result;
  for (const item of node.items) {
    if (!isPair(item) || !isScalar(item.key)) continue;
    const k = String(item.key.value);
    const v = scalarToString(item.value as Node | undefined);
    if (v !== undefined) {
      result[k] = v;
    }
  }
  return result;
}

function parseStringArray(node: Node | undefined): string[] | undefined {
  if (!node) return undefined;
  if (isScalar(node) && node.value !== null && node.value !== undefined) {
    return [String(node.value)];
  }
  if (isSeq(node)) {
    const out: string[] = [];
    for (const el of node.items) {
      const val = scalarToString(el as Node | undefined);
      if (val !== undefined) out.push(val);
    }
    return out;
  }
  return undefined;
}

function parsePermissions(
  node: Node | undefined,
  lineCounter: LineCounter
): WorkflowPermissionsBlock | undefined {
  if (!node) return undefined;
  const { lineStart, lineEnd } = getLineRange(node, lineCounter);

  if (isScalar(node)) {
    const val = String(node.value ?? "").trim().toLowerCase();
    if (val === "write-all") {
      return { mode: "write-all", scopes: {}, lineStart, lineEnd };
    }
    if (val === "read-all") {
      return { mode: "read-all", scopes: {}, lineStart, lineEnd };
    }
    return { mode: "empty", scopes: {}, lineStart, lineEnd };
  }

  if (isMap(node)) {
    const scopes: Record<string, PermissionAccess> = {};
    for (const item of node.items) {
      if (!isPair(item) || !isScalar(item.key)) continue;
      const scope = String(item.key.value).trim();
      const accessRaw = String(scalarToString(item.value as Node | undefined) ?? "")
        .trim()
        .toLowerCase();
      if (accessRaw === "read" || accessRaw === "write" || accessRaw === "none") {
        scopes[scope] = accessRaw;
      }
    }
    return {
      mode: Object.keys(scopes).length === 0 ? "empty" : "scoped",
      scopes,
      lineStart,
      lineEnd
    };
  }

  return undefined;
}

function parseTriggers(
  rootMap: YAMLMap,
  lineCounter: LineCounter
): WorkflowTrigger[] {
  // Handle both "on" (YAML 1.2 core schema) and boolean `true` key (YAML 1.1 compatibility)
  const onNode = getMapValue(rootMap, "on") ?? getMapValue(rootMap, "true");
  if (!onNode) return [];

  const triggers: WorkflowTrigger[] = [];

  if (isScalar(onNode)) {
    const event = scalarToString(onNode);
    if (event) {
      const range = getLineRange(onNode, lineCounter);
      triggers.push({ event, ...range });
    }
    return triggers;
  }

  if (isSeq(onNode)) {
    for (const item of onNode.items) {
      const event = scalarToString(item as Node | undefined);
      if (event) {
        const range = getLineRange(item as Node | undefined, lineCounter);
        triggers.push({ event, ...range });
      }
    }
    return triggers;
  }

  if (isMap(onNode)) {
    for (const item of onNode.items) {
      if (!isPair(item) || !isScalar(item.key)) continue;
      const event = String(item.key.value);
      const range = getLineRange(item.key as Node, lineCounter);
      const val = item.value as Node | undefined;
      let branches: string[] | undefined;
      let types: string[] | undefined;
      if (val && isMap(val)) {
        branches = parseStringArray(getMapValue(val, "branches"));
        types = parseStringArray(getMapValue(val, "types"));
      }
      triggers.push({ event, branches, types, ...range });
    }
  }

  return triggers;
}

export function isActionPinnedToSha(usesRef: string): boolean {
  const trimmed = usesRef.trim();
  // Local relative actions (./.github/actions/...) are repository-local
  if (trimmed.startsWith("./")) return true;
  // Docker actions pinned by sha256 digest are immutable
  if (trimmed.startsWith("docker://") && /@sha256:[0-9a-f]{64}$/i.test(trimmed)) {
    return true;
  }
  return SHA_PIN_REGEX.test(trimmed);
}

function detectOidcCloudTarget(usesRef: string): "aws" | "azure" | "gcp" | undefined {
  const lower = usesRef.toLowerCase();
  if (lower.startsWith("aws-actions/configure-aws-credentials")) return "aws";
  if (lower.startsWith("azure/login")) return "azure";
  if (lower.startsWith("google-github-actions/auth")) return "gcp";
  return undefined;
}

export interface WorkflowParseResult {
  workflow?: ParsedWorkflow;
  error?: string;
}

/**
 * Safely parses a GitHub Actions workflow YAML file into a strongly-typed model
 * with exact line-number tracking and strict YAML alias/size limits.
 */
export function parseGitHubWorkflowYaml(
  filePath: string,
  yamlContent: string
): WorkflowParseResult {
  if (Buffer.byteLength(yamlContent, "utf8") > MAX_WORKFLOW_FILE_BYTES) {
    return {
      error: `Workflow file "${filePath}" exceeds maximum allowed size (${MAX_WORKFLOW_FILE_BYTES} bytes).`
    };
  }

  const lineCounter = new LineCounter();
  let doc;
  try {
    doc = parseDocument(yamlContent, {
      lineCounter,
      schema: "core",
      prettyErrors: false
    });
  } catch (err) {
    return {
      error: `Failed to parse workflow YAML "${filePath}": ${(err as Error).message}`
    };
  }

  if (doc.errors.length > 0) {
    const firstErr = doc.errors[0]!.message.split("\n")[0];
    return {
      error: `Invalid YAML syntax in "${filePath}": ${firstErr}`
    };
  }

  // Enforce strict YAML alias ceiling to prevent Billion Laughs expansion DoS (CICD-T1)
  let aliasCount = 0;
  visit(doc, {
    Alias() {
      aliasCount += 1;
      if (aliasCount > MAX_YAML_ALIASES) {
        return visit.BREAK;
      }
      return undefined;
    }
  });
  if (aliasCount > MAX_YAML_ALIASES) {
    return {
      error: `YAML alias count in "${filePath}" exceeds safety limit (${MAX_YAML_ALIASES}); rejected to prevent YAML alias-expansion DoS.`
    };
  }
  void isAlias;

  if (!doc.contents || !isMap(doc.contents)) {
    return {
      error: `Workflow file "${filePath}" root YAML document must be a mapping.`
    };
  }

  const rootMap = doc.contents;
  const name = scalarToString(getMapValue(rootMap, "name")) ?? filePath;
  const triggers = parseTriggers(rootMap, lineCounter);
  const permissions = parsePermissions(getMapValue(rootMap, "permissions"), lineCounter);
  const env = parseStringRecord(getMapValue(rootMap, "env"));
  const rawLines = yamlContent.split(/\r?\n/);

  const jobs: WorkflowJob[] = [];
  const thirdPartyActions: ParsedWorkflow["thirdPartyActions"] = [];
  const oidcTargets = new Set<"aws" | "azure" | "gcp" | "generic">();
  let usesOidc = false;

  if (permissions?.scopes["id-token"] === "write" || permissions?.mode === "write-all") {
    usesOidc = true;
  }

  const jobsNode = getMapValue(rootMap, "jobs");
  if (jobsNode && isMap(jobsNode)) {
    for (const jobPair of jobsNode.items) {
      if (!isPair(jobPair) || !isScalar(jobPair.key)) continue;
      const jobId = String(jobPair.key.value);
      const jobVal = jobPair.value as Node | undefined;
      if (!jobVal || !isMap(jobVal)) continue;

      const jobRange = getLineRange(jobVal, lineCounter, getLineRange(jobPair.key as Node, lineCounter).lineStart);
      const jobPerms = parsePermissions(getMapValue(jobVal, "permissions"), lineCounter);
      if (jobPerms?.scopes["id-token"] === "write" || jobPerms?.mode === "write-all") {
        usesOidc = true;
      }

      const envNode = getMapValue(jobVal, "environment");
      let environment: string | undefined;
      if (envNode && isScalar(envNode)) {
        environment = scalarToString(envNode);
      } else if (envNode && isMap(envNode)) {
        environment = scalarToString(getMapValue(envNode, "name"));
      }

      const reusableUses = scalarToString(getMapValue(jobVal, "uses"));
      const secretsNode = getMapValue(jobVal, "secrets");
      const secretsInherit =
        secretsNode !== undefined &&
        isScalar(secretsNode) &&
        String(secretsNode.value).trim().toLowerCase() === "inherit";

      const runsOnNode = getMapValue(jobVal, "runs-on");
      const runsOn =
        scalarToString(runsOnNode) ??
        (parseStringArray(runsOnNode)?.join(", ") || undefined);

      const steps: WorkflowStep[] = [];
      const stepsNode = getMapValue(jobVal, "steps");
      if (stepsNode && isSeq(stepsNode)) {
        stepsNode.items.forEach((stepItem, index) => {
          if (!stepItem || !isMap(stepItem as Node)) return;
          const stepMap = stepItem as YAMLMap;
          const stepRange = getLineRange(stepMap, lineCounter, jobRange.lineStart);
          const usesNode = getMapValue(stepMap, "uses");
          const runNode = getMapValue(stepMap, "run");
          const uses = scalarToString(usesNode);
          const run = scalarToString(runNode);
          const withInputs = parseStringRecord(getMapValue(stepMap, "with"));

          if (uses) {
            const usesLine = getLineRange(usesNode, lineCounter, stepRange.lineStart).lineStart;
            const cloudTarget = detectOidcCloudTarget(uses);
            if (cloudTarget) {
              // Detect whether cloud login action uses OIDC (role-to-assume / workload_identity_provider / tenant-id without creds)
              if (
                (cloudTarget === "aws" && Boolean(withInputs["role-to-assume"])) ||
                (cloudTarget === "gcp" && Boolean(withInputs["workload_identity_provider"])) ||
                (cloudTarget === "azure" && !withInputs["creds"] && Boolean(withInputs["client-id"]))
              ) {
                usesOidc = true;
                oidcTargets.add(cloudTarget);
              }
            }

            if (!uses.startsWith("./")) {
              thirdPartyActions.push({
                action: uses,
                pinnedToSha: isActionPinnedToSha(uses),
                jobId,
                lineStart: usesLine
              });
            }
          }

          steps.push({
            index,
            id: scalarToString(getMapValue(stepMap, "id")),
            name: scalarToString(getMapValue(stepMap, "name")),
            uses,
            withInputs,
            run,
            env: parseStringRecord(getMapValue(stepMap, "env")),
            shell: scalarToString(getMapValue(stepMap, "shell")),
            lineStart: stepRange.lineStart,
            lineEnd: stepRange.lineEnd,
            usesLine: usesNode ? getLineRange(usesNode, lineCounter, stepRange.lineStart).lineStart : undefined,
            runLine: runNode ? getLineRange(runNode, lineCounter, stepRange.lineStart).lineStart : undefined
          });
        });
      }

      jobs.push({
        jobId,
        name: scalarToString(getMapValue(jobVal, "name")),
        runsOn,
        environment,
        usesReusableWorkflow: reusableUses,
        secretsInherit,
        permissions: jobPerms,
        env: parseStringRecord(getMapValue(jobVal, "env")),
        steps,
        lineStart: jobRange.lineStart,
        lineEnd: jobRange.lineEnd
      });
    }
  }

  if (usesOidc && oidcTargets.size === 0) {
    oidcTargets.add("generic");
  }

  const secretSet = new Set<string>();
  SECRET_REF_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SECRET_REF_REGEX.exec(yamlContent)) !== null) {
    if (match[1] && match[1] !== "GITHUB_TOKEN") {
      secretSet.add(match[1]);
    }
  }

  return {
    workflow: {
      filePath,
      name,
      triggers,
      permissions,
      env,
      jobs,
      referencedSecrets: [...secretSet].sort(),
      thirdPartyActions,
      usesOidc,
      oidcCloudTargets: [...oidcTargets],
      rawLines
    }
  };
}
