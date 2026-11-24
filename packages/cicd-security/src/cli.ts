import path from "node:path";
import { analyzeWorkspaceCicdSecurity } from "./adapter.js";
import {
  formatGitHubAnnotations,
  formatPullRequestMarkdownSummary
} from "./policy.js";
import type { CicdPolicyMode } from "./types.js";

async function main() {
  const args = process.argv.slice(2);
  let targetPath = process.cwd();
  let format: "json" | "markdown" | "annotations" = "markdown";
  let policyMode: CicdPolicyMode = "warning";
  const ignorePaths: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--format" && args[i + 1]) {
      const f = args[++i]!;
      if (f === "json" || f === "markdown" || f === "annotations") format = f;
    } else if (arg === "--policy" && args[i + 1]) {
      const p = args[++i]!;
      if (p === "informational" || p === "info") policyMode = "informational";
      else if (p === "warning" || p === "warn") policyMode = "warning";
      else if (p === "failure" || p === "fail") policyMode = "failure";
    } else if (arg === "--ignore" && args[i + 1]) {
      ignorePaths.push(args[++i]!);
    } else if (!arg.startsWith("-")) {
      targetPath = path.resolve(arg);
    }
  }

  const report = await analyzeWorkspaceCicdSecurity(targetPath, {
    mode: policyMode,
    failOnSeverities: ["CRITICAL", "HIGH"],
    ignorePaths
  });

  if (format === "json") {
    console.log(JSON.stringify(report, null, 2));
  } else if (format === "annotations") {
    const out = formatGitHubAnnotations(report.findings);
    if (out) console.log(out);
  } else {
    console.log(formatPullRequestMarkdownSummary(report));
  }

  process.exit(report.policyEvaluation.exitCode);
}

const isMain = process.argv[1]?.endsWith("cli.ts") || process.argv[1]?.endsWith("cli.js");
if (isMain) {
  main().catch((err) => {
    console.error("[indicative/cicd-security] CLI error:", (err as Error).message);
    process.exit(2);
  });
}
