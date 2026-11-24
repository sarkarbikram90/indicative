import fs from "node:fs/promises";
import path from "node:path";
import { analyzeWorkspaceCicdSecurity } from "./adapter.js";
import {
  formatCicdReportAsSarif,
  formatGitHubAnnotations,
  formatPullRequestMarkdownSummary
} from "./policy.js";
import type { CicdPolicyMode } from "./types.js";

export interface CicdCliOptions {
  targetPath: string;
  format: "json" | "markdown" | "annotations" | "sarif";
  policyMode: CicdPolicyMode;
  ignorePaths: string[];
  outputFile?: string;
  sarifFile?: string;
  summaryFile?: string;
  githubOutputFile?: string;
  emitAnnotations?: boolean;
}

export function parseCicdCliArgs(args: string[]): CicdCliOptions {
  let targetPath = process.cwd();
  let format: "json" | "markdown" | "annotations" | "sarif" = "markdown";
  let policyMode: CicdPolicyMode = "warning";
  const ignorePaths: string[] = [];
  let outputFile: string | undefined;
  let sarifFile: string | undefined;
  let summaryFile: string | undefined;
  let githubOutputFile: string | undefined;
  let emitAnnotations = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--format" && args[i + 1]) {
      const f = args[++i]!;
      if (f === "json" || f === "markdown" || f === "annotations" || f === "sarif") {
        format = f;
      }
    } else if (arg === "--policy" && args[i + 1]) {
      const p = args[++i]!;
      if (p === "informational" || p === "info") policyMode = "informational";
      else if (p === "warning" || p === "warn") policyMode = "warning";
      else if (p === "failure" || p === "fail") policyMode = "failure";
    } else if (arg === "--ignore" && args[i + 1]) {
      const raw = args[++i]!;
      for (const entry of raw.split(/[,\n]/).map((s) => s.trim()).filter(Boolean)) {
        ignorePaths.push(entry);
      }
    } else if (arg === "--output" && args[i + 1]) {
      outputFile = path.resolve(args[++i]!);
    } else if (arg === "--sarif-file" && args[i + 1]) {
      sarifFile = path.resolve(args[++i]!);
    } else if (arg === "--summary-file" && args[i + 1]) {
      summaryFile = path.resolve(args[++i]!);
    } else if (arg === "--github-output" && args[i + 1]) {
      githubOutputFile = path.resolve(args[++i]!);
    } else if (arg === "--annotations") {
      emitAnnotations = true;
    } else if (!arg.startsWith("-")) {
      targetPath = path.resolve(arg);
    }
  }

  return {
    targetPath,
    format,
    policyMode,
    ignorePaths,
    outputFile,
    sarifFile,
    summaryFile,
    githubOutputFile,
    emitAnnotations
  };
}

export async function runCicdCli(options: CicdCliOptions): Promise<number> {
  const report = await analyzeWorkspaceCicdSecurity(options.targetPath, {
    mode: options.policyMode,
    failOnSeverities: ["CRITICAL", "HIGH"],
    ignorePaths: options.ignorePaths
  });

  const markdownSummary = formatPullRequestMarkdownSummary(report);
  let primaryOutput: string;
  if (options.format === "json") {
    primaryOutput = JSON.stringify(report, null, 2);
  } else if (options.format === "sarif") {
    primaryOutput = formatCicdReportAsSarif(report);
  } else if (options.format === "annotations") {
    primaryOutput = formatGitHubAnnotations(report.findings);
  } else {
    primaryOutput = markdownSummary;
  }

  if (options.outputFile) {
    await fs.mkdir(path.dirname(options.outputFile), { recursive: true });
    await fs.writeFile(options.outputFile, `${primaryOutput}\n`, "utf8");
  } else if (primaryOutput) {
    console.log(primaryOutput);
  }

  if (options.sarifFile) {
    const sarifContent =
      options.format === "sarif" ? primaryOutput : formatCicdReportAsSarif(report);
    await fs.mkdir(path.dirname(options.sarifFile), { recursive: true });
    await fs.writeFile(options.sarifFile, `${sarifContent}\n`, "utf8");
  }

  if (options.summaryFile) {
    await fs.mkdir(path.dirname(options.summaryFile), { recursive: true });
    await fs.appendFile(options.summaryFile, `\n${markdownSummary}\n`, "utf8");
  }

  if (options.emitAnnotations && options.format !== "annotations") {
    const annotations = formatGitHubAnnotations(report.findings);
    if (annotations) console.log(annotations);
  }

  if (options.githubOutputFile) {
    const outputLines = [
      `findings-count=${report.findings.length}`,
      `blocking-count=${report.policyEvaluation.blockingFindingsCount}`,
      `policy-passed=${report.policyEvaluation.passed ? "true" : "false"}`,
      `sarif-file=${options.sarifFile ?? (options.format === "sarif" ? (options.outputFile ?? "") : "")}`
    ];
    await fs.appendFile(options.githubOutputFile, `${outputLines.join("\n")}\n`, "utf8");
  }

  return report.policyEvaluation.exitCode;
}

async function main() {
  const options = parseCicdCliArgs(process.argv.slice(2));
  const exitCode = await runCicdCli(options);
  process.exit(exitCode);
}

const isMain = process.argv[1]?.endsWith("cli.ts") || process.argv[1]?.endsWith("cli.js");
if (isMain) {
  main().catch((err) => {
    console.error("[indicative/cicd-security] CLI error:", (err as Error).message);
    process.exit(2);
  });
}
