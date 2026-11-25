#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import type { CicdPolicyMode } from "@indicative/cicd-security";
import { analyzeWorkspaceCloudIdentity } from "./adapter.js";
import {
  formatCloudIdentityMarkdownSummary,
  formatCloudIdentityReportAsSarif
} from "./policy.js";

export interface CloudIdentityCliOptions {
  targetPath: string;
  format: "json" | "markdown" | "sarif";
  policyMode: CicdPolicyMode;
  ignorePaths: string[];
  outputFile?: string;
  sarifFile?: string;
}

export function parseCloudIdentityCliArgs(args: string[]): CloudIdentityCliOptions {
  let targetPath = process.cwd();
  let format: "json" | "markdown" | "sarif" = "markdown";
  let policyMode: CicdPolicyMode = "warning";
  const ignorePaths: string[] = [];
  let outputFile: string | undefined;
  let sarifFile: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--format" && args[i + 1]) {
      const f = args[++i]!;
      if (f === "json" || f === "markdown" || f === "sarif") format = f;
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
    } else if (!arg.startsWith("-")) {
      targetPath = path.resolve(arg);
    }
  }

  return { targetPath, format, policyMode, ignorePaths, outputFile, sarifFile };
}

export async function runCloudIdentityCli(
  options: CloudIdentityCliOptions
): Promise<number> {
  const report = await analyzeWorkspaceCloudIdentity(options.targetPath, {
    mode: options.policyMode,
    failOnSeverities: ["CRITICAL", "HIGH"],
    ignorePaths: options.ignorePaths
  });

  const primary =
    options.format === "json"
      ? JSON.stringify(report, null, 2)
      : options.format === "sarif"
        ? formatCloudIdentityReportAsSarif(report)
        : formatCloudIdentityMarkdownSummary(report);

  if (options.outputFile) {
    await fs.mkdir(path.dirname(options.outputFile), { recursive: true });
    await fs.writeFile(options.outputFile, `${primary}\n`, "utf8");
  } else {
    console.log(primary);
  }

  if (options.sarifFile) {
    const sarif =
      options.format === "sarif" ? primary : formatCloudIdentityReportAsSarif(report);
    await fs.mkdir(path.dirname(options.sarifFile), { recursive: true });
    await fs.writeFile(options.sarifFile, `${sarif}\n`, "utf8");
  }

  return report.policyEvaluation.exitCode;
}

const argv1 = process.argv[1] ?? "";
const isMain =
  argv1.endsWith("cli.ts") ||
  argv1.endsWith("cli.js") ||
  argv1.endsWith("indicative-cloud-identity");
if (isMain) {
  runCloudIdentityCli(parseCloudIdentityCliArgs(process.argv.slice(2)))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error("[indicative/cloud-identity] CLI error:", (err as Error).message);
      process.exit(2);
    });
}
