#!/usr/bin/env node
import { build } from "esbuild";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const outDir = path.join(repoRoot, "action-dist");
const outFile = path.join(outDir, "cicd-cli.cjs");

await fs.mkdir(outDir, { recursive: true });

await build({
  entryPoints: [path.join(repoRoot, "packages", "cicd-security", "src", "cli.ts")],
  outfile: outFile,
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  minify: false,
  sourcemap: false,
  legalComments: "linked",
  logLevel: "info"
});

const stat = await fs.stat(outFile);
console.log(
  `Bundled standalone Indicative CI/CD CLI to ${path.relative(repoRoot, outFile)} (${(stat.size / 1024).toFixed(1)} KiB)`
);
