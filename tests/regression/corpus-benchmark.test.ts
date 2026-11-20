import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  createDefaultScannerRegistry,
  createResourceLimits,
  IsolatedScannerRunner
} from "@indicative/scanner-runner";
import { normalizeAndDeduplicateFindings } from "@indicative/findings";
import {
  materializeCleanGitRepo,
  materializeVulnerableGitRepo,
  type MaterializedCorpusRepo
} from "../fixtures/corpusBuilder.js";

interface ExpectedItem {
  id: string;
  scanner: string;
  category: string;
  ruleId?: string;
  packageName?: string;
  filePath?: string;
  lineStart?: number;
  exposureLocation?: string;
  mustRedactSecret: boolean;
}

describe("Security Regression Corpus — Measured Precision, Recall & False-Positive Baseline", () => {
  let tmpDir: string;
  let vulnRepo: MaterializedCorpusRepo;
  let cleanRepo: { repoPath: string; cleanup(): Promise<void> };
  let runner: IsolatedScannerRunner;

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ind-reg-"));
    vulnRepo = await materializeVulnerableGitRepo(tmpDir);
    cleanRepo = await materializeCleanGitRepo(tmpDir);

    runner = new IsolatedScannerRunner({
      registry: createDefaultScannerRegistry({
        semgrepBin: "semgrep",
        semgrepRulesDir: path.resolve(process.cwd(), "services/scanner-runner/rules/semgrep"),
        trivyBin: "trivy",
        trivyCacheDir: path.resolve(process.cwd(), ".trivy-cache"),
        trivyOfflineMode: true,
        gitleaksBin: "gitleaks"
      }),
      workspacesRoot: tmpDir,
      limits: createResourceLimits()
    });
  });

  afterAll(async () => {
    await vulnRepo.cleanup();
    await cleanRepo.cleanup();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("measures actual detection precision, recall, FPR, coverage, and zero parsing/scanner failures", async () => {
    const manifestPath = path.resolve(process.cwd(), "tests/fixtures/expected-manifest.json");
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
      fixtures: {
        "vulnerable-app": { expectedFindings: ExpectedItem[] };
        "clean-app": { expectedFindings: ExpectedItem[]; maxFalsePositivesAllowed: number };
      };
    };

    const masterKey = "regression-corpus-test-hmac-key-0123456789abcdef";

    const [vulnExec, cleanExec] = await Promise.all([
      runner.executeScan({
        scanId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1",
        organizationId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1",
        projectId: "cccccccc-cccc-cccc-cccc-ccccccccccc1",
        workspacePath: vulnRepo.repoPath,
        scanners: ["semgrep", "trivy", "gitleaks"],
        secretFingerprintKey: masterKey
      }),
      runner.executeScan({
        scanId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2",
        organizationId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1",
        projectId: "cccccccc-cccc-cccc-cccc-ccccccccccc2",
        workspacePath: cleanRepo.repoPath,
        scanners: ["semgrep", "trivy", "gitleaks"],
        secretFingerprintKey: masterKey
      })
    ]);

    const allRuns = [...vulnExec.results, ...cleanExec.results];
    const scannerExecutionFailures = allRuns.filter((r) => r.status !== "SUCCESS").length;
    const parsingFailures = allRuns.filter((r) => r.errorClass === "MALFORMED_OUTPUT").length;

    expect(scannerExecutionFailures).toBe(0);
    expect(parsingFailures).toBe(0);

    const vulnBundles = normalizeAndDeduplicateFindings({
      organizationId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1",
      projectId: "cccccccc-cccc-cccc-cccc-ccccccccccc1",
      scanId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1",
      rawFindings: vulnExec.results.flatMap((r) => r.findings)
    });

    const cleanBundles = normalizeAndDeduplicateFindings({
      organizationId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1",
      projectId: "cccccccc-cccc-cccc-cccc-ccccccccccc2",
      scanId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2",
      rawFindings: cleanExec.results.flatMap((r) => r.findings)
    });

    const expected = manifest.fixtures["vulnerable-app"].expectedFindings;
    let truePositives = 0;
    const missedIds: string[] = [];

    for (const exp of expected) {
      const matched = vulnBundles.some((b) => {
        const f = b.finding;
        if (f.scanner !== exp.scanner || f.category !== exp.category) return false;
        if (exp.ruleId && f.ruleId !== exp.ruleId) return false;
        if (exp.packageName && f.packageName !== exp.packageName) return false;
        if (
          exp.filePath &&
          !b.occurrences.some((o) => o.filePath === exp.filePath) &&
          f.filePath !== exp.filePath
        ) {
          return false;
        }
        return true;
      });

      if (matched) {
        truePositives += 1;
      } else {
        missedIds.push(exp.id);
      }
    }

    const falseNegatives = expected.length - truePositives;
    const cleanFalsePositives = cleanBundles.length;

    const recall = expected.length > 0 ? truePositives / expected.length : 1;
    const precision =
      truePositives + cleanFalsePositives > 0
        ? truePositives / (truePositives + cleanFalsePositives)
        : 1;
    const falsePositiveRate =
      cleanBundles.length === 0 ? 0 : cleanFalsePositives / (cleanFalsePositives + 1);

    // Emit measured benchmark metrics so they are captured accurately in test logs & documentation
    console.log(
      JSON.stringify(
        {
          benchmark: "indicative-security-regression-corpus",
          scanners: vulnExec.results.map((r) => ({
            scanner: r.scanner,
            version: r.scannerVersion,
            rulesetVersion: r.rulesetVersion,
            durationMs: r.durationMs,
            rawFindings: r.findings.length
          })),
          expectedTotal: expected.length,
          truePositives,
          falseNegatives,
          missedIds,
          vulnerableNormalizedFindingsTotal: vulnBundles.length,
          cleanRepoFalsePositives: cleanFalsePositives,
          precision: Number(precision.toFixed(4)),
          recall: Number(recall.toFixed(4)),
          falsePositiveRate: Number(falsePositiveRate.toFixed(4)),
          detectionCoverage: `${truePositives}/${expected.length}`,
          parsingFailures,
          scannerExecutionFailures
        },
        null,
        2
      )
    );

    // Redaction guarantee on regression corpus
    const serializedVuln = JSON.stringify(vulnBundles);
    expect(serializedVuln).not.toContain(vulnRepo.secrets.dummyAwsKey);
    expect(serializedVuln).not.toContain(vulnRepo.secrets.dummyGithubPat);
    expect(serializedVuln).not.toContain(vulnRepo.secrets.dummyPrivateKeyLine);

    expect(cleanFalsePositives).toBeLessThanOrEqual(
      manifest.fixtures["clean-app"].maxFalsePositivesAllowed
    );
    expect(recall).toBeGreaterThanOrEqual(0.95);
    expect(precision).toBe(1);
  });
});
