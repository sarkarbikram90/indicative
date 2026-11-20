import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface MaterializedSecretFixtures {
  dummyAwsKey: string;
  dummyGithubPat: string;
  dummyPrivateKeyLine: string;
  dummyDbPassword: string;
}

export interface MaterializedCorpusRepo {
  repoPath: string;
  secrets: MaterializedSecretFixtures;
  applyRemediationCommit(): Promise<string>;
  cleanup(): Promise<void>;
}

async function copyRecursive(src: string, dest: string): Promise<void> {
  await fs.mkdir(dest, { recursive: true });
  const entries = await fs.readdir(src, { withFileTypes: true });
  for (const entry of entries) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      await copyRecursive(s, d);
    } else if (entry.isFile()) {
      await fs.copyFile(s, d);
    }
  }
}

async function runGit(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, {
    cwd,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Indicative Test Corpus",
      GIT_AUTHOR_EMAIL: "corpus@indicative.local",
      GIT_COMMITTER_NAME: "Indicative Test Corpus",
      GIT_COMMITTER_EMAIL: "corpus@indicative.local"
    }
  });
  return stdout.trim();
}

/**
 * Generates 100% synthetic dummy test credentials dynamically at test runtime
 * so real secrets never exist and static patterns are never committed to Indicative's own repo.
 */
export function buildSyntheticDummySecrets(): MaterializedSecretFixtures {
  const dummyAwsKey = ["AKIA", "QYLPMN5HHHFPZAM2"].join("");
  const dummyGithubPat = [
    "ghp_",
    "9xK4mN7pQ2rS5tU8vW1yZ3aB6cD0eF4gH7jK"
  ].join("");
  const dummyDbPassword = ["SuperDummy", "DbPass", "948271!"].join("");
  const pemBody = crypto.randomBytes(64).toString("base64");
  const dummyPrivateKeyLine = pemBody.slice(0, 32);

  return {
    dummyAwsKey,
    dummyGithubPat,
    dummyPrivateKeyLine,
    dummyDbPassword
  };
}

/**
 * Materializes a real Git repository with multi-commit history for regression & E2E testing:
 * - Commit 1: Adds historical dummy GitHub PAT (in config/legacy-removed.env) & dummy RSA key
 * - Commit 2: Deletes config/legacy-removed.env (testing removed secret still in Git history!)
 *             and adds current working-tree dummy AWS key + duplicated copy in another file
 * - Commit 3: Copies static SAST (JS/TS + Python), SCA (vulnerable package-lock.json), and IaC
 *             (Dockerfile + Kubernetes + Terraform) fixtures
 */
export async function materializeVulnerableGitRepo(
  baseTmpDir: string
): Promise<MaterializedCorpusRepo> {
  const repoPath = path.join(
    baseTmpDir,
    `corpus-vuln-${crypto.randomBytes(6).toString("hex")}`
  );
  await fs.mkdir(repoPath, { recursive: true });

  const secrets = buildSyntheticDummySecrets();
  const staticFixtureDir = path.resolve(process.cwd(), "tests/fixtures/vulnerable-app");

  await runGit(repoPath, ["init", "-b", "main"]);
  await runGit(repoPath, ["config", "user.name", "Indicative Test Corpus"]);
  await runGit(repoPath, ["config", "user.email", "corpus@indicative.local"]);

  // Commit 1: Historical secret that will be removed in Commit 2 + private key fixture
  await fs.mkdir(path.join(repoPath, "config"), { recursive: true });
  await fs.mkdir(path.join(repoPath, "keys"), { recursive: true });

  await fs.writeFile(
    path.join(repoPath, "config", "legacy-removed.env"),
    `# Dummy test fixture only\nGITHUB_TOKEN=${secrets.dummyGithubPat}\nDATABASE_URL=postgresql://admin:${secrets.dummyDbPassword}@db.internal:5432/app\n`,
    "utf8"
  );

  const { privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const pemLines = privateKey.trim().split(/\r?\n/);
  const dummyPrivateKeyLine = pemLines[1] ?? "";

  await fs.writeFile(path.join(repoPath, "keys", "service-key.pem"), privateKey, "utf8");
  secrets.dummyPrivateKeyLine = dummyPrivateKeyLine;

  await runGit(repoPath, ["add", "."]);
  await runGit(repoPath, ["commit", "-m", "chore: initial config with legacy credentials"]);

  // Commit 2: Remove legacy-removed.env (remains in git history!) and add current-tree secret
  await fs.rm(path.join(repoPath, "config", "legacy-removed.env"));
  await fs.writeFile(
    path.join(repoPath, "config", "current.env"),
    `# Dummy test fixture only\nAWS_ACCESS_KEY_ID=${secrets.dummyAwsKey}\n`,
    "utf8"
  );
  // Second occurrence of exact same AWS dummy key in a second file to verify cross-file correlation!
  await fs.writeFile(
    path.join(repoPath, "config", "backup.env"),
    `BACKUP_AWS_KEY=${secrets.dummyAwsKey}\n`,
    "utf8"
  );

  await runGit(repoPath, ["add", "-A"]);
  await runGit(repoPath, ["commit", "-m", "chore: remove legacy env and add current config"]);

  // Commit 3: Copy SAST/SCA/IaC vulnerable fixtures + benign false-positive example
  await copyRecursive(staticFixtureDir, repoPath);
  await fs.writeFile(
    path.join(repoPath, "config", "false-positive-example.ts"),
    `export const DOC_EXAMPLE = { PLACEHOLDER_KEY: "example-not-a-real-secret" };\n`,
    "utf8"
  );

  await runGit(repoPath, ["add", "-A"]);
  await runGit(repoPath, ["commit", "-m", "feat: add application code and infra fixtures"]);

  return {
    repoPath,
    secrets,
    async applyRemediationCommit() {
      // Fix JS SQL injection & eval & weak hash in src/vulnerable.ts
      const fixedTs = [
        'import crypto from "node:crypto";',
        "",
        "export function findUserSafe(db: { query: (sql: string, p: unknown[]) => Promise<unknown> }, userId: string) {",
        '  return db.query("SELECT id, email FROM users WHERE id = $1", [userId]);',
        "}",
        "",
        "export function strongPasswordDigest(input: string): string {",
        '  return crypto.createHash("sha256").update(input).digest("hex");',
        "}"
      ].join("\n");
      await fs.writeFile(path.join(repoPath, "src", "vulnerable.ts"), fixedTs, "utf8");
      await runGit(repoPath, ["add", "src/vulnerable.ts"]);
      await runGit(repoPath, ["commit", "-m", "fix(security): remediate JS SAST findings"]);
      return runGit(repoPath, ["rev-parse", "HEAD"]);
    },
    async cleanup() {
      await fs.rm(repoPath, { recursive: true, force: true });
    }
  };
}

export async function materializeCleanGitRepo(
  baseTmpDir: string
): Promise<{ repoPath: string; cleanup(): Promise<void> }> {
  const repoPath = path.join(
    baseTmpDir,
    `corpus-clean-${crypto.randomBytes(6).toString("hex")}`
  );
  const staticCleanDir = path.resolve(process.cwd(), "tests/fixtures/clean-app");
  await copyRecursive(staticCleanDir, repoPath);
  await runGit(repoPath, ["init", "-b", "main"]);
  await runGit(repoPath, ["config", "user.name", "Indicative Clean Corpus"]);
  await runGit(repoPath, ["config", "user.email", "clean@indicative.local"]);
  await runGit(repoPath, ["add", "-A"]);
  await runGit(repoPath, ["commit", "-m", "chore: clean baseline repository"]);

  return {
    repoPath,
    async cleanup() {
      await fs.rm(repoPath, { recursive: true, force: true });
    }
  };
}
