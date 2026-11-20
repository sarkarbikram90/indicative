import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { safeSpawnBinary } from "@indicative/scanners";
import {
  safeRemoveEphemeralDir,
  validateGitHubRepositorySlug,
  validateSafePathWithinRoot
} from "@indicative/security";
import type { GitHubAppClient } from "./githubApp.js";

export interface IngestionRequest {
  scanId: string;
  provider: "GITHUB" | "LOCAL_FIXTURE";
  repositoryFullName: string;
  branch: string;
  githubInstallationId?: number;
  localFixturePath?: string;
  workspacesRoot: string;
  timeoutMs: number;
  githubAppClient?: GitHubAppClient;
}

export interface IngestedRepository {
  workspacePath: string;
  branch: string;
  commitSha: string | null;
  commitMessage: string | null;
  hasGitHistory: boolean;
  isShallowClone: boolean;
  cleanup(): Promise<void>;
}

async function copyDirRecursive(src: string, dest: string): Promise<void> {
  await fs.mkdir(dest, { recursive: true });
  const entries = await fs.readdir(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    const stat = await fs.lstat(srcPath);
    if (stat.isSymbolicLink()) {
      const linkTarget = await fs.readlink(srcPath);
      await fs.symlink(linkTarget, destPath);
    } else if (stat.isDirectory()) {
      await copyDirRecursive(srcPath, destPath);
    } else if (stat.isFile()) {
      await fs.copyFile(srcPath, destPath);
    }
  }
}

async function readGitHeadMetadata(
  workspacePath: string
): Promise<{
  hasGitHistory: boolean;
  isShallowClone: boolean;
  commitSha: string | null;
  commitMessage: string | null;
  branch: string | null;
}> {
  const gitDir = path.join(workspacePath, ".git");
  try {
    const stat = await fs.stat(gitDir);
    if (!stat.isDirectory()) {
      return {
        hasGitHistory: false,
        isShallowClone: false,
        commitSha: null,
        commitMessage: null,
        branch: null
      };
    }
  } catch {
    return {
      hasGitHistory: false,
      isShallowClone: false,
      commitSha: null,
      commitMessage: null,
      branch: null
    };
  }

  let isShallowClone = false;
  try {
    await fs.access(path.join(gitDir, "shallow"));
    isShallowClone = true;
  } catch {
    isShallowClone = false;
  }

  const shaRes = await safeSpawnBinary({
    binary: "git",
    args: ["-C", workspacePath, "rev-parse", "HEAD"],
    timeoutMs: 10_000
  });
  const msgRes = await safeSpawnBinary({
    binary: "git",
    args: ["-C", workspacePath, "log", "-1", "--pretty=%s"],
    timeoutMs: 10_000
  });
  const branchRes = await safeSpawnBinary({
    binary: "git",
    args: ["-C", workspacePath, "rev-parse", "--abbrev-ref", "HEAD"],
    timeoutMs: 10_000
  });

  return {
    hasGitHistory: true,
    isShallowClone,
    commitSha: shaRes.exitCode === 0 ? shaRes.stdout.trim() : null,
    commitMessage: msgRes.exitCode === 0 ? msgRes.stdout.trim().slice(0, 200) : null,
    branch: branchRes.exitCode === 0 ? branchRes.stdout.trim() : null
  };
}

/**
 * Trusted repository ingestion boundary.
 * - Never accepts arbitrary user-supplied URLs.
 * - Uses short-lived GitHub App installation tokens passed via transient HTTP header
 *   so credentials are NEVER persisted in .git/config or logs.
 * - Preserves full Git history (no shallow clone) so Gitleaks can scan historical commits.
 */
export async function ingestRepositoryForScan(
  request: IngestionRequest
): Promise<IngestedRepository> {
  const slug = validateGitHubRepositorySlug(request.repositoryFullName);
  const resolvedRoot = path.resolve(request.workspacesRoot);
  await fs.mkdir(resolvedRoot, { recursive: true });

  const folderName = `scan-${request.scanId}-${crypto.randomBytes(6).toString("hex")}`;
  const workspacePath = validateSafePathWithinRoot(resolvedRoot, folderName);

  const cleanup = async () => {
    await safeRemoveEphemeralDir(workspacePath, resolvedRoot).catch(() => {});
  };

  try {
    if (request.provider === "LOCAL_FIXTURE") {
      if (!request.localFixturePath) {
        throw new Error("INGESTION_ERROR: Missing localFixturePath for LOCAL_FIXTURE repo.");
      }
      const resolvedFixture = path.resolve(request.localFixturePath);
      await copyDirRecursive(resolvedFixture, workspacePath);
    } else {
      if (!request.githubAppClient || !request.githubInstallationId) {
        throw new Error(
          "INGESTION_ERROR: GitHub App credentials and installationId are required to clone GitHub repositories."
        );
      }

      const { token } = await request.githubAppClient.createInstallationToken(
        request.githubInstallationId,
        [slug.fullName]
      );

      const basicAuth = Buffer.from(`x-access-token:${token}`, "utf8").toString("base64");
      const cloneUrl = `https://github.com/${slug.owner}/${slug.repo}.git`;

      // Harden git clone: disable hooks, fsmonitor, submodules, file:// protocol;
      // preserve full commit history (do NOT pass --depth 1) for historical secret scanning.
      const cloneArgs = [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "submodule.recurse=false",
        "-c",
        `http.https://github.com/.extraheader=AUTHORIZATION: basic ${basicAuth}`,
        "clone",
        "--no-tags",
        "--branch",
        request.branch,
        "--",
        cloneUrl,
        workspacePath
      ];

      const cloneRes = await safeSpawnBinary({
        binary: "git",
        args: cloneArgs,
        timeoutMs: request.timeoutMs
      });

      if (cloneRes.exitCode !== 0) {
        throw new Error(
          `INGESTION_CLONE_FAILED: Unable to clone ${slug.fullName}@${request.branch} (exit ${cloneRes.exitCode}).`
        );
      }
    }

    const gitMeta = await readGitHeadMetadata(workspacePath);

    return {
      workspacePath,
      branch: gitMeta.branch && gitMeta.branch !== "HEAD" ? gitMeta.branch : request.branch,
      commitSha: gitMeta.commitSha,
      commitMessage: gitMeta.commitMessage,
      hasGitHistory: gitMeta.hasGitHistory,
      isShallowClone: gitMeta.isShallowClone,
      cleanup
    };
  } catch (err) {
    await cleanup();
    throw err;
  }
}
