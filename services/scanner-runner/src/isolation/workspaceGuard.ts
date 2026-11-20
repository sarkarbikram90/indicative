import fs from "node:fs/promises";
import path from "node:path";
import {
  safeRemoveEphemeralDir,
  sanitizeUntrustedWorkspace,
  validateSafePathWithinRoot,
  type WorkspaceSanitizationReport
} from "@indicative/security";
import type { ScannerResourceLimits } from "../resource-limits/limits.js";

export interface PreparedWorkspace {
  workspacePath: string;
  hasGitHistory: boolean;
  isShallowClone: boolean;
  sanitization: WorkspaceSanitizationReport;
}

export async function inspectAndSanitizeScanWorkspace(params: {
  workspacesRoot: string;
  workspacePath: string;
  limits: ScannerResourceLimits;
}): Promise<PreparedWorkspace> {
  const validatedPath = validateSafePathWithinRoot(
    params.workspacesRoot,
    params.workspacePath
  );

  const stat = await fs.stat(validatedPath);
  if (!stat.isDirectory()) {
    throw new Error("INVALID_WORKSPACE: Target workspace path is not a directory.");
  }

  const sanitization = await sanitizeUntrustedWorkspace(validatedPath, {
    maxBytes: params.limits.maxRepoSizeBytes,
    maxFiles: params.limits.maxFilesPerScan
  });

  let hasGitHistory = false;
  let isShallowClone = false;
  try {
    const gitDir = path.join(validatedPath, ".git");
    const gitStat = await fs.stat(gitDir);
    hasGitHistory = gitStat.isDirectory();
    if (hasGitHistory) {
      try {
        await fs.access(path.join(gitDir, "shallow"));
        isShallowClone = true;
      } catch {
        isShallowClone = false;
      }
    }
  } catch {
    hasGitHistory = false;
  }

  return {
    workspacePath: validatedPath,
    hasGitHistory,
    isShallowClone,
    sanitization
  };
}

export async function cleanupScanWorkspace(
  workspacePath: string,
  workspacesRoot: string
): Promise<void> {
  await safeRemoveEphemeralDir(workspacePath, workspacesRoot);
}
