import fs from "node:fs/promises";
import path from "node:path";

export interface WorkspaceLimits {
  maxBytes: number;
  maxFiles: number;
}

export interface WorkspaceSanitizationReport {
  fileCount: number;
  totalBytes: number;
  removedSymlinks: string[];
  suspiciousFilenames: string[];
  exceededFileLimit: boolean;
  exceededSizeLimit: boolean;
  warnings: string[];
}

/**
 * Validates that a candidate relative or absolute path resolves strictly inside workspaceRoot.
 * Rejects path traversal, null bytes, and drive-prefix escapes.
 */
export function validateSafePathWithinRoot(rootDir: string, targetPath: string): string {
  if (!targetPath || targetPath.includes("\0")) {
    throw new Error("SECURITY_PATH_ERROR: Path contains invalid null byte or is empty.");
  }
  const resolvedRoot = path.resolve(rootDir);
  const resolvedTarget = path.resolve(resolvedRoot, targetPath);

  const relative = path.relative(resolvedRoot, resolvedTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(
      `SECURITY_PATH_TRAVERSAL: Path "${targetPath}" escapes allowed workspace root.`
    );
  }
  return resolvedTarget;
}

/**
 * Normalizes a finding file path into a clean forward-slash relative path inside the repository.
 */
export function normalizeRepoRelativePath(workspaceRoot: string, rawFilePath: string): string {
  const cleaned = rawFilePath.replace(/\0/g, "").trim();
  const resolvedRoot = path.resolve(workspaceRoot);

  let rel: string;
  if (path.isAbsolute(cleaned) || /^[A-Za-z]:[\\/]/.test(cleaned)) {
    const resolvedFile = path.resolve(cleaned);
    if (
      process.platform === "win32" &&
      resolvedFile.toLowerCase().startsWith(resolvedRoot.toLowerCase())
    ) {
      rel = resolvedFile.slice(resolvedRoot.length).replace(/^[\\/]+/, "");
    } else {
      rel = path.relative(resolvedRoot, resolvedFile);
    }
  } else {
    rel = cleaned;
  }

  const normalized = path.posix
    .normalize(rel.replace(/\\/g, "/"))
    .replace(/^\/+/, "")
    .replace(/^\.\//, "");

  if (normalized.startsWith("..")) {
    throw new Error(`SECURITY_PATH_TRAVERSAL: Invalid relative path "${rawFilePath}".`);
  }
  return normalized;
}

/**
 * Inspects an untrusted workspace directory before scanner execution:
 * - Removes symlinks pointing outside the workspace root (or broken symlinks)
 * - Flags potentially malicious filenames (leading dash option injection, control chars, shell metachars)
 * - Enforces maximum file count and total size bounds
 */
export async function sanitizeUntrustedWorkspace(
  workspaceRoot: string,
  limits: WorkspaceLimits
): Promise<WorkspaceSanitizationReport> {
  const resolvedRoot = path.resolve(workspaceRoot);
  const realRoot = await fs.realpath(resolvedRoot);

  const report: WorkspaceSanitizationReport = {
    fileCount: 0,
    totalBytes: 0,
    removedSymlinks: [],
    suspiciousFilenames: [],
    exceededFileLimit: false,
    exceededSizeLimit: false,
    warnings: []
  };

  async function walk(currentDir: string): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(resolvedRoot, fullPath).replace(/\\/g, "/");

      // Flag suspicious filenames (option injection, control chars, shell metachars)
      if (
        entry.name.startsWith("-") ||
        /[\x00-\x1f\x7f;|$`<>]/.test(entry.name)
      ) {
        report.suspiciousFilenames.push(relPath);
      }

      const stat = await fs.lstat(fullPath);
      if (stat.isSymbolicLink()) {
        let shouldRemove = false;
        try {
          const targetReal = await fs.realpath(fullPath);
          const relTarget = path.relative(realRoot, targetReal);
          if (relTarget.startsWith("..") || path.isAbsolute(relTarget)) {
            shouldRemove = true;
          }
        } catch {
          // Broken or cyclic symlink — remove safely
          shouldRemove = true;
        }

        if (shouldRemove) {
          await fs.unlink(fullPath);
          report.removedSymlinks.push(relPath);
          report.warnings.push(
            `Removed unsafe or escaping symbolic link prior to scanning: ${relPath}`
          );
        }
        continue;
      }

      if (stat.isDirectory()) {
        await walk(fullPath);
      } else if (stat.isFile()) {
        report.fileCount += 1;
        report.totalBytes += stat.size;

        if (report.fileCount > limits.maxFiles) {
          report.exceededFileLimit = true;
          report.warnings.push(
            `Repository exceeded maximum file limit (${limits.maxFiles} files).`
          );
          return;
        }
        if (report.totalBytes > limits.maxBytes) {
          report.exceededSizeLimit = true;
          report.warnings.push(
            `Repository exceeded maximum size limit (${Math.round(limits.maxBytes / (1024 * 1024))} MB).`
          );
          return;
        }
      }
    }
  }

  await walk(resolvedRoot);
  return report;
}

/**
 * Safely deletes an ephemeral directory only if it resides strictly beneath allowedRoot.
 */
export async function safeRemoveEphemeralDir(
  dirPath: string,
  allowedRoot: string
): Promise<void> {
  const resolvedRoot = path.resolve(allowedRoot);
  const resolvedTarget = path.resolve(dirPath);
  const rel = path.relative(resolvedRoot, resolvedTarget);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(
      `SECURITY_PATH_ERROR: Refusing to delete directory outside allowed ephemeral root.`
    );
  }
  await fs.rm(resolvedTarget, { recursive: true, force: true });
}
