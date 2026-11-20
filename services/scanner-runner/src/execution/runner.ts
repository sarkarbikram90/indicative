import type {
  ScannerExecutionResult,
  ScannerHealth,
  ScannerLimitation
} from "@indicative/contracts";
import { createRedactingLogger, type StructuredLogger } from "@indicative/security";
import type { ScannerAdapterRegistry } from "../adapters/registry.js";
import {
  inspectAndSanitizeScanWorkspace,
  type PreparedWorkspace
} from "../isolation/workspaceGuard.js";
import type { ScannerResourceLimits } from "../resource-limits/limits.js";

export interface RunnerExecutionRequest {
  scanId: string;
  organizationId: string;
  projectId: string;
  workspacePath: string;
  scanners: string[];
  secretFingerprintKey: string;
  signal?: AbortSignal;
}

export interface RunnerExecutionResponse {
  scanId: string;
  workspaceSummary: {
    fileCount: number;
    totalBytes: number;
    hasGitHistory: boolean;
    isShallowClone: boolean;
    removedSymlinksCount: number;
    suspiciousFilenamesCount: number;
  };
  limitations: ScannerLimitation[];
  results: ScannerExecutionResult[];
}

export class IsolatedScannerRunner {
  private readonly registry: ScannerAdapterRegistry;
  private readonly workspacesRoot: string;
  private readonly limits: ScannerResourceLimits;
  private readonly logger: StructuredLogger;

  constructor(options: {
    registry: ScannerAdapterRegistry;
    workspacesRoot: string;
    limits: ScannerResourceLimits;
    logger?: StructuredLogger;
  }) {
    this.registry = options.registry;
    this.workspacesRoot = options.workspacesRoot;
    this.limits = options.limits;
    this.logger =
      options.logger ?? createRedactingLogger({ service: "scanner-runner", level: "info" });
  }

  async healthCheck(): Promise<{ ok: boolean; scanners: ScannerHealth[] }> {
    const scanners = await this.registry.checkAllHealth();
    return {
      ok: scanners.some((s) => s.available),
      scanners
    };
  }

  async executeScan(request: RunnerExecutionRequest): Promise<RunnerExecutionResponse> {
    const log = this.logger.child({
      scanId: request.scanId,
      organizationId: request.organizationId
    });

    const prepared: PreparedWorkspace = await inspectAndSanitizeScanWorkspace({
      workspacesRoot: this.workspacesRoot,
      workspacePath: request.workspacePath,
      limits: this.limits
    });

    const limitations: ScannerLimitation[] = [];

    if (prepared.sanitization.removedSymlinks.length > 0) {
      limitations.push({
        code: "UNSAFE_SYMLINKS_REMOVED",
        message: `Removed ${prepared.sanitization.removedSymlinks.length} unsafe/escaping symbolic links before scanning.`,
        scopeAffected: "workspace"
      });
    }

    if (prepared.sanitization.exceededFileLimit) {
      limitations.push({
        code: "MAX_FILES_EXCEEDED",
        message: `Repository exceeded configured file ceiling (${this.limits.maxFilesPerScan} files); scan rejected for safety.`,
        scopeAffected: "entire_repository"
      });
    }

    if (prepared.sanitization.exceededSizeLimit) {
      limitations.push({
        code: "MAX_REPO_SIZE_EXCEEDED",
        message: `Repository exceeded configured size ceiling (${Math.round(this.limits.maxRepoSizeBytes / (1024 * 1024))} MB); scan rejected for safety.`,
        scopeAffected: "entire_repository"
      });
    }

    // Refuse execution if workspace exceeds configured hard size or file limits
    if (
      prepared.sanitization.exceededFileLimit ||
      prepared.sanitization.exceededSizeLimit
    ) {
      const now = new Date().toISOString();
      return {
        scanId: request.scanId,
        workspaceSummary: {
          fileCount: prepared.sanitization.fileCount,
          totalBytes: prepared.sanitization.totalBytes,
          hasGitHistory: prepared.hasGitHistory,
          isShallowClone: prepared.isShallowClone,
          removedSymlinksCount: prepared.sanitization.removedSymlinks.length,
          suspiciousFilenamesCount: prepared.sanitization.suspiciousFilenames.length
        },
        limitations,
        results: request.scanners.map((scanner) => ({
          scanner,
          scannerVersion: "unknown",
          capabilities: [],
          status: "FAILED",
          errorClass: "RESOURCE_LIMIT",
          errorMessage: limitations.map((l) => l.message).join(" "),
          exitCode: null,
          startedAt: now,
          completedAt: now,
          durationMs: 0,
          limitations,
          findings: []
        }))
      };
    }

    // Overall scan timeout controller
    const scanAbort = new AbortController();
    const overallTimer = setTimeout(() => scanAbort.abort(), this.limits.maxScanDurationMs);
    overallTimer.unref();

    const onParentAbort = () => scanAbort.abort();
    if (request.signal) {
      if (request.signal.aborted) scanAbort.abort();
      else request.signal.addEventListener("abort", onParentAbort, { once: true });
    }

    try {
      const results = await Promise.all(
        request.scanners.map(async (scannerName): Promise<ScannerExecutionResult> => {
          const adapter = this.registry.get(scannerName);
          const now = new Date().toISOString();
          if (!adapter) {
            return {
              scanner: scannerName,
              scannerVersion: "unknown",
              capabilities: [],
              status: "UNAVAILABLE",
              errorClass: "BINARY_NOT_FOUND",
              errorMessage: `Scanner adapter "${scannerName}" is not registered.`,
              exitCode: null,
              startedAt: now,
              completedAt: now,
              durationMs: 0,
              limitations: [],
              findings: []
            };
          }

          log.info("Starting scanner execution", { scanner: scannerName });
          const res = await adapter.execute({
            scanId: request.scanId,
            organizationId: request.organizationId,
            projectId: request.projectId,
            workspacePath: prepared.workspacePath,
            hasGitHistory: prepared.hasGitHistory,
            isShallowClone: prepared.isShallowClone,
            maxGitHistoryCommits: this.limits.maxGitHistoryCommits,
            timeoutMs: this.limits.scannerTimeoutMs,
            secretFingerprintKey: request.secretFingerprintKey,
            signal: scanAbort.signal
          });
          log.info("Finished scanner execution", {
            scanner: scannerName,
            status: res.status,
            findingsCount: res.findings.length,
            durationMs: res.durationMs
          });
          return res;
        })
      );

      for (const r of results) {
        limitations.push(...r.limitations);
      }

      return {
        scanId: request.scanId,
        workspaceSummary: {
          fileCount: prepared.sanitization.fileCount,
          totalBytes: prepared.sanitization.totalBytes,
          hasGitHistory: prepared.hasGitHistory,
          isShallowClone: prepared.isShallowClone,
          removedSymlinksCount: prepared.sanitization.removedSymlinks.length,
          suspiciousFilenamesCount: prepared.sanitization.suspiciousFilenames.length
        },
        limitations,
        results
      };
    } finally {
      clearTimeout(overallTimer);
      if (request.signal) {
        request.signal.removeEventListener("abort", onParentAbort);
      }
    }
  }
}
