export interface ScannerResourceLimits {
  maxRepoSizeBytes: number;
  maxFilesPerScan: number;
  scannerTimeoutMs: number;
  maxScanDurationMs: number;
  maxGitHistoryCommits: number;
  containerMemoryLimit: string;
  containerCpuLimit: string;
  containerPidsLimit: number;
  nonRootUidGid: string;
}

export function createResourceLimits(options?: Partial<ScannerResourceLimits>): ScannerResourceLimits {
  return {
    maxRepoSizeBytes: options?.maxRepoSizeBytes ?? 250 * 1024 * 1024,
    maxFilesPerScan: options?.maxFilesPerScan ?? 25_000,
    scannerTimeoutMs: options?.scannerTimeoutMs ?? 120_000,
    maxScanDurationMs: options?.maxScanDurationMs ?? 300_000,
    maxGitHistoryCommits: options?.maxGitHistoryCommits ?? 5_000,
    containerMemoryLimit: options?.containerMemoryLimit ?? "1g",
    containerCpuLimit: options?.containerCpuLimit ?? "1.0",
    containerPidsLimit: options?.containerPidsLimit ?? 256,
    nonRootUidGid: options?.nonRootUidGid ?? "10001:10001"
  };
}

/**
 * Generates hardened OCI container arguments for running a single untrusted scanner job
 * in an isolated container (no network, read-only rootfs, dropped capabilities, non-root).
 * Never mounts Docker sockets or host credentials.
 */
export function buildHardenedOciArgs(params: {
  image: string;
  workspaceHostPath: string;
  limits: ScannerResourceLimits;
  command: string[];
}): string[] {
  return [
    "run",
    "--rm",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    `--user=${params.limits.nonRootUidGid}`,
    `--memory=${params.limits.containerMemoryLimit}`,
    `--cpus=${params.limits.containerCpuLimit}`,
    `--pids-limit=${params.limits.containerPidsLimit}`,
    "--tmpfs=/tmp:rw,noexec,nosuid,size=256m",
    "-v",
    `${params.workspaceHostPath}:/workspace:ro`,
    "-w",
    "/workspace",
    params.image,
    ...params.command
  ];
}
