export type SandboxRuntimeProfile = "local-process" | "docker" | "gvisor" | "kata";

export interface SandboxRuntimeDescriptor {
  runtime: SandboxRuntimeProfile;
  ociRuntimeFlag?: string;
  productionMultiTenantReady: boolean;
  isolationSummary: string;
}

export function describeSandboxRuntime(
  runtime: SandboxRuntimeProfile
): SandboxRuntimeDescriptor {
  switch (runtime) {
    case "gvisor":
      return {
        runtime: "gvisor",
        ociRuntimeFlag: "runsc",
        productionMultiTenantReady: true,
        isolationSummary:
          "gVisor (runsc) user-space kernel sandbox with no-egress networking, read-only rootfs, and dropped capabilities."
      };
    case "kata":
      return {
        runtime: "kata",
        ociRuntimeFlag: "kata-runtime",
        productionMultiTenantReady: true,
        isolationSummary:
          "Kata Containers hardware-virtualized microVM isolation with dedicated guest kernel and no-egress networking."
      };
    case "docker":
      return {
        runtime: "docker",
        productionMultiTenantReady: false,
        isolationSummary:
          "Hardened Docker container (non-root, read-only rootfs, cap-drop ALL, internal no-egress network). Local/single-tenant only — shared host kernel is NOT sufficient for untrusted multi-tenant SaaS."
      };
    case "local-process":
    default:
      return {
        runtime: "local-process",
        productionMultiTenantReady: false,
        isolationSummary:
          "Local isolated process runner (stripped env, allowlisted binaries, workspace sanitization, timeouts). Development/testing only."
      };
  }
}

export interface ScannerResourceLimits {
  maxRepoSizeBytes: number;
  maxFilesPerScan: number;
  maxReportBytes: number;
  scannerTimeoutMs: number;
  maxScanDurationMs: number;
  maxGitHistoryCommits: number;
  containerMemoryLimit: string;
  containerCpuLimit: string;
  containerPidsLimit: number;
  nonRootUidGid: string;
  sandboxRuntime: SandboxRuntimeProfile;
}

export function createResourceLimits(
  options?: Partial<ScannerResourceLimits>
): ScannerResourceLimits {
  return {
    maxRepoSizeBytes: options?.maxRepoSizeBytes ?? 250 * 1024 * 1024,
    maxFilesPerScan: options?.maxFilesPerScan ?? 25_000,
    maxReportBytes: options?.maxReportBytes ?? 64 * 1024 * 1024,
    scannerTimeoutMs: options?.scannerTimeoutMs ?? 120_000,
    maxScanDurationMs: options?.maxScanDurationMs ?? 300_000,
    maxGitHistoryCommits: options?.maxGitHistoryCommits ?? 5_000,
    containerMemoryLimit: options?.containerMemoryLimit ?? "1g",
    containerCpuLimit: options?.containerCpuLimit ?? "1.0",
    containerPidsLimit: options?.containerPidsLimit ?? 256,
    nonRootUidGid: options?.nonRootUidGid ?? "10001:10001",
    sandboxRuntime: options?.sandboxRuntime ?? "local-process"
  };
}

/**
 * Generates hardened OCI container arguments for running a single untrusted scanner job
 * in an isolated container or microVM/gVisor sandbox (no network, read-only rootfs,
 * dropped capabilities, non-root, optional gVisor/Kata runtime and seccomp profile).
 * Never mounts Docker sockets or host credentials.
 */
export function buildHardenedOciArgs(params: {
  image: string;
  workspaceHostPath: string;
  limits: ScannerResourceLimits;
  command: string[];
  seccompProfilePath?: string;
}): string[] {
  const runtimeInfo = describeSandboxRuntime(params.limits.sandboxRuntime);
  const args: string[] = ["run", "--rm"];

  if (runtimeInfo.ociRuntimeFlag) {
    args.push(`--runtime=${runtimeInfo.ociRuntimeFlag}`);
  }

  args.push(
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true"
  );

  if (params.seccompProfilePath) {
    args.push(`--security-opt=seccomp=${params.seccompProfilePath}`);
  }

  args.push(
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
  );

  return args;
}
