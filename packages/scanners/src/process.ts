import { spawn } from "node:child_process";
import path from "node:path";
import type { ScannerErrorClass } from "@indicative/contracts";

const ALLOWED_BINARY_BASENAMES = new Set([
  "semgrep",
  "semgrep.exe",
  "trivy",
  "trivy.exe",
  "gitleaks",
  "gitleaks.exe",
  "git",
  "git.exe",
  "docker",
  "docker.exe"
]);

export interface SafeExecOptions {
  binary: string;
  args: string[];
  cwd?: string;
  timeoutMs: number;
  maxOutputBytes?: number;
  extraEnv?: Record<string, string>;
  signal?: AbortSignal;
}

export interface SafeExecResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  cancelled: boolean;
  durationMs: number;
  spawnErrorCode?: string;
  spawnErrorMessage?: string;
}

/**
 * Validates that the requested executable matches Indicative's strict binary allowlist.
 */
export function assertApprovedBinary(binaryPath: string): void {
  const base = path.basename(binaryPath).toLowerCase();
  if (!ALLOWED_BINARY_BASENAMES.has(base)) {
    throw new Error(
      `SECURITY_DISALLOWED_BINARY: Refusing to spawn unapproved executable "${base}".`
    );
  }
}

/**
 * Constructs a stripped environment for scanner child processes so that
 * control-plane secrets (GitHub tokens, DB URLs, AI keys, session keys, cloud creds)
 * are NEVER inherited by untrusted scanner executions.
 */
export function buildSanitizedScannerEnv(
  extraEnv: Record<string, string> = {}
): NodeJS.ProcessEnv {
  const safeKeys = [
    "PATH",
    "Path",
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "LOCALAPPDATA",
    "APPDATA",
    "LANG",
    "LC_ALL",
    "PYTHONIOENCODING"
  ];
  const env: NodeJS.ProcessEnv = {
    PYTHONUTF8: "1",
    PYTHONIOENCODING: "utf-8",
    SEMGREP_SEND_METRICS: "off",
    TRIVY_NO_PROGRESS: "true"
  };

  for (const key of safeKeys) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key];
    }
  }

  // On Windows, ensure user Python Scripts dir and winget Links dir are searchable if present
  if (process.platform === "win32") {
    const extraPaths: string[] = [];
    if (process.env.APPDATA) {
      extraPaths.push(path.join(process.env.APPDATA, "Python", "Python314", "Scripts"));
      extraPaths.push(path.join(process.env.APPDATA, "Python", "Python313", "Scripts"));
      extraPaths.push(path.join(process.env.APPDATA, "Python", "Python312", "Scripts"));
    }
    if (process.env.LOCALAPPDATA) {
      extraPaths.push(path.join(process.env.LOCALAPPDATA, "Microsoft", "WinGet", "Links"));
    }
    const existingPath = env.PATH ?? env.Path ?? "";
    const combined = [existingPath, ...extraPaths].filter(Boolean).join(";");
    env.PATH = combined;
    env.Path = combined;
  }

  return { ...env, ...extraEnv };
}

/**
 * Spawns an approved binary WITHOUT shell interpolation (shell: false),
 * enforcing timeout, AbortSignal cancellation, and bounded stdout/stderr buffers.
 */
export async function safeSpawnBinary(options: SafeExecOptions): Promise<SafeExecResult> {
  assertApprovedBinary(options.binary);

  const start = Date.now();
  const maxBytes = options.maxOutputBytes ?? 16 * 1024 * 1024; // 16 MB cap
  const env = buildSanitizedScannerEnv(options.extraEnv);

  return new Promise<SafeExecResult>((resolve) => {
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let cancelled = false;
    let settled = false;

    const child = spawn(options.binary, options.args, {
      cwd: options.cwd,
      env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });

    const finish = (
      exitCode: number | null,
      spawnErrorCode?: string,
      spawnErrorMessage?: string
    ) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (options.signal) {
        options.signal.removeEventListener("abort", onAbort);
      }
      resolve({
        exitCode,
        stdout,
        stderr,
        timedOut,
        cancelled,
        durationMs: Date.now() - start,
        spawnErrorCode,
        spawnErrorMessage
      });
    };

    const killChild = () => {
      try {
        child.kill("SIGTERM");
        setTimeout(() => {
          try {
            if (!child.killed) child.kill("SIGKILL");
          } catch {
            // ignore
          }
        }, 1500).unref();
      } catch {
        // ignore
      }
    };

    const onAbort = () => {
      cancelled = true;
      killChild();
    };

    if (options.signal) {
      if (options.signal.aborted) {
        cancelled = true;
        killChild();
      } else {
        options.signal.addEventListener("abort", onAbort, { once: true });
      }
    }

    const timer = setTimeout(() => {
      timedOut = true;
      killChild();
    }, options.timeoutMs);
    timer.unref();

    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdoutBytes < maxBytes) {
        const remaining = maxBytes - stdoutBytes;
        const slice = chunk.subarray(0, remaining);
        stdout += slice.toString("utf8");
        stdoutBytes += slice.byteLength;
      }
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderrBytes < maxBytes) {
        const remaining = maxBytes - stderrBytes;
        const slice = chunk.subarray(0, remaining);
        stderr += slice.toString("utf8");
        stderrBytes += slice.byteLength;
      }
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      finish(null, err.code, err.message);
    });

    child.on("close", (code) => {
      finish(code);
    });
  });
}

export function classifyProcessError(result: SafeExecResult): ScannerErrorClass {
  if (result.cancelled) return "CANCELLED";
  if (result.timedOut) return "TIMEOUT";
  if (result.spawnErrorCode === "ENOENT") return "BINARY_NOT_FOUND";
  if (
    result.stderr.toLowerCase().includes("cannot download") ||
    result.stderr.toLowerCase().includes("db error") ||
    result.stderr.toLowerCase().includes("vulnerability db")
  ) {
    return "OFFLINE_DB_MISSING";
  }
  if (
    result.stderr.toLowerCase().includes("out of memory") ||
    result.stderr.toLowerCase().includes("cannot allocate memory")
  ) {
    return "RESOURCE_LIMIT";
  }
  return "EXECUTION_ERROR";
}
