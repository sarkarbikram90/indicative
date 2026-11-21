import fs from "node:fs/promises";

export const DEFAULT_MAX_SCANNER_REPORT_BYTES = 64 * 1024 * 1024; // 64 MB

export class ScannerReportSizeExceededError extends Error {
  public readonly actualBytes: number;
  public readonly maxBytes: number;

  constructor(actualBytes: number, maxBytes: number) {
    super(
      `SCANNER_REPORT_SIZE_EXCEEDED: Scanner output (${Math.round(actualBytes / (1024 * 1024))} MB) exceeded configured safety ceiling (${Math.round(maxBytes / (1024 * 1024))} MB).`
    );
    this.name = "ScannerReportSizeExceededError";
    this.actualBytes = actualBytes;
    this.maxBytes = maxBytes;
  }
}

/**
 * Verifies file byte size via fs.stat BEFORE reading into V8 heap so hostile or
 * unexpectedly massive scanner JSON outputs fail cleanly with RESOURCE_LIMIT
 * instead of crashing the worker process with an OOM.
 */
export async function readBoundedTextFile(
  filePath: string,
  maxBytes: number = DEFAULT_MAX_SCANNER_REPORT_BYTES
): Promise<{ content: string; sizeBytes: number }> {
  const stat = await fs.stat(filePath);
  if (stat.size > maxBytes) {
    throw new ScannerReportSizeExceededError(stat.size, maxBytes);
  }
  const content = await fs.readFile(filePath, "utf8");
  return { content, sizeBytes: stat.size };
}
