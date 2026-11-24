import crypto from "node:crypto";
import type { RawScannerFinding } from "@indicative/contracts";

function sha256(parts: string[]): string {
  return crypto.createHash("sha256").update(parts.join("|"), "utf8").digest("hex");
}

function normalizeCodeAnchor(snippet?: string): string {
  if (!snippet) return "";
  return snippet
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

/**
 * Generates deterministic, category-specific finding fingerprints.
 * Never relies solely on finding titles.
 *
 * - SECRET: Correlates the exact same leaked credential across multiple files and commits
 *           using the tenant-keyed HMAC secretFingerprint (never plaintext).
 * - SCA:    Correlates by manifest file, package name, and CVE/rule ID.
 * - IAC:    Correlates by rule ID, config file path, and resource or line bucket.
 * - SAST:   Correlates by scanner, rule ID, normalized file path, and normalized code anchor/line.
 */
export function computeCanonicalFingerprint(
  projectId: string,
  finding: RawScannerFinding
): string {
  const file = (finding.filePath ?? "").replace(/\\/g, "/").toLowerCase();

  switch (finding.category) {
    case "SECRET": {
      if (finding.secretFingerprint) {
        return `fp:secret:${sha256([
          "v1",
          "SECRET",
          projectId,
          finding.secretType ?? finding.ruleId,
          finding.secretFingerprint
        ])}`;
      }
      return `fp:secret:${sha256([
        "v1",
        "SECRET",
        projectId,
        finding.scanner,
        finding.ruleId,
        file,
        String(finding.lineStart ?? 0)
      ])}`;
    }

    case "SCA": {
      return `fp:sca:${sha256([
        "v1",
        "SCA",
        projectId,
        finding.scanner,
        file,
        (finding.packageName ?? "").toLowerCase(),
        (finding.cve ?? finding.ruleId).toUpperCase()
      ])}`;
    }

    case "IAC": {
      const resource =
        typeof finding.rawMetadata?.resource === "string"
          ? finding.rawMetadata.resource
          : String(Math.floor((finding.lineStart ?? 0) / 5));
      return `fp:iac:${sha256([
        "v1",
        "IAC",
        projectId,
        finding.scanner,
        finding.ruleId,
        file,
        resource
      ])}`;
    }

    case "CICD": {
      const workflowAnchor =
        typeof finding.rawMetadata?.workflowAnchor === "string"
          ? finding.rawMetadata.workflowAnchor
          : typeof finding.rawMetadata?.jobId === "string"
            ? `${finding.rawMetadata.jobId}:${finding.rawMetadata.stepName ?? finding.lineStart ?? 0}`
            : normalizeCodeAnchor(finding.codeSnippet) || String(finding.lineStart ?? 0);
      return `fp:cicd:${sha256([
        "v1",
        "CICD",
        projectId,
        finding.scanner,
        finding.ruleId,
        file,
        workflowAnchor
      ])}`;
    }

    case "SAST":
    default: {
      const anchor = normalizeCodeAnchor(finding.codeSnippet) || String(finding.lineStart ?? 0);
      return `fp:sast:${sha256([
        "v1",
        "SAST",
        projectId,
        finding.scanner,
        finding.ruleId,
        file,
        anchor
      ])}`;
    }
  }
}
