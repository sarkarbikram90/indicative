import crypto from "node:crypto";
import type {
  ExposureLocation,
  FindingEvidence,
  FindingSeverity,
  RawScannerFinding,
  SecurityFinding
} from "@indicative/contracts";
import {
  containsPotentialPlaintextSecret,
  redactSecretsInText
} from "@indicative/security";
import { computeCanonicalFingerprint } from "./fingerprint.js";
import {
  defaultOfflineIntelligenceProvider,
  resolveVulnerabilityIntelligence,
  type VulnerabilityIntelligenceProvider
} from "./intelligence.js";
import { assessQualitativeRisk } from "./prioritization.js";

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0
};

export interface NormalizedOccurrenceInput {
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  commitSha?: string;
  commitTimestamp?: string;
  exposureLocation?: ExposureLocation;
  redactedSnippet?: string;
}

export interface NormalizedFindingBundle {
  finding: SecurityFinding;
  occurrences: NormalizedOccurrenceInput[];
}

function mergeExposureLocation(
  a?: ExposureLocation,
  b?: ExposureLocation
): ExposureLocation | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a === b) return a;
  return "BOTH";
}

function assertNoPlaintextSecretLeak(finding: SecurityFinding): void {
  const serialized = JSON.stringify({
    title: finding.title,
    description: finding.description,
    remediation: finding.remediation,
    evidence: finding.evidence
  });
  if (containsPotentialPlaintextSecret(serialized)) {
    throw new Error(
      `SECURITY_VIOLATION: Unredacted secret material detected during finding normalization for rule ${finding.ruleId}.`
    );
  }
}

function buildEvidenceForRaw(raw: RawScannerFinding): FindingEvidence[] {
  const evidence: FindingEvidence[] = [];

  if (raw.category === "SECRET") {
    const safeContent = redactSecretsInText(
      raw.redactedMatch || raw.codeSnippet || "[REDACTED]"
    );
    evidence.push({
      id: crypto.randomUUID(),
      type: raw.commitSha ? "GIT_COMMIT" : "SECRET_EXPOSURE",
      label: raw.commitSha
        ? `Redacted secret match in commit ${raw.commitSha.slice(0, 10)}`
        : "Redacted secret match in working tree",
      content: safeContent,
      filePath: raw.filePath,
      lineStart: raw.lineStart,
      lineEnd: raw.lineEnd,
      commitSha: raw.commitSha,
      commitTimestamp: raw.commitTimestamp,
      metadata: {
        secretValidity: "NOT_VERIFIED",
        exposureLocation: raw.exposureLocation ?? "WORKING_TREE"
      }
    });
  } else if (raw.category === "SCA") {
    evidence.push({
      id: crypto.randomUUID(),
      type: "PACKAGE_ADVISORY",
      label: `${raw.packageName ?? "package"}@${raw.installedVersion ?? "unknown"} (${raw.cve ?? raw.ruleId})`,
      content: redactSecretsInText(
        `Affected package: ${raw.packageName ?? "unknown"} ${raw.installedVersion ?? "unknown"}` +
          (raw.fixedVersion ? ` | Fixed in: ${raw.fixedVersion}` : " | No fixed version listed") +
          (typeof raw.cvssScore === "number" ? ` | CVSS: ${raw.cvssScore}` : "")
      ),
      filePath: raw.filePath,
      metadata: {
        packageName: raw.packageName ?? "unknown",
        installedVersion: raw.installedVersion ?? "unknown",
        ...(raw.fixedVersion ? { fixedVersion: raw.fixedVersion } : {})
      }
    });
  } else if (raw.category === "CICD") {
    const isOidc =
      raw.ruleId.startsWith("GHA-OIDC") ||
      raw.rawMetadata?.evidenceType === "OIDC_TRUST_POLICY";
    evidence.push({
      id: crypto.randomUUID(),
      type: isOidc ? "OIDC_TRUST_POLICY" : "WORKFLOW_CONFIG",
      label: raw.filePath
        ? `${raw.filePath}${raw.lineStart ? `:${raw.lineStart}` : ""}`
        : isOidc
          ? "Static OIDC Trust Configuration"
          : "GitHub Actions Workflow Configuration",
      content: redactSecretsInText(raw.codeSnippet || raw.description),
      filePath: raw.filePath,
      lineStart: raw.lineStart,
      lineEnd: raw.lineEnd,
      metadata: raw.rawMetadata
    });
  } else if (raw.category === "CLOUD_IDENTITY") {
    const isChain =
      raw.ruleId === "IAM-CORR-001" ||
      raw.rawMetadata?.evidenceType === "ATTACK_PATH_CHAIN";
    evidence.push({
      id: crypto.randomUUID(),
      type: isChain ? "ATTACK_PATH_CHAIN" : "IAM_POLICY",
      label: raw.filePath
        ? `${raw.filePath}${raw.lineStart ? `:${raw.lineStart}` : ""}`
        : isChain
          ? "Correlated CI/CD to Cloud IAM Chain"
          : "Static AWS IAM Policy Configuration",
      content: redactSecretsInText(raw.codeSnippet || raw.description),
      filePath: raw.filePath,
      lineStart: raw.lineStart,
      lineEnd: raw.lineEnd,
      metadata: raw.rawMetadata
    });
  } else if (raw.codeSnippet) {
    evidence.push({
      id: crypto.randomUUID(),
      type: raw.category === "IAC" ? "CONFIG_SNIPPET" : "CODE_SNIPPET",
      label: raw.filePath
        ? `${raw.filePath}${raw.lineStart ? `:${raw.lineStart}` : ""}`
        : "Matched source snippet",
      content: redactSecretsInText(raw.codeSnippet),
      filePath: raw.filePath,
      lineStart: raw.lineStart,
      lineEnd: raw.lineEnd
    });
  }

  for (const refUrl of raw.references.slice(0, 3)) {
    evidence.push({
      id: crypto.randomUUID(),
      type: "SCANNER_REFERENCE",
      label: "Scanner Reference",
      content: refUrl,
      referenceUrl: refUrl
    });
  }

  return evidence;
}

/**
 * Normalizes and deduplicates raw findings from all scanner adapters into
 * canonical SecurityFinding bundles ready for persistence and scan comparison.
 */
export function normalizeAndDeduplicateFindings(params: {
  organizationId: string;
  projectId: string;
  scanId: string;
  rawFindings: RawScannerFinding[];
  nowIso?: string;
  intelligenceProvider?: VulnerabilityIntelligenceProvider;
}): NormalizedFindingBundle[] {
  const now = params.nowIso ?? new Date().toISOString();
  const intelProvider = params.intelligenceProvider ?? defaultOfflineIntelligenceProvider;
  const grouped = new Map<string, NormalizedFindingBundle>();

  for (const raw of params.rawFindings) {
    const fingerprint = computeCanonicalFingerprint(params.projectId, raw);
    const occurrence: NormalizedOccurrenceInput = {
      filePath: raw.filePath,
      lineStart: raw.lineStart,
      lineEnd: raw.lineEnd,
      commitSha: raw.commitSha,
      commitTimestamp: raw.commitTimestamp,
      exposureLocation: raw.exposureLocation,
      redactedSnippet: raw.codeSnippet
        ? redactSecretsInText(raw.codeSnippet)
        : raw.redactedMatch
    };

    const newEvidence = buildEvidenceForRaw(raw);
    const existing = grouped.get(fingerprint);

    if (!existing) {
      const intelligence =
        raw.category === "SCA"
          ? resolveVulnerabilityIntelligence(raw.cve, intelProvider, "SCANNER_MATCH")
          : undefined;
      const cicdContext =
        raw.category === "CICD"
          ? {
              untrustedTrigger: Boolean(raw.rawMetadata?.untrustedTrigger),
              hasWritePermissions: Boolean(raw.rawMetadata?.hasWritePermissions),
              correlatedOidcTrust: Boolean(raw.rawMetadata?.correlatedOidcTrust),
              evidenceBasis:
                typeof raw.rawMetadata?.evidenceBasis === "string"
                  ? raw.rawMetadata.evidenceBasis
                  : "STATIC_CONFIG"
            }
          : undefined;

      const cloudIdentityContext =
        raw.category === "CLOUD_IDENTITY"
          ? {
              correlatedAttackChain:
                raw.ruleId === "IAM-CORR-001" ||
                raw.rawMetadata?.evidenceType === "ATTACK_PATH_CHAIN",
              capabilityTier:
                typeof raw.rawMetadata?.capabilityTier === "string"
                  ? raw.rawMetadata.capabilityTier
                  : undefined,
              broadOidcTrust: Boolean(raw.rawMetadata?.broadOidcTrust),
              untrustedTrigger: Boolean(raw.rawMetadata?.untrustedTrigger),
              evidenceBasis:
                typeof raw.rawMetadata?.evidenceBasis === "string"
                  ? raw.rawMetadata.evidenceBasis
                  : "STATIC_CONFIG"
            }
          : undefined;

      const risk = assessQualitativeRisk({
        category: raw.category,
        severity: raw.severity,
        originalSeverity: raw.originalSeverity,
        confidence: raw.confidence,
        cvssScore: raw.cvssScore,
        fixedVersion: raw.fixedVersion,
        exposureLocation: raw.exposureLocation,
        secretType: raw.secretType,
        occurrenceCount: 1,
        intelligence,
        cicdContext,
        cloudIdentityContext
      });

      const canonical: SecurityFinding = {
        id: crypto.randomUUID(),
        fingerprint,
        organizationId: params.organizationId,
        projectId: params.projectId,
        scanId: params.scanId,
        scanner: raw.scanner,
        scannerVersion: raw.scannerVersion,
        rulesetVersion: raw.rulesetVersion,
        ruleId: raw.ruleId,
        category: raw.category,
        title: redactSecretsInText(raw.title),
        description: redactSecretsInText(raw.description),
        severity: raw.severity,
        originalSeverity: raw.originalSeverity,
        confidence: raw.confidence,
        riskPriority: risk.riskPriority,
        riskRationale: risk.riskRationale,
        filePath: raw.filePath,
        lineStart: raw.lineStart,
        lineEnd: raw.lineEnd,
        packageName: raw.packageName,
        installedVersion: raw.installedVersion,
        fixedVersion: raw.fixedVersion,
        cve: raw.cve,
        cvssScore: raw.cvssScore,
        secretType: raw.secretType,
        secretFingerprint: raw.secretFingerprint,
        secretValidity: raw.category === "SECRET" ? "NOT_VERIFIED" : undefined,
        commitSha: raw.commitSha,
        commitTimestamp: raw.commitTimestamp,
        exposureLocation: raw.exposureLocation,
        evidence: newEvidence,
        intelligence,
        remediation: raw.remediationHint ? redactSecretsInText(raw.remediationHint) : undefined,
        status: "OPEN",
        verificationState: "DETECTED",
        occurrenceCount: 1,
        firstSeenAt: now,
        lastSeenAt: now
      };

      assertNoPlaintextSecretLeak(canonical);
      grouped.set(fingerprint, { finding: canonical, occurrences: [occurrence] });
    } else {
      // Deduplicate exact duplicate occurrence (same file, line, commit, exposure)
      const isDuplicateOccurrence = existing.occurrences.some(
        (o) =>
          o.filePath === occurrence.filePath &&
          o.lineStart === occurrence.lineStart &&
          o.commitSha === occurrence.commitSha &&
          o.exposureLocation === occurrence.exposureLocation
      );

      if (!isDuplicateOccurrence) {
        existing.occurrences.push(occurrence);
        existing.finding.occurrenceCount = existing.occurrences.length;

        // Preserve highest severity across correlated occurrences
        if (SEVERITY_RANK[raw.severity] > SEVERITY_RANK[existing.finding.severity]) {
          existing.finding.severity = raw.severity;
        }

        existing.finding.exposureLocation = mergeExposureLocation(
          existing.finding.exposureLocation,
          raw.exposureLocation
        );

        // Append non-duplicate evidence up to 12 items
        for (const ev of newEvidence) {
          const alreadyHas = existing.finding.evidence.some(
            (e) =>
              e.type === ev.type &&
              e.filePath === ev.filePath &&
              e.lineStart === ev.lineStart &&
              e.commitSha === ev.commitSha &&
              e.content === ev.content
          );
          if (!alreadyHas && existing.finding.evidence.length < 12) {
            existing.finding.evidence.push(ev);
          }
        }

        // Recompute transparent qualitative risk with updated occurrenceCount & exposureLocation
        const updatedRisk = assessQualitativeRisk({
          category: existing.finding.category,
          severity: existing.finding.severity,
          originalSeverity: existing.finding.originalSeverity,
          confidence: existing.finding.confidence,
          cvssScore: existing.finding.cvssScore,
          fixedVersion: existing.finding.fixedVersion,
          exposureLocation: existing.finding.exposureLocation,
          secretType: existing.finding.secretType,
          occurrenceCount: existing.finding.occurrenceCount,
          intelligence: existing.finding.intelligence
        });
        existing.finding.riskPriority = updatedRisk.riskPriority;
        existing.finding.riskRationale = updatedRisk.riskRationale;
        assertNoPlaintextSecretLeak(existing.finding);
      }
    }
  }

  return [...grouped.values()];
}
