import type {
  FindingStatus,
  ScanComparison,
  ScannerExecutionStatus,
  VerificationState
} from "@indicative/contracts";

const ALLOWED_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  OPEN: [
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "FIXED_PENDING_VERIFICATION"
  ],
  ACKNOWLEDGED: [
    "OPEN",
    "IN_PROGRESS",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "FIXED_PENDING_VERIFICATION"
  ],
  IN_PROGRESS: [
    "ACKNOWLEDGED",
    "FIXED_PENDING_VERIFICATION",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK"
  ],
  FIXED_PENDING_VERIFICATION: ["RESOLVED_VERIFIED", "REOPENED", "IN_PROGRESS"],
  RESOLVED_VERIFIED: ["REOPENED"],
  FALSE_POSITIVE: ["OPEN", "REOPENED"],
  ACCEPTED_RISK: ["OPEN", "REOPENED"],
  REOPENED: [
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "FIXED_PENDING_VERIFICATION",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK"
  ]
};

export function isValidStatusTransition(from: FindingStatus, to: FindingStatus): boolean {
  if (from === to) return false;
  return ALLOWED_TRANSITIONS[from]?.includes(to) ?? false;
}

export function assertValidStatusTransition(from: FindingStatus, to: FindingStatus): void {
  if (!isValidStatusTransition(from, to)) {
    throw new Error(
      `INVALID_STATUS_TRANSITION: Cannot transition finding from "${from}" to "${to}".`
    );
  }
}

export interface ExistingProjectFinding {
  id: string;
  fingerprint: string;
  scanner: string;
  category: string;
  status: FindingStatus;
  exposureLocation?: string | null;
}

export interface ScannerCoverageOutcome {
  scanner: string;
  status: ScannerExecutionStatus;
  hasScopeLimitations: boolean;
}

export interface VerificationDecision {
  findingId: string;
  previousStatus: FindingStatus;
  nextStatus: FindingStatus;
  verificationState: VerificationState;
  statusChanged: boolean;
  reason: string;
}

export interface ScanComparisonPlan {
  comparison: ScanComparison;
  newFingerprints: string[];
  recurringDecisions: VerificationDecision[];
  missingDecisions: VerificationDecision[];
}

/**
 * Compares previously persisted findings for a project against the newly detected
 * fingerprints in the current scan, honoring strict scanner failure transparency:
 * - If a finding's scanner failed, timed out, was unavailable, or had scope limitations,
 *   absence does NOT verify resolution -> VERIFICATION_INCONCLUSIVE.
 * - If a finding marked FIXED_PENDING_VERIFICATION or RESOLVED_VERIFIED is detected again -> REOPENED.
 * - If a finding marked FIXED_PENDING_VERIFICATION is no longer detected after a clean scan -> RESOLVED_VERIFIED
 *   with VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE.
 * - Secrets always note that repository removal does not establish credential revocation.
 */
export function computeScanComparisonAndVerification(params: {
  currentScanId: string;
  previousScanId: string | null;
  existingFindings: ExistingProjectFinding[];
  detectedFingerprints: Set<string>;
  scannerOutcomes: ScannerCoverageOutcome[];
}): ScanComparisonPlan {
  const scannerMap = new Map(params.scannerOutcomes.map((s) => [s.scanner, s]));
  const existingByFp = new Map(params.existingFindings.map((f) => [f.fingerprint, f]));

  const newFingerprints: string[] = [];
  const recurringFindingIds: string[] = [];
  const reopenedFindingIds: string[] = [];
  const notDetectedFindingIds: string[] = [];
  const inconclusiveFindingIds: string[] = [];

  const recurringDecisions: VerificationDecision[] = [];
  const missingDecisions: VerificationDecision[] = [];

  for (const fp of params.detectedFingerprints) {
    if (!existingByFp.has(fp)) {
      newFingerprints.push(fp);
    }
  }

  for (const existing of params.existingFindings) {
    const stillDetected = params.detectedFingerprints.has(existing.fingerprint);
    const scannerOutcome = scannerMap.get(existing.scanner);

    if (stillDetected) {
      recurringFindingIds.push(existing.id);

      if (
        existing.status === "FIXED_PENDING_VERIFICATION" ||
        existing.status === "RESOLVED_VERIFIED"
      ) {
        reopenedFindingIds.push(existing.id);
        recurringDecisions.push({
          findingId: existing.id,
          previousStatus: existing.status,
          nextStatus: "REOPENED",
          verificationState: "DETECTED",
          statusChanged: true,
          reason: `Re-detected in scan ${params.currentScanId} by ${existing.scanner}; automatically reopened.`
        });
      } else {
        recurringDecisions.push({
          findingId: existing.id,
          previousStatus: existing.status,
          nextStatus: existing.status,
          verificationState: "DETECTED",
          statusChanged: false,
          reason: `Still detected in scan ${params.currentScanId}.`
        });
      }
      continue;
    }

    // Finding was NOT detected in current scan.
    // Skip already closed/suppressed states unless verification was pending.
    if (
      existing.status === "FALSE_POSITIVE" ||
      existing.status === "ACCEPTED_RISK" ||
      existing.status === "RESOLVED_VERIFIED"
    ) {
      continue;
    }

    // Check whether the responsible scanner actually succeeded without scope limitations
    const cleanScannerRun =
      scannerOutcome !== undefined &&
      scannerOutcome.status === "SUCCESS" &&
      !scannerOutcome.hasScopeLimitations;

    if (!cleanScannerRun) {
      inconclusiveFindingIds.push(existing.id);
      const reason = !scannerOutcome
        ? `Scanner "${existing.scanner}" did not run in scan ${params.currentScanId}; verification inconclusive.`
        : `Scanner "${existing.scanner}" finished with status ${scannerOutcome.status}${
            scannerOutcome.hasScopeLimitations ? " and scope limitations" : ""
          }; absence cannot be treated as verified resolution.`;

      missingDecisions.push({
        findingId: existing.id,
        previousStatus: existing.status,
        nextStatus: existing.status,
        verificationState: "VERIFICATION_INCONCLUSIVE",
        statusChanged: false,
        reason
      });
      continue;
    }

    notDetectedFindingIds.push(existing.id);
    const secretCaveat =
      existing.category === "SECRET"
        ? " Note: removal from scanned repository scope does NOT verify credential revocation or rotation."
        : "";

    if (existing.status === "FIXED_PENDING_VERIFICATION") {
      missingDecisions.push({
        findingId: existing.id,
        previousStatus: existing.status,
        nextStatus: "RESOLVED_VERIFIED",
        verificationState: "VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE",
        statusChanged: true,
        reason: `Not detected in latest clean ${existing.scanner} scan ${params.currentScanId} (verification successful within scanned scope).${secretCaveat}`
      });
    } else {
      // OPEN / ACKNOWLEDGED / IN_PROGRESS / REOPENED: do not blindly assert human-verified fix,
      // record NOT_DETECTED_IN_LATEST_SCAN while preserving auditable transition only when explicitly pending,
      // or mark RESOLVED_VERIFIED for non-secret code fixes where scanner succeeded cleanly.
      const nextStatus: FindingStatus =
        existing.category === "SECRET" ? existing.status : "RESOLVED_VERIFIED";
      missingDecisions.push({
        findingId: existing.id,
        previousStatus: existing.status,
        nextStatus,
        verificationState: "NOT_DETECTED_IN_LATEST_SCAN",
        statusChanged: nextStatus !== existing.status,
        reason:
          existing.category === "SECRET"
            ? `Secret not detected in latest clean ${existing.scanner} scan ${params.currentScanId}, but credential revocation is unverified; manual confirmation required to close.${secretCaveat}`
            : `Not detected in latest clean ${existing.scanner} scan ${params.currentScanId}; marked resolved within scanned scope.`
      });
    }
  }

  const summary =
    `Scan comparison: ${newFingerprints.length} new, ${recurringFindingIds.length} recurring, ` +
    `${notDetectedFindingIds.length} no longer detected, ${reopenedFindingIds.length} reopened, ` +
    `${inconclusiveFindingIds.length} inconclusive.`;

  return {
    comparison: {
      currentScanId: params.currentScanId,
      previousScanId: params.previousScanId,
      newFindingIds: [], // populated after DB insert of new findings
      recurringFindingIds,
      notDetectedFindingIds,
      reopenedFindingIds,
      inconclusiveFindingIds,
      summary
    },
    newFingerprints,
    recurringDecisions,
    missingDecisions
  };
}
