import type {
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  RiskPriority
} from "@indicative/contracts";

export interface RiskPrioritizationInput {
  category: FindingCategory;
  severity: FindingSeverity;
  originalSeverity?: string;
  confidence: FindingConfidence;
  cvssScore?: number;
  fixedVersion?: string;
  exposureLocation?: "WORKING_TREE" | "GIT_HISTORY" | "BOTH";
  secretType?: string;
  occurrenceCount: number;
  internetExposureKnown?: boolean;
  assetCriticality?: "CRITICAL" | "HIGH" | "STANDARD" | "LOW";
}

export interface RiskPrioritizationOutput {
  riskPriority: RiskPriority;
  riskRationale: string[];
}

/**
 * Transparent, deterministic qualitative risk prioritization.
 * Never fabricates deployment exposure or active credential validity.
 */
export function assessQualitativeRisk(
  input: RiskPrioritizationInput
): RiskPrioritizationOutput {
  const rationale: string[] = [];

  rationale.push(
    `Normalized severity: ${input.severity}${input.originalSeverity ? ` (scanner original: ${input.originalSeverity})` : ""}.`
  );
  rationale.push(`Detection confidence: ${input.confidence}.`);

  if (input.category === "SECRET") {
    rationale.push(
      `Exposed credential type: ${input.secretType ?? "unspecified"}; exposure scope: ${input.exposureLocation ?? "WORKING_TREE"}.`
    );
    rationale.push(
      "Credential active/revoked status is NOT_VERIFIED; assume compromise until owner confirms rotation."
    );
    if (input.occurrenceCount > 1) {
      rationale.push(
        `Detected across ${input.occurrenceCount} file/commit locations in repository.`
      );
    }

    const priority: RiskPriority =
      input.severity === "CRITICAL" || input.exposureLocation === "BOTH"
        ? "IMMEDIATE"
        : "HIGH";
    return { riskPriority: priority, riskRationale: rationale };
  }

  if (typeof input.cvssScore === "number") {
    rationale.push(`Reported CVSS score: ${input.cvssScore.toFixed(1)}.`);
  }

  if (input.category === "SCA") {
    if (input.fixedVersion) {
      rationale.push(`Upstream patched version available: ${input.fixedVersion}.`);
    } else {
      rationale.push("No upstream patched version reported yet.");
    }
    rationale.push("Application call-graph reachability: Not statically confirmed in MVP.");
  }

  if (input.internetExposureKnown === undefined) {
    rationale.push("Runtime internet exposure: Unknown (not assumed).");
  } else {
    rationale.push(
      `Runtime internet exposure: ${input.internetExposureKnown ? "Explicitly marked public" : "Marked internal"}.`
    );
  }

  if (input.assetCriticality) {
    rationale.push(`Configured asset criticality: ${input.assetCriticality}.`);
  }

  let priority: RiskPriority;
  if (
    input.severity === "CRITICAL" &&
    (input.confidence === "HIGH" || (input.cvssScore !== undefined && input.cvssScore >= 9.0))
  ) {
    priority = "IMMEDIATE";
  } else if (
    input.severity === "CRITICAL" ||
    (input.severity === "HIGH" && input.confidence !== "LOW")
  ) {
    priority = "HIGH";
  } else if (
    input.severity === "HIGH" ||
    input.severity === "MEDIUM"
  ) {
    priority = "MEDIUM";
  } else if (input.severity === "LOW") {
    priority = "LOW";
  } else {
    priority = "INFORMATIONAL";
  }

  return { riskPriority: priority, riskRationale: rationale };
}
