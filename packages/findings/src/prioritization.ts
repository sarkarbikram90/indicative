import type {
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  RiskPriority,
  VulnerabilityIntelligence
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
  intelligence?: VulnerabilityIntelligence;
  cicdContext?: {
    untrustedTrigger?: boolean;
    hasWritePermissions?: boolean;
    correlatedOidcTrust?: boolean;
    evidenceBasis?: string;
  };
  cloudIdentityContext?: {
    correlatedAttackChain?: boolean;
    capabilityTier?: string;
    broadOidcTrust?: boolean;
    untrustedTrigger?: boolean;
    evidenceBasis?: string;
  };
}

export interface RiskPrioritizationOutput {
  riskPriority: RiskPriority;
  riskRationale: string[];
}

const PRIORITY_RANK: Record<RiskPriority, number> = {
  INFORMATIONAL: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  IMMEDIATE: 4
};

function elevatePriority(current: RiskPriority, target: RiskPriority): RiskPriority {
  return PRIORITY_RANK[target] > PRIORITY_RANK[current] ? target : current;
}

/**
 * Transparent, deterministic, evidence-backed risk prioritization.
 * - Preserves original scanner severity and never hides or invents missing signals.
 * - Explicitly distinguishes [VERIFIED], [INFERRED], and [UNKNOWN] context.
 * - Never fabricates deployment exposure, reachability, or active credential validity.
 */
export function assessQualitativeRisk(
  input: RiskPrioritizationInput
): RiskPrioritizationOutput {
  const rationale: string[] = [];

  rationale.push(
    `[VERIFIED] Normalized severity: ${input.severity}${input.originalSeverity ? ` (scanner original: ${input.originalSeverity})` : ""}.`
  );
  rationale.push(`[VERIFIED] Detection confidence: ${input.confidence}.`);

  if (input.category === "SECRET") {
    rationale.push(
      `[VERIFIED] Exposed credential type: ${input.secretType ?? "unspecified"}; exposure scope: ${input.exposureLocation ?? "WORKING_TREE"}.`
    );
    rationale.push(
      "[UNKNOWN] Credential active/revoked status is NOT_VERIFIED; assume compromise until owner confirms rotation."
    );
    if (input.occurrenceCount > 1) {
      rationale.push(
        `[VERIFIED] Detected across ${input.occurrenceCount} file/commit locations in repository.`
      );
    }

    const priority: RiskPriority =
      input.severity === "CRITICAL" || input.exposureLocation === "BOTH"
        ? "IMMEDIATE"
        : "HIGH";
    return { riskPriority: priority, riskRationale: rationale };
  }

  if (input.category === "CICD") {
    rationale.push(
      `[VERIFIED] Evidence basis: ${input.cicdContext?.evidenceBasis ?? "STATIC_CONFIG"} (repository workflow / IaC static analysis).`
    );
    if (input.cicdContext?.untrustedTrigger) {
      rationale.push(
        "[VERIFIED] Triggered by untrusted external event (e.g., pull_request_target / workflow_run)."
      );
    }
    if (input.cicdContext?.hasWritePermissions) {
      rationale.push(
        "[VERIFIED] Workflow or job requests elevated write or id-token permissions."
      );
    }
    if (input.cicdContext?.correlatedOidcTrust) {
      rationale.push(
        "[INFERRED] Static cross-file correlation links repository OIDC workflow token request to permissive cloud trust policy."
      );
      rationale.push(
        "[UNKNOWN] Live cloud IAM role policies, permission boundaries, SCPs, and GitHub environment approval gates are not statically verifiable."
      );
    } else {
      rationale.push(
        "[UNKNOWN] Repository-level GitHub default GITHUB_TOKEN settings and branch/environment protection rules cannot be verified statically."
      );
    }
  }

  if (input.category === "CLOUD_IDENTITY") {
    rationale.push(
      `[VERIFIED] Evidence basis: ${input.cloudIdentityContext?.evidenceBasis ?? "STATIC_CONFIG"} (static AWS IAM policy & workflow identity correlation).`
    );
    if (input.cloudIdentityContext?.capabilityTier) {
      rationale.push(
        `[VERIFIED] Static IAM role capability classification: ${input.cloudIdentityContext.capabilityTier}.`
      );
    }
    if (input.cloudIdentityContext?.correlatedAttackChain) {
      rationale.push(
        "[INFERRED] Cross-file static correlation links a CI/CD workflow identity reference to an over-privileged AWS IAM role."
      );
    }
    rationale.push(
      "[UNKNOWN] Account-level AWS SCPs, out-of-band Permission Boundaries, live IAM drift, and GitHub branch/environment approval gates are not statically verifiable."
    );
  }

  if (typeof input.cvssScore === "number") {
    rationale.push(`[VERIFIED] Reported CVSS score: ${input.cvssScore.toFixed(1)}.`);
  }

  if (input.category === "SCA") {
    if (input.fixedVersion) {
      rationale.push(`[VERIFIED] Upstream patched version available: ${input.fixedVersion}.`);
    } else {
      rationale.push("[VERIFIED] No upstream patched version reported yet.");
    }
    const reachStatus = input.intelligence?.reachabilityStatus ?? "UNKNOWN";
    rationale.push(
      reachStatus === "UNKNOWN"
        ? "[UNKNOWN] Application call-graph reachability: Not statically confirmed."
        : `[${reachStatus}] Application call-graph reachability: ${reachStatus}.`
    );
  }

  if (input.intelligence) {
    if (input.intelligence.kevListed === true) {
      rationale.push(
        `[VERIFIED] Listed in CISA Known Exploited Vulnerabilities (KEV) catalog (added ${input.intelligence.kevDateAdded ?? "date unspecified"}; source: ${input.intelligence.source}, observed ${input.intelligence.observedAt}).`
      );
    } else if (input.intelligence.kevListed === false) {
      rationale.push(
        `[VERIFIED] Not listed in CISA KEV snapshot as of ${input.intelligence.observedAt} (absence from KEV is not proof of safety).`
      );
    }

    if (typeof input.intelligence.epssScore === "number") {
      const pct = (input.intelligence.epssScore * 100).toFixed(1);
      const percentile =
        typeof input.intelligence.epssPercentile === "number"
          ? `, ${(input.intelligence.epssPercentile * 100).toFixed(1)}th percentile`
          : "";
      rationale.push(
        `[INFERRED] FIRST EPSS exploitation probability: ${pct}%${percentile} (observed ${input.intelligence.observedAt}; source: ${input.intelligence.source}).`
      );
    }
  } else if (input.category === "SCA") {
    rationale.push(
      "[UNKNOWN] External exploitation intelligence (CISA KEV / EPSS): No matching record in current offline snapshot (not interpreted as safety)."
    );
  }

  if (input.internetExposureKnown === undefined) {
    rationale.push("[UNKNOWN] Runtime internet exposure: Unknown (not assumed).");
  } else {
    rationale.push(
      `[VERIFIED] Runtime internet exposure: ${input.internetExposureKnown ? "Explicitly marked public" : "Marked internal"}.`
    );
  }

  if (input.assetCriticality) {
    rationale.push(`[VERIFIED] Configured asset criticality: ${input.assetCriticality}.`);
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
  } else if (input.severity === "HIGH" || input.severity === "MEDIUM") {
    priority = "MEDIUM";
  } else if (input.severity === "LOW") {
    priority = "LOW";
  } else {
    priority = "INFORMATIONAL";
  }

  // Contextual elevations grounded strictly in verified or explicitly labeled signals
  if (input.intelligence?.kevListed === true) {
    priority = elevatePriority(priority, "IMMEDIATE");
  } else if (
    typeof input.intelligence?.epssScore === "number" &&
    input.intelligence.epssScore >= 0.7 &&
    (input.severity === "CRITICAL" || input.severity === "HIGH")
  ) {
    priority = elevatePriority(priority, "IMMEDIATE");
  } else if (
    typeof input.intelligence?.epssScore === "number" &&
    input.intelligence.epssScore >= 0.4 &&
    input.severity === "MEDIUM"
  ) {
    priority = elevatePriority(priority, "HIGH");
  }

  if (input.category === "CICD") {
    if (
      (input.cicdContext?.untrustedTrigger && input.cicdContext?.hasWritePermissions) ||
      input.cicdContext?.correlatedOidcTrust
    ) {
      priority = elevatePriority(priority, "IMMEDIATE");
    }
  }

  if (input.category === "CLOUD_IDENTITY") {
    if (
      input.cloudIdentityContext?.correlatedAttackChain &&
      (input.severity === "CRITICAL" || input.cloudIdentityContext.broadOidcTrust)
    ) {
      priority = elevatePriority(priority, "IMMEDIATE");
    }
  }

  if (input.internetExposureKnown === true && input.severity === "HIGH") {
    priority = elevatePriority(priority, "IMMEDIATE");
  }

  return { riskPriority: priority, riskRationale: rationale };
}
