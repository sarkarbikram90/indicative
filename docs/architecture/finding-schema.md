# Indicative — Canonical Finding Schema & Lifecycle

## 1. Canonical `SecurityFinding` Model

Every finding from Semgrep, Trivy, Gitleaks, or future `ScannerAdapter` engines is normalized into a single deterministic contract defined in `packages/contracts/src/findings.ts`:

```typescript
export type FindingCategory = "SAST" | "SCA" | "SECRET" | "IAC";
export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
export type FindingConfidence = "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type SecretValidity = "UNKNOWN" | "NOT_VERIFIED";

export type FindingStatus =
  | "OPEN"
  | "ACKNOWLEDGED"
  | "IN_PROGRESS"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK"
  | "FIXED_PENDING_VERIFICATION"
  | "RESOLVED_VERIFIED"
  | "REOPENED";

export type RiskPriority = "IMMEDIATE" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export interface FindingEvidence {
  id: string;
  type:
    | "CODE_SNIPPET"
    | "PACKAGE_ADVISORY"
    | "SECRET_EXPOSURE"
    | "CONFIG_SNIPPET"
    | "GIT_COMMIT"
    | "SCANNER_REFERENCE";
  label: string;
  content: string; // Always redacted for secrets
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  commitSha?: string;
  commitTimestamp?: string;
  referenceUrl?: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface SecurityFinding {
  id: string;
  fingerprint: string;

  organizationId: string;
  projectId: string;
  scanId: string;

  scanner: string;
  scannerVersion: string;
  rulesetVersion?: string;
  ruleId: string;

  category: FindingCategory;
  title: string;
  description: string;

  severity: FindingSeverity;
  originalSeverity?: string;
  confidence: FindingConfidence;

  riskPriority: RiskPriority;
  riskRationale: string[];

  filePath?: string;
  lineStart?: number;
  lineEnd?: number;

  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  cve?: string;
  cvssScore?: number;

  secretType?: string;
  secretFingerprint?: string; // Tenant-keyed HMAC-SHA256 hex digest (never plaintext)
  secretValidity?: SecretValidity; // Always UNKNOWN or NOT_VERIFIED in MVP
  commitSha?: string;
  commitTimestamp?: string;
  exposureLocation?: "WORKING_TREE" | "GIT_HISTORY" | "BOTH";

  evidence: FindingEvidence[];
  remediation?: string;

  status: FindingStatus;
  verificationState?:
    | "DETECTED"
    | "NOT_DETECTED_IN_LATEST_SCAN"
    | "VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE"
    | "VERIFICATION_INCONCLUSIVE";

  occurrenceCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
}
```

## 2. Category-Specific Deterministic Fingerprinting

Fingerprints are SHA-256 hashes over normalized, structured tuples—never finding titles alone:

| Category | Fingerprint Input Tuple | Rationale |
|---|---|---|
| **SAST** | `v1\|SAST\|projectId\|scanner\|ruleId\|normalizedFilePath\|normalizedCodeAnchorOrLineBucket` | Survives minor unrelated edits while distinguishing independent occurrences in the same file. |
| **SCA** | `v1\|SCA\|projectId\|scanner\|normalizedFilePath\|packageName\|cveOrRuleId` | Tracks the same vulnerable dependency in a manifest even if version shifts slightly, while distinguishing distinct lockfiles or CVEs. |
| **IAC** | `v1\|IAC\|projectId\|scanner\|ruleId\|normalizedFilePath\|resourceOrLineBucket` | Stable identity per misconfiguration rule per file/resource block. |
| **SECRET** | `v1\|SECRET\|projectId\|secretType\|tenantKeyedHmacSecretFingerprint` | Correlates the **same leaked credential** across multiple files and multiple Git commits into a single canonical finding with multiple `finding_occurrences`, without ever storing the plaintext secret! |

### Tenant-Keyed Secret Fingerprinting
1. Derive a tenant-specific 32-byte key via `HKDF-SHA256(masterKey, salt=organizationId, info="indicative:secret-fingerprint:v1")`.
2. Compute `HMAC-SHA256(tenantKey, rawSecretBytes)` and encode as `hmac-sha256:v1:<hex>`.
3. Immediately discard `rawSecretBytes` and replace all occurrences in snippets, evidence, descriptions, and logs with masked tokens (e.g., `[REDACTED:aws-access-key:AKIA****MPLE]`).

This prevents rainbow-table reversal, prevents cross-tenant secret correlation, and enables exact deduplication across branches, files, and commits within a tenant.

## 3. Severity Normalization Mapping

| Scanner | Original Severity | Normalized `FindingSeverity` |
|---|---|---|
| Semgrep | `ERROR` / `CRITICAL` | `HIGH` (or `CRITICAL` if rule metadata `impact=HIGH` & `confidence=HIGH` or `severity=CRITICAL`) |
| Semgrep | `WARNING` | `MEDIUM` |
| Semgrep | `INFO` | `LOW` / `INFO` |
| Trivy | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` | 1:1 mapping |
| Gitleaks | Provider-specific high-impact credentials (AWS keys, private keys, GitHub tokens, DB URIs) | `CRITICAL` / `HIGH` (generic entropy/API keys default to `HIGH` or `MEDIUM` based on rule class) |

Original scanner severity is always preserved in `originalSeverity`.

## 4. Finding Lifecycle & Verification Rules

Allowed manual and automated state transitions:

```text
OPEN -> ACKNOWLEDGED | IN_PROGRESS | FALSE_POSITIVE | ACCEPTED_RISK | FIXED_PENDING_VERIFICATION
ACKNOWLEDGED -> IN_PROGRESS | FALSE_POSITIVE | ACCEPTED_RISK | FIXED_PENDING_VERIFICATION | OPEN
IN_PROGRESS -> FIXED_PENDING_VERIFICATION | ACKNOWLEDGED | FALSE_POSITIVE | ACCEPTED_RISK
FIXED_PENDING_VERIFICATION -> RESOLVED_VERIFIED (scanner verified) | REOPENED (re-detected) | IN_PROGRESS
RESOLVED_VERIFIED -> REOPENED (re-detected in subsequent scan)
FALSE_POSITIVE -> OPEN | REOPENED
ACCEPTED_RISK -> OPEN | REOPENED
REOPENED -> ACKNOWLEDGED | IN_PROGRESS | FIXED_PENDING_VERIFICATION | FALSE_POSITIVE | ACCEPTED_RISK
```

### Verification Criteria on Re-Scan
When a subsequent scan completes for the same project:
1. Check whether the scanner responsible for a previously open finding executed with status `SUCCESS` and full applicable scope (e.g., for Git history secrets, full history was scanned without truncation).
2. If the scanner **failed, timed out, was unavailable, or had scope limitations**: mark `verificationState = VERIFICATION_INCONCLUSIVE` and **do not** transition the finding to `RESOLVED_VERIFIED`.
3. If the scanner succeeded cleanly and the finding is **still detected**:
   - Update `lastSeenAt`, record a new `finding_occurrences` row, set `verificationState = DETECTED`.
   - If status was `FIXED_PENDING_VERIFICATION` or `RESOLVED_VERIFIED`, automatically transition to `REOPENED` and record an audited `finding_status_history` entry.
4. If the scanner succeeded cleanly and the finding is **no longer detected**:
   - If status was `FIXED_PENDING_VERIFICATION`: transition to `RESOLVED_VERIFIED` with `verificationState = VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE`.
   - If status was `OPEN` / `ACKNOWLEDGED` / `IN_PROGRESS` / `REOPENED`: set `verificationState = NOT_DETECTED_IN_LATEST_SCAN` and transition to `RESOLVED_VERIFIED` **only** for non-secret findings where the scanner completed cleanly; for `SECRET` findings, explicitly attach the caveat that removal from the scanned repository does **not** verify credential revocation (`secretValidity` remains `NOT_VERIFIED`).

## 5. Transparent Qualitative Risk Prioritization

Indicative computes `riskPriority` (`IMMEDIATE`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) using a documented, deterministic rule matrix—never an unexplained LLM score:
- `IMMEDIATE`: Exposed high-impact secret in working tree or git history; or `CRITICAL` severity with `HIGH` confidence (or known CVSS ≥ 9.0 with fixed version available).
- `HIGH`: `CRITICAL` with non-high confidence; `HIGH` severity with `HIGH`/`MEDIUM` confidence; or reachable SAST injection / auth flaw.
- `MEDIUM`: `MEDIUM` severity, or `HIGH` severity with `LOW` confidence / missing lockfile context.
- `LOW`: `LOW` severity.
- `INFORMATIONAL`: `INFO` or `UNKNOWN` severity.

Every prioritization decision stores an explicit `riskRationale: string[]` explaining each input factor (e.g., `"Severity: HIGH (original: ERROR)"`, `"Confidence: HIGH"`, `"Fixed version available: 4.17.21"`, `"Internet exposure: Unknown (not assumed)"`).
