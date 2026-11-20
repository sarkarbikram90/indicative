# Indicative — Canonical Finding Schema

## 1. Purpose

Different scanners produce different output formats, severity scales, and metadata. The findings engine converts every scanner result into one canonical representation so the rest of the product — UI, deduplication, lifecycle, reporting, and AI — can operate uniformly while preserving scanner provenance.

This document describes the target schema from Agent.md §9. Implementations may refine field names when technically justified, but must preserve the concepts.

## 2. Core finding

```typescript
interface SecurityFinding {
  id: string;
  fingerprint: string;

  organizationId: string;
  projectId: string;
  scanId: string;

  scanner: string;
  scannerVersion: string;
  ruleId: string;

  category: "SAST" | "SCA" | "SECRET" | "IAC";

  title: string;
  description: string;

  severity:
    | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
  originalSeverity?: string;

  confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

  filePath?: string;
  lineStart?: number;
  lineEnd?: number;

  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  cve?: string;

  secretType?: string;
  secretFingerprint?: string;
  secretValidity?: "UNKNOWN" | "NOT_VERIFIED";

  evidence: FindingEvidence[];
  remediation?: string;

  status:
    | "OPEN"
    | "ACKNOWLEDGED"
    | "IN_PROGRESS"
    | "FALSE_POSITIVE"
    | "ACCEPTED_RISK"
    | "FIXED_PENDING_VERIFICATION"
    | "RESOLVED_VERIFIED"
    | "REOPENED";

  firstSeenAt: string;
  lastSeenAt: string;
}
```

## 3. Evidence

Evidence records support the finding without disclosing secrets. Each entry should identify its source, location, and a **redacted** excerpt.

```typescript
interface FindingEvidence {
  type: "source" | "scanner-output" | "dependency" | "config" | "commit" | "other";
  summary: string;
  location?: {
    filePath?: string;
    lineStart?: number;
    lineEnd?: number;
    commitId?: string;
    commitTimestamp?: string;
  };
  redactedExcerpt?: string;
}
```

Rules:

- Secret values must be masked before entering `summary` or `redactedExcerpt`.
- Full scanner output is never embedded verbatim.
- Unredacted output is disposed of immediately after parsing.

## 4. Severity normalization

| Canonical | Typical scanner inputs |
|-----------|------------------------|
| CRITICAL | critical, error, severity 4, CVSS ≥ 9.0 |
| HIGH | high, severity 3, CVSS 7.0–8.9 |
| MEDIUM | medium, moderate, warning, severity 2, CVSS 4.0–6.9 |
| LOW | low, info+, severity 1, CVSS < 4.0 |
| INFO | info, note, informational |
| UNKNOWN | missing or unrecognized value |

`originalSeverity` always retains the scanner's own label. Normalization must never silently upgrade a finding; documented mapping only.

## 5. Confidence

Confidence is separate from severity. It reflects how reliable the detection is, not how dangerous the issue is.

- `HIGH` — deterministic rule match with clear evidence
- `MEDIUM` — likely true positive, some ambiguity
- `LOW` — heuristic or needs review
- `UNKNOWN` — scanner supplied no confidence signal

## 6. Fingerprinting

Fingerprints are deterministic and category-specific. They must **not** rely solely on titles.

| Category | Fingerprint inputs |
|----------|--------------------|
| SAST | organization, project, scanner, rule id, normalized file path, normalized location |
| SCA | organization, project, scanner, CVE/rule id, package name, installed version |
| SECRET | organization/project keyed HMAC of the secret value, optional rule id — occurrences across files/commits correlate to one credential |
| IAC | organization, project, scanner, rule id, normalized file path, config location |

Secret fingerprints use a **keyed HMAC with a tenant-specific key**. Plaintext credentials are never used directly as fingerprints and are never stored.

## 7. Deduplication and tracking

- Identical fingerprints within a scan collapse to one finding with multiple occurrences.
- Across scans, fingerprints identify new, recurring, and no-longer-detected findings.
- `firstSeenAt` / `lastSeenAt` track the observation window.
- A finding disappearing from a later scan is **not** automatically resolved; verification rules apply.

## 8. Lifecycle

```text
OPEN
  ↓
ACKNOWLEDGED
  ↓
IN_PROGRESS
  ↓
FIXED_PENDING_VERIFICATION
  ↓
RESOLVED_VERIFIED
```

Additional states: `FALSE_POSITIVE`, `ACCEPTED_RISK`, `REOPENED`.

- Human-controlled transitions (false positive, accepted risk) must be audited.
- Automatic resolution from absence in a scan is prohibited without verification criteria.
- Secret removal from the repository is distinct from credential revocation; the MVP never claims revocation.

## 9. Provenance and AI separation

Each finding retains:

- scanner name and version
- rule/ruleset identifier
- original severity
- evidence location

AI analyses are stored separately as `finding_ai_analyses` with model and prompt version. AI content is labelled as analysis/recommendation and never overwrites scanner facts.
