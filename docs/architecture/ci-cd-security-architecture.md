# Indicative — CI/CD Security Intelligence Architecture

**Document Version:** 1.0  
**Last Updated:** 2026-11-23  
**Package:** `packages/cicd-security` (`@indicative/cicd-security`)

---

## 1. Design Objectives

Indicative's CI/CD Security Intelligence engine analyzes GitHub Actions workflows and static cloud OIDC federation configurations inside a repository to detect high-impact pipeline and source-to-cloud trust weaknesses.

Core design principles:
1. **Deterministic & Offline-First:** Runs entirely inside the isolated, no-egress `scanner-runner` with zero network access and zero execution of repository code.
2. **AST & Line-Number Accurate:** Uses a safe, schema-restricted YAML 1.2 parser (`yaml` AST with `Document` / `CST` line counters) rather than fragile regexes across raw text.
3. **Context-Aware Precision:** Evaluates workflow triggers, job permissions, checkout targets, `env:` indirection, and OIDC subject/audience claims together to minimize false positives (e.g., `id-token: write` alone is informational unless paired with unsafe triggers, overly broad cloud trust, or excessive scope; `${{ github.event.pull_request.title }}` passed via `env:` and referenced as `"$TITLE"` is NOT flagged as shell injection).
4. **Honest Evidence Boundaries:** Strictly distinguishes **static configuration evidence** (`STATIC_CONFIG`) from **live cloud verification** (`LIVE_CLOUD` — not performed in Phase 2). Never claims a workflow *can* assume a cloud role unless both the workflow OIDC request and the trust policy conditions are analyzed — and explicitly states that live IAM role permissions, SCPs, and branch-protection rules cannot be verified statically.
5. **First-Class Canonical Integration:** Implements Indicative's `ScannerAdapter` interface (`scanner = "cicd-github-actions"`, `category = "CICD"`) so findings automatically gain canonical fingerprinting, deduplication, lifecycle state tracking, fix verification, SARIF/JSON/CSV exports, AI advisory explanation, and Web UI inspection.

---

## 2. Architecture & Data Flow

```text
Repository Workspace (sanitized, read-only)
   │
   ├──► Workflow Discovery (.github/workflows/**/*.{yml,yaml})
   │       │
   │       ▼
   │    Safe YAML AST Parser (alias/depth/size limits, line mapping)
   │       │
   │       ▼
   │    Typed Workflow Model (triggers, permissions, jobs, steps, uses, run, env, secrets, OIDC)
   │
   ├──► Static OIDC Trust Discovery (Terraform *.tf, CloudFormation/IAM *.json/*.yaml, Bicep/ARM, GCP WIF)
   │       │
   │       ▼
   │    Static Cloud Trust Extractor (AWS IAM OIDC, Azure FIC, GCP WIF -> sub/aud conditions)
   │
   ▼
Rule Engine (15+ versioned, documented rules across 7 categories)
   │
   ├──► RawScannerFinding[] (category: "CICD", redacted snippets, lineStart/lineEnd, structured metadata)
   ├──► WorkflowInventorySummary (workflows, triggers, permissions, actions, secrets, OIDC refs)
   └──► Policy Evaluation (informational / warning / failure thresholds) + CI Reporters (JSON, SARIF, PR Markdown, GitHub Actions Annotations)
   │
   ▼
Existing Indicative Pipeline
   ├──► normalizeAndDeduplicateFindings (CICD category fingerprint + contextual risk prioritization)
   ├──► PostgreSQL persistence (findings, finding_occurrences, finding_evidence, scanner_runs)
   └──► Fastify REST API + Next.js Web UI (/workflows view + /findings + /scans)
```

---

## 3. Package Layout

```text
packages/cicd-security/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts                  # Public exports
    ├── types.ts                  # Typed WorkflowModel, OidcTrustPolicy, RuleMetadata, PolicyConfig
    ├── parser/
    │   ├── yamlParser.ts         # Safe YAML AST parser with line-number mapping & YAML-bomb limits
    │   └── workflowParser.ts     # GitHub Actions semantic extractor (triggers, perms, jobs, steps)
    ├── oidc/
    │   └── oidcAnalyzer.ts       # Static AWS IAM / Azure FIC / GCP WIF trust-policy parser & correlator
    ├── rules/
    │   ├── registry.ts           # Versioned rule catalog (metadata, CWE, limitations, FP guidance)
    │   ├── permissions.ts        # GHA-PERM-* rules
    │   ├── triggers.ts           # GHA-TRIG-* rules
    │   ├── injection.ts          # GHA-INJ-* rules (untrusted context expression injection)
    │   ├── supplyChain.ts        # GHA-ACT-* rules (unpinned actions, reusable workflows, persist-credentials)
    │   ├── secrets.ts            # GHA-SEC-* rules (secret logging, untrusted PR exposure, long-lived cloud creds)
    │   ├── integrity.ts          # GHA-INT-* rules (artifact/cache/install integrity)
    │   └── oidc.ts               # GHA-OIDC-* rules (wildcard sub, missing aud, workflow-to-policy correlation)
    ├── policy.ts                 # Policy evaluation (info/warn/fail) + GitHub Annotations & PR Markdown summary
    ├── adapter.ts                # CicdScannerAdapter implementing @indicative/contracts ScannerAdapter
    └── cicd.test.ts              # Unit tests for parser, rules, OIDC correlation, policy, and security bounds
```

Rule documentation is also maintained under `rules/cicd/github-actions/README.md` with stable rule IDs, severities, threat models, false-positive notes, and remediation examples.

---

## 4. Rule Catalog (v1.0.0)

| Rule ID | Category | Default Severity | Description |
|---|---|---|---|
| `GHA-PERM-001` | Permissions | `MEDIUM` | Missing explicit top-level `permissions:` block (relies on repository default token scope) |
| `GHA-PERM-002` | Permissions | `CRITICAL` | Workflow or job declares `permissions: write-all` |
| `GHA-PERM-003` | Permissions | `HIGH` | Excessive write permissions (`contents: write`, `packages: write`, `actions: write`, `security-events: write`) granted globally or on untrusted/PR triggers |
| `GHA-PERM-004` | Permissions | `MEDIUM` / `HIGH` | `id-token: write` declared at workflow root or paired with untrusted triggers (`pull_request_target`) rather than scoped to a dedicated deployment job/environment |
| `GHA-TRIG-001` | Triggers | `CRITICAL` | `pull_request_target` combined with checkout of untrusted PR head (`github.event.pull_request.head.sha` / `head.ref`) — classic pwn-request RCE |
| `GHA-TRIG-002` | Triggers | `HIGH` | `workflow_run` downloads untrusted artifacts or checks out untrusted PR head commit inside privileged context |
| `GHA-INJ-001` | Injection | `CRITICAL` / `HIGH` | Untrusted GitHub event context (`pull_request.title`, `issue.body`, `comment.body`, `head_ref`, `commits.*.message`, etc.) interpolated directly into `run:` shell scripts or `actions/github-script` instead of via `env:` |
| `GHA-ACT-001` | Supply Chain | `MEDIUM` / `HIGH` | Third-party GitHub Action referenced by mutable tag/branch (`@v4`, `@main`) instead of a 40-char immutable commit SHA |
| `GHA-ACT-002` | Supply Chain | `HIGH` | Reusable workflow (`uses: owner/repo/.github/workflows/...@ref`) referenced by mutable tag/branch instead of commit SHA |
| `GHA-ACT-003` | Supply Chain | `MEDIUM` | `actions/checkout` without `persist-credentials: false` in workflows with write permissions or untrusted execution steps |
| `GHA-SEC-001` | Secrets | `HIGH` | Secrets interpolated into `echo`/shell commands or `secrets: inherit` passed to external reusable workflows |
| `GHA-SEC-002` | Secrets | `HIGH` | Static long-lived cloud credentials (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `GCP_SA_KEY`, `AZURE_CREDENTIALS`) used in CI workflows instead of short-lived OIDC federation |
| `GHA-INT-001` | Build Integrity | `MEDIUM` | Unverified remote script execution piped to shell (`curl ... \| sh`, `wget ... \| bash`) in workflow steps |
| `GHA-INT-002` | Build Integrity | `MEDIUM` | Dependency installation without lockfile integrity (`npm install` instead of `npm ci`, unpinned `pip install`) in release/CI build jobs |
| `GHA-OIDC-001` | OIDC Federation | `CRITICAL` | Overly broad OIDC subject (`sub`) trust condition (e.g., `repo:org/*`, `repo:org/repo:*` without branch/environment restriction, or missing `sub` claim) in AWS IAM / Azure FIC / GCP WIF config |
| `GHA-OIDC-002` | OIDC Federation | `HIGH` | Missing or wildcard `aud` (`sts.amazonaws.com` / `api://AzureADTokenExchange`) validation in static OIDC trust policy |
| `GHA-OIDC-003` | OIDC Correlation | `CRITICAL` / `HIGH` | Cross-file correlation: repository contains both a workflow requesting `id-token: write` (or cloud OIDC action) and a permissive static cloud OIDC trust policy, forming an evidence-backed pipeline-to-cloud trust weakness |

---

## 5. Canonical Finding Schema & Fingerprinting Integration

- **Category:** Add `"CICD"` to `FindingCategorySchema` (backward-compatible enum extension).
- **Scanner Name:** Add `"cicd-github-actions"` to `ScannerNameSchema` and `ScannerCapabilitySchema` (`"cicd"`).
- **Evidence Types:** Add `"WORKFLOW_CONFIG"` and `"OIDC_TRUST_POLICY"` to `FindingEvidenceSchema`.
- **Canonical Fingerprint (`packages/findings/src/fingerprint.ts`):**
  - `fp:cicd:sha256("v1", "CICD", projectId, scanner, ruleId, normalizedFilePath, workflowOrJobAnchor)`
  - Survives line-number shifts when unrelated steps are added above/below in a workflow!
- **Prioritization (`packages/findings/src/prioritization.ts`):**
  - Incorporates CI/CD exploitability context (e.g., untrusted PR trigger + write permissions, or correlated OIDC wildcard trust) with explicit rationale statements separating verified static evidence from unknown runtime cloud permissions.

---

## 6. Web UI & API Integration

- **API Endpoint:** `GET /api/v1/projects/:projectId/workflows` (and `/api/v1/workflows` org summary) aggregates CI/CD findings and structured workflow/OIDC metadata extracted from persisted findings & evidence — zero fake data, strict tenant isolation.
- **Web UI (`/workflows`):** Dedicated **Workflow Security** page in `AppShell` navigation showing:
  - Analyzed workflow files, triggers, permissions, third-party actions, OIDC references, and correlated cloud trust policies.
  - Filtered CI/CD findings grouped by rule category with direct links to Finding Detail pages.
  - Clear labeling that OIDC trust checks reflect **static repository configuration** (`STATIC_CONFIG`), not live cloud API verification.
