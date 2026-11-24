# Indicative — Current-State Technical & Security Audit

**Audit Date:** 2026-11-23  
**Audited Baseline Commit:** `ab5fc58` (`main`)  
**Auditor Methodology:** Direct source-code inspection across all 12 workspaces, deployment manifests, database migrations, and runtime execution of typecheck, build, and automated test suites (`vitest run` against real Semgrep `1.186.0`, Trivy `0.76.2`, Gitleaks `8.30.1`, and embedded PostgreSQL).

---

## Baseline Verification Results (Pre-Change)

| Check | Command | Actual Outcome | Notes |
|---|---|---|---|
| TypeScript Type Check | `npm run typecheck` | **PASS** (12/12 workspaces) | Strict TypeScript across all packages, services, and apps |
| Linting | `npm run lint` | **NO-OP (PASS exit 0)** | **Gap:** No workspace defines a `lint` script; ESLint is not configured |
| Production Build | `npm run build` | **PASS** (12/12 workspaces) | Includes Next.js 15.5.29 production build (`8` routes) |
| Full Automated Test Suite | `npm test` | **PASS** (`8/8` files, `32/32` tests, `14.99s`) | Real Semgrep `1.186.0`, Trivy `0.76.2`, Gitleaks `8.30.1`, PGlite |
| Security Regression Corpus | `tests/regression/corpus-benchmark.test.ts` | **PASS** (`20/20` TP, `0` FN, `0` clean FP) | Precision `1.0000`, Recall `1.0000`, `0` parse/exec failures |

---

## Evidence Classification Matrix

Evidence levels used throughout this assessment:
- **VERIFIED**: Supported by working implementation and repeatable automated tests.
- **PARTIALLY_VERIFIED**: Implemented in code, but with incomplete test coverage, runtime gaps, or unenforced controls.
- **DOCUMENTED_ONLY**: Present in architecture/strategy docs or DB schema, but not wired into runtime execution.
- **NOT_IMPLEMENTED**: Missing capability.

| Capability / Control | Classification | Concrete Code & Test Evidence |
|---|---|---|
| Next.js 15 / React 19 / Tailwind UI | **VERIFIED** | `apps/web/src/app/*` builds cleanly (`next build`), covers Dashboard, Projects, Scans, Findings, Finding Detail, AI Advisor. |
| Fastify 5 REST API + OpenAPI 3.1 + Prometheus metrics | **VERIFIED** | `apps/api/src/server.ts`, `routes/platform.ts`, `routes/auth.ts`; verified in `tests/integration/platform.integration.test.ts`. |
| PostgreSQL 16 + Drizzle ORM (19 tables + migrations) | **VERIFIED** | `packages/database/src/schema.ts`, `migrations/0001_initial.sql`; verified via PGlite migrations in integration/security/E2E tests. |
| Redis + BullMQ scan queue | **PARTIALLY_VERIFIED** | `apps/worker/src/jobs/scanQueue.ts` implements BullMQ, but all automated tests use `createInlineAsyncEnqueuer`; no automated test exercises live Redis/BullMQ retries or cancellation. |
| GitHub OAuth & GitHub App short-lived token ingestion | **PARTIALLY_VERIFIED** | `apps/api/src/routes/auth.ts`, `apps/worker/src/ingestion/githubApp.ts`, `repositoryIngestor.ts`. OAuth CSRF state and repo discovery are tested with mocked `fetchImpl`; live git clone with transient `extraheader` is implemented but only tested via local fixtures in automated tests. |
| Semgrep CE (`1.186.0`), Trivy (`0.76.2`), Gitleaks (`8.30.1`) adapters | **VERIFIED** | `packages/scanners/src/*`; independently executed against real binaries in `scanners.test.ts`, `corpus-benchmark.test.ts`, and `full-workflow.e2e.test.ts`. |
| Trivy offline DB staleness / freshness inspection | **NOT_IMPLEMENTED** | `packages/scanners/src/trivy.ts` checks `trivy.db` existence, but does not inspect `metadata.json` (`UpdatedAt`) to warn on outdated vulnerability databases. |
| Canonical normalization, dedupe & lifecycle verification | **VERIFIED** | `packages/findings/src/normalizer.ts`, `fingerprint.ts`, `lifecycle.ts`; verified in `findings.test.ts` and `full-workflow.e2e.test.ts`. |
| Tenant-keyed HKDF + HMAC-SHA256 secret fingerprinting & redaction | **VERIFIED** | `packages/security/src/secrets.ts`, ReDoS-hardened PEM scrubber & chunked redaction; verified in `security.test.ts` and E2E zero-leak assertions. |
| Optional provider-agnostic AI Analyst + pre-LLM redaction gate | **VERIFIED** | `packages/ai/src/analyst.ts`, `provider.ts`; prompt-injection fencing, Zod validation, fail-closed redaction verified in `ai.test.ts`. |
| Streaming JSON, SARIF 2.1.0, CSV report exports | **VERIFIED** | `packages/findings/src/exporters.ts`; CSV formula neutralization and secret assertions verified in `findings.test.ts` and E2E tests. |
| Tenant isolation & auth/CSRF enforcement | **VERIFIED** | `apps/api/src/middleware/auth.ts` + explicit `organizationId` scoping on every route; verified in `tests/security/security-controls.test.ts`. |
| Docker Compose scanner isolation (`read_only`, `cap_drop`, `internal: true`) | **PARTIALLY_VERIFIED** | Declared in `docker-compose.yml`, **however** a runtime conflict exists: `scanner-runner` mounts `/shared-workspaces:ro` while `workspaceGuard.ts` calls `fs.unlink` on unsafe symlinks (would throw `EROFS` in Compose). |
| gVisor / Kata microVM runtime execution | **PARTIALLY_VERIFIED** | `buildHardenedOciArgs` and sandbox YAML/Compose profiles exist and are unit-tested, **but** `IsolatedScannerRunner` never spawns OCI/gVisor containers at runtime — it spawns binaries directly in its own process. |
| Per-organization `security_policies` enforcement | **DOCUMENTED_ONLY** | `security_policies` table exists and is seeded (`maxRepoSizeMb`, `maxConcurrentScans`, `allowAiAnalysis`), **but zero runtime code queries or enforces it**. |
| `scanner_metadata` live health sync | **DOCUMENTED_ONLY** | Table exists and is seeded with static defaults, but is never updated from live `scanner-runner` health checks and has no API endpoint. |
| Artifact retention expiry sweeper | **DOCUMENTED_ONLY** | `scan_artifacts.expires_at` is persisted, but no background cleanup job purges expired artifacts. |
| External vulnerability intelligence enrichment (KEV / EPSS / OSV) | **NOT_IMPLEMENTED** | Risk prioritization currently uses severity, confidence, CVSS, fix availability, and secret exposure only. |
| CI/CD & GitHub Actions security analysis + OIDC federation analysis | **NOT_IMPLEMENTED** | No workflow parser, CI/CD rules, or OIDC trust-policy correlation exists yet. |
| Security context graph & attack-path correlation | **NOT_IMPLEMENTED** | Findings are stored independently without typed entity/relationship graphs. |
| Open-source community & release infrastructure | **NOT_IMPLEMENTED** | Missing `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `CHANGELOG.md`, `ROADMAP.md`, `SUPPORT.md`, issue/PR templates, and `.github/workflows/ci.yml`. |

---

## 1. What Is Implemented and Verified

- **Clean modular TypeScript monorepo** (`packages/*`, `services/scanner-runner`, `apps/*`) with strict TypeScript compilation and Zod contract validation across service boundaries.
- **Real, deterministic multi-engine scanning**: Semgrep CE (`1.186.0` with pinned offline ruleset), Trivy (`0.76.2` offline SCA + IaC), and Gitleaks (`8.30.1` working tree + full Git history).
- **Strong secret-handling discipline**: Tenant-keyed `HKDF-SHA256` + `HMAC-SHA256` fingerprinting, linear-time PEM scrubbing, chunked ReDoS-safe regex redaction, `finally`-block deletion of raw Gitleaks reports, artifact storage fail-closed guard, and pre-LLM redaction gate.
- **Honest verification & failure transparency**: Scanner failures (`FAILED`, `TIMEOUT`, `UNAVAILABLE`, `PARTIAL`) and Git history limitations (`NO_GIT_HISTORY`, `SHALLOW_CLONE_HISTORY_TRUNCATED`) yield `VERIFICATION_INCONCLUSIVE` rather than falsely closing findings. Secret findings explicitly mark validity as `NOT_VERIFIED`.
- **Audited finding lifecycle**: Strict state-transition validation (`assertValidStatusTransition`), immutable `finding_status_history`, `audit_events`, and automatic reopening on re-detection.
- **Streaming exports**: JSON, SARIF 2.1.0, and formula-safe CSV streams with per-chunk redaction checks.

## 2. What Is Implemented but Insufficiently Tested

- **BullMQ / Redis worker lifecycle** (`apps/worker/src/jobs/scanQueue.ts`): Queue retries, worker crash recovery, and active job cancellation via Redis have no automated integration tests.
- **S3/MinIO artifact adapter** (`packages/shared/src/storage.ts`): Automated tests exercise `LocalArtifactStorage`; `S3ArtifactStorage` is untested in CI.
- **Docker Compose end-to-end stack**: No automated smoke test verifies the multi-container `worker -> http://scanner-runner:4100` path over `:ro` workspace mounts.
- **Web frontend (`apps/web`)**: Builds cleanly with TypeScript and Next.js, but has zero component or Playwright browser tests.

## 3. What Is Documented but Not Implemented

- **`security_policies` enforcement**: Seeded in PostgreSQL, never read by API or worker.
- **Live `scanner_metadata` tracking**: Static seed rows only; no `/api/v1/scanners/health` endpoint or health sync.
- **Artifact expiration cleanup**: `expires_at` column stored, no scheduled sweeper.
- **Per-scan OCI/gVisor container execution**: `buildHardenedOciArgs` exists as a helper, not wired into `IsolatedScannerRunner.executeScan()`.
- **Linting pipeline**: Root `npm run lint` runs `--if-present` over workspaces that have no `lint` script.

## 4. Security Risks Identified in Code Audit

| Severity | Finding | Location | Remediation |
|---|---|---|---|
| **High** | **Read-only mount vs. symlink unlink conflict (`EROFS`)**: `docker-compose.yml` mounts `/shared-workspaces:ro` into `scanner-runner`, while `workspaceGuard.ts` calls `fs.unlink()` on unsafe symlinks. An adversarial repo with an escaping symlink will crash the runner instead of cleanly sanitizing. | `docker-compose.yml:91`, `packages/security/src/workspace.ts:124`, `apps/worker/src/ingestion/repositoryIngestor.ts` | Sanitize symlinks during writable ingestion in `repositoryIngestor.ts`, and handle `EROFS`/`EACCES` in `workspaceGuard.ts` by rejecting the scan with a typed limitation/failure rather than an unhandled 500. |
| **Medium** | **Unrestricted `localFixturePath` in dev `DEMO_MODE`**: `POST /api/v1/projects` allows any local filesystem path when `DEMO_MODE=true`. | `apps/api/src/routes/platform.ts:386` | Restrict `localFixturePath` via `validateSafePathWithinRoot` to an explicit approved fixtures directory (e.g., `tests/fixtures` or configured root). |
| **Medium** | **Permissive production CORS origins**: `apps/api/src/server.ts` hardcodes `http://localhost:3000` and `http://127.0.0.1:3000` into CORS `origin` even when `NODE_ENV=production`. | `apps/api/src/server.ts:60` | Only include localhost origins when `NODE_ENV !== "production"`. |
| **Medium** | **Unvalidated UUID path parameters cause HTTP 500**: `:projectId`, `:scanId`, `:findingId` are passed directly into PostgreSQL UUID columns without Zod UUID validation. | `apps/api/src/routes/platform.ts:521,702,902` | Validate all UUID route params and return HTTP 400 `VALIDATION_ERROR`. |
| **Medium** | **`security_policies.allowAiAnalysis` bypassed**: An org disabling AI via `security_policies` would still allow `/analyze` and `/advisor/ask`. | `apps/api/src/routes/platform.ts:1080,1155` | Query `security_policies` before invoking AI or accepting concurrent scans. |
| **Low** | **Stale offline Trivy DB undetectable**: Trivy offline scans succeed silently even if `trivy.db` is months out of date. | `packages/scanners/src/trivy.ts:242` | Parse `.trivy-cache/db/metadata.json` (`UpdatedAt`), surface DB age in health/provenance, and emit a `TRIVY_DB_STALE` limitation when older than threshold (default 14 days). |

## 5. Technical Debt

- `apps/api/src/routes/platform.ts` is 1,464 lines in a single file — should be split by domain (projects, scans, findings, reports, advisor, workflows) as new capabilities are added.
- Dashboard `repositoriesScanned` counts unique `projectId` values from only the 10 most recent scans rather than all org scans.
- Findings query sorts exclusively by `lastSeenAt` without priority/severity sorting or `riskPriority` filtering.
- Hardcoded scanner list `["semgrep", "trivy", "gitleaks"]` appears in multiple places (`contracts/scans.ts`, `contracts/scanners.ts`, `database/schema.ts`, `scanner-runner/server.ts`, `worker/scanProcessor.ts`, `web/findings/page.tsx`) instead of a single canonical scanner registry constant.

## 6. Architectural Improvements Needed

1. **Unified Scanner & Analyzer Registration**: Expand `ScannerNameSchema`, `FindingCategorySchema` (add `CICD`), and `FindingEvidenceSchema` (add `WORKFLOW_CONFIG`, `OIDC_TRUST_POLICY`) while preserving 100% backward compatibility with existing findings and migrations.
2. **Enriched Evidence & Prioritization Model**: Add optional, backward-compatible contextual enrichment fields (e.g., CISA KEV / EPSS / reachability / exposure provenance with explicit `VERIFIED` / `INFERRED` / `UNKNOWN` evidence states) without inventing scores.
3. **Dedicated CI/CD Security Intelligence Package (`packages/cicd-security`)**: Implement a deterministic, AST/line-aware YAML analyzer for GitHub Actions and static OIDC cloud trust correlation that implements Indicative's `ScannerAdapter` contract so it integrates cleanly into the isolated runner, canonical finding lifecycle, SARIF/JSON/CSV exporters, and Web UI.
4. **Open-Source Community & CI Foundation**: Add governance, security disclosure policy, contributing guide, changelog, roadmap, GitHub templates, and a self-testing GitHub Actions CI workflow (dogfooding Indicative's own CI/CD security rules!).

## 7. What Should Remain Unchanged

- Modular TypeScript monolith + independently deployable `worker` and `scanner-runner` topology.
- PostgreSQL 16 + Drizzle ORM + Zod contract-first architecture (no premature Rust rewrite or graph database).
- Core `ScannerAdapter` abstraction and pinned Semgrep / Trivy / Gitleaks engines.
- Zero-plaintext secret pipeline (`HKDF-SHA256` + `HMAC-SHA256`, fail-closed redaction gates).
- Advisory-only AI Security Analyst with zero tool-execution authority.

## 8. What Should Be Simplified or Removed

- Remove hardcoded `localhost:3000` CORS fallback in production mode.
- Consolidate duplicate scanner-name arrays into shared constants exported from `@indicative/contracts`.
- Keep `README.md` status table strictly aligned with verified capabilities (no speculative claims).

## 9. Production-Readiness Gaps (Unchanged Multi-Tenant Prerequisites)

- MicroVM / gVisor (`runsc`) or Kata per-scan runtime orchestration for untrusted multi-tenant code.
- PostgreSQL Row-Level Security (RLS) policies as defense-in-depth alongside service-layer `organization_id` filters.
- External KMS/HSM secret management (`SECRET_FINGERPRINT_KEY`, `SESSION_SECRET`, `GITHUB_APP_PRIVATE_KEY`) and TLS everywhere.
- Scheduled artifact retention sweeper and per-organization AI token budgets.
- GitHub Webhook HMAC verification (`X-Hub-Signature-256`) for automated push/PR scanning.

## 10. Recommended Immediate Priorities

1. **P0 (Immediate):** Fix the audited security bugs (`EROFS` symlink sanitization order, UUID validation, prod CORS hardening, `localFixturePath` confinement, `security_policies` enforcement) and establish full open-source community & CI/CD hygiene (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `CHANGELOG.md`, `ROADMAP.md`, `SUPPORT.md`, `docs/community/`, `.github/*`).
2. **P1 (Core Engine):** Add Trivy offline DB freshness checks, CISA KEV / EPSS offline-capable vulnerability enrichment hooks with explicit provenance, and enhanced transparent risk prioritization (preserving original severity and explicitly distinguishing verified vs. inferred vs. unknown context).
3. **P1 (Flagship Vertical Slice):** Build `packages/cicd-security` — a deterministic GitHub Actions & static OIDC federation security analyzer integrated end-to-end across `scanner-runner` → `findings` → `worker` → `api` → `web` (including a dedicated Workflow Security view), backed by a vulnerable & hardened fixture corpus with measured precision/recall.
