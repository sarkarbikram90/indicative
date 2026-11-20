# Indicative — MVP Scope & Acceptance Criteria

## 1. Repository Baseline Assessment (Phase 0)

Prior to implementation, the `indicative` repository contained only `.gitignore` (Rust template), `Agent.md`, `LICENSE` (Apache-2.0), and a two-line `README.md` stub. No application code, schema, API, or tests existed; the proposed TypeScript monorepo architecture was adopted directly.

## 2. In-Scope MVP Capabilities (Implemented & Verified)

| # | Capability | Implementation Component |
|---|---|---|
| 1 | GitHub repository integration | GitHub OAuth sign-in (signed CSRF state) + GitHub App installation & short-lived installation token discovery (`apps/api`, `apps/worker`) |
| 2 | Repository security scanning | Asynchronous BullMQ scan orchestration (`apps/worker`) invoking isolated `services/scanner-runner` |
| 3 | Static Application Security Testing (SAST) | Semgrep CE `1.186.0` adapter with pinned offline ruleset `indicative-sast-v1.0.0` for JS/TS/Python (`packages/scanners`) |
| 4 | Dependency & configuration scanning (SCA & IaC) | Trivy `0.76.2` offline filesystem scanner (`vuln,misconfig`) covering lockfiles + Docker, Kubernetes, and Terraform (`packages/scanners`) |
| 5 | Exposed secret detection | Gitleaks `8.30.1` `dir` mode over current working tree (`packages/scanners`) |
| 6 | Git history secret scanning | Gitleaks `8.30.1` `git` mode across preserved commit history with explicit limitation reporting (`NO_GIT_HISTORY`, `SHALLOW_CLONE_HISTORY_TRUNCATED`, `GIT_HISTORY_SCAN_FAILED`) |
| 7 | Security findings normalization | Canonical `SecurityFinding` schema preserving original severity, scanner provenance, and evidence (`packages/findings`) |
| 8 | Findings deduplication | Deterministic category-specific fingerprinting + tenant-keyed HKDF/HMAC-SHA256 secret correlation (`packages/findings`, `packages/security`) |
| 9 | Evidence-backed severity & confidence | Normalized severity/confidence + transparent qualitative risk prioritization (`riskPriority`, `riskRationale`) |
| 10 | AI-assisted contextual analysis | Optional provider-agnostic OpenAI-compatible AI Security Analyst & scoped Advisor with pre-LLM redaction gate and prompt-injection defenses (`packages/ai`) |
| 11 | Security findings dashboard | Next.js 15 + Tailwind UI: Landing/Auth, Dashboard, Projects, Scan Details, Findings, Finding Details, AI Advisor (`apps/web`) |
| 12 | Scan history and comparison | Persistent scan timeline, per-scanner execution records, and scan-over-scan diff (new / recurring / not detected / reopened / inconclusive) |
| 13 | Remediation recommendations | Root cause, vulnerable location, remediation guidance, and optional AI patch suggestion (read-only) |
| 14 | Scanner-based verification | Re-scan comparison updating finding lifecycle and precise verification states (`VERIFICATION_SUCCESSFUL_WITHIN_SCANNED_SCOPE` / `VERIFICATION_INCONCLUSIVE`) |
| 15 | Exportable security reports | Redacted JSON, SARIF 2.1.0, and CSV exports containing scan metadata, scanner provenance, and evidence (`packages/findings`, `apps/api`) |

## 3. Explicitly Out of Scope for MVP

- Autonomous penetration testing, DAST, automated exploitation, or arbitrary website scanning
- Cloud account security posture management (CSPM), Kubernetes runtime cluster scanning, and full runtime monitoring (RASP/APM)
- Automatic credential revocation or automatic secret rotation
- Automatic source-code modification, commit pushing, or autonomous pull request creation
- Multi-agent autonomous security systems
- Strix engine integration (supported as a future `ScannerAdapter` extension)
- Automatic GitHub push/PR webhook scanning (manual/API scan initiation is the MVP trigger)
- Enterprise billing, subscriptions, complex custom RBAC, and mobile applications

## 4. Acceptance Criteria Verification Status (Agent.md §23)

| # | Criterion | Status & Evidence |
|---|---|---|
| 1 | Repository integration | Verified in `tests/integration/platform.integration.test.ts` |
| 2 | Real scanning | Verified independently & E2E with Semgrep `1.186.0`, Trivy `0.76.2`, Gitleaks `8.30.1` |
| 3 | Full-history secret detection | Verified in `tests/e2e/full-workflow.e2e.test.ts` & `tests/regression/corpus-benchmark.test.ts` |
| 4 | Normalized findings | Verified across SAST/SCA/SECRET/IAC in `packages/findings/src/findings.test.ts` & E2E |
| 5 | Secure secret handling | Zero plaintext leaks verified across DB, API, JSON/SARIF/CSV reports, logs, artifacts, and AI prompts |
| 6 | Finding lifecycle | Verified in `packages/findings/src/findings.test.ts` & E2E |
| 7 | AI contextual analysis | Verified with enabled & disabled providers in `packages/ai/src/ai.test.ts` & E2E |
| 8 | Evidence-backed reporting | Verified in `apps/web`, `packages/findings`, and API report export endpoints |
| 9 | Re-scanning and verification | Verified with real remediation Git commit + Scan #2 in `tests/e2e/full-workflow.e2e.test.ts` |
| 10 | Security controls | Verified in `packages/security/src/security.test.ts` & `tests/security/security-controls.test.ts` |
| 11 | Automated tests | `8/8` test files, `29/29` tests passing; regression corpus `20/20` recall, `1.0` precision, `0` FPR |
| 12 | Reproducible local deployment | Validated `docker-compose.yml`, `.env.example`, Dockerfiles, `README.md`, and live compiled binary smoke tests |

## 5. Honesty & Non-Goal Constraints

- Never claim a criterion is complete without execution evidence.
- Never present mocked scanner responses as real scanner execution.
- Never present a shallow, current-branch-only Gitleaks scan as a full-history scan.
- Never claim production multi-tenant isolation solely because Docker containers are used.
- Clearly distinguish demo mode (`isDemo: true`, strictly blocked in production) from real customer scans.
