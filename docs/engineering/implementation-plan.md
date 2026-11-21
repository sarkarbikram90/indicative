# Indicative — Implementation Plan

## Execution Status Summary

All MVP phases (Phases 0–7) defined in `Agent.md §24` have been implemented and verified with automated unit, integration, security, real-scanner end-to-end, and regression corpus tests (`8/8` test files, `29/29` tests passing).

| Phase | Scope | Key Deliverables | Verification Gate | Status |
|---|---|---|---|---|
| **Phase 0** | Repository Assessment & Architecture | Product strategy, MVP scope, system architecture, threat model (`T1`–`T11`), canonical finding schema, ADRs (`ADR-001`–`ADR-013`), implementation plan | All 7 docs authored and aligned with actual implementation | ✅ Complete |
| **Phase 1** | Foundation | Monorepo workspaces, `packages/config`, `packages/contracts`, `packages/security`, `packages/shared`, `packages/database` (19 tables + SQL migration + seed), `apps/api`, `apps/worker` BullMQ, `apps/web`, `docker-compose.yml`, `.env.example` | All 12 workspaces compile/typecheck cleanly; `docker compose config --quiet` valid; migrations & seed verified | ✅ Complete |
| **Phase 2** | Repository Integration | GitHub OAuth (signed CSRF state), GitHub App RS256 JWT + short-lived installation token discovery, project/repo linking, hardened full-history ingestion, idempotent scan queuing | Mocked GitHub API integration tests + real multi-commit Git ingestion verified; zero token leakage | ✅ Complete |
| **Phase 3** | Scanner Execution | `services/scanner-runner`, workspace sanitization, resource limits, pinned Semgrep `1.186.0` + bundled JS/TS/Python ruleset (`indicative-sast-v1.0.0`), pinned Trivy `0.76.2` offline DB, pinned Gitleaks `8.30.1` (`dir` + `git`), health checks | All 3 scanners demonstrated independently and via compiled runner `/health` | ✅ Complete |
| **Phase 4** | Findings Intelligence | Canonical `SecurityFinding` schema, output parsers, normalization, category-specific fingerprinting, tenant-keyed HKDF+HMAC secret correlation, deduplication, lifecycle state machine, scan comparison & verification, qualitative risk prioritization, JSON/SARIF/CSV exports | Unit + E2E tests verify dedupe, lifecycle transitions, `VERIFICATION_INCONCLUSIVE` on failure, and zero secret leaks | ✅ Complete |
| **Phase 5** | AI Security Analyst | Provider-agnostic `AiProvider`, `DisabledAiProvider`, `OpenAiCompatibleProvider`, pre-LLM secret redaction gate, `<UNTRUSTED_REPOSITORY_DATA>` fencing, Zod output validation, model/prompt versioning, scoped AI Advisor | Unit + E2E tests verify disabled fallback, secret blocking, invalid JSON/refusal/429 handling, and prompt-injection resilience | ✅ Complete |
| **Phase 6** | Dashboard & Reporting | Full `/api/v1/*` REST API + OpenAPI 3.1 `/docs`, Landing/Auth, Dashboard, Projects, Scan Details, Findings, Finding Details, AI Advisor, JSON/SARIF/CSV downloads | Next.js 15 production build passes (`8` routes); live compiled API smoke tests pass | ✅ Complete |
| **Phase 7** | Verification & Hardening | Regression corpus (`vulnerable-app` + `clean-app`), unit/integration/security/E2E suites, tenant isolation tests, runner hardening tests, production-readiness assessment | `29/29` tests pass; measured corpus baseline: `20/20` recall, `1.0` precision, `0` FPR, `0` parsing/scanner failures | ✅ Complete |

## Post-MVP Hardening Roadmap
See [Production-Readiness Assessment](production-readiness.md) and [Rust Performance Evaluation](rust-performance-evaluation.md) for microVM/gVisor multi-tenant isolation, PostgreSQL RLS, Cloud KMS key management, automated webhook scans, and objective ADR-014 profiling criteria.
