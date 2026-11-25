# Indicative — Architecture Decision Records (ADRs)

This file records key engineering decisions made for the Indicative MVP, capturing context, decision, and consequences.

---

## ADR-001 — Modular Monolith with Separately Deployed Execution Workers
- **Context:** The platform requires a web UI, REST API, async job processing, isolated scanner execution, and an optional AI module without premature microservice overhead.
- **Decision:** Implement one TypeScript (`npm` workspaces) monorepo with clear package boundaries (`config`, `contracts`, `security`, `shared`, `database`, `scanners`, `findings`, `ai`) and four runtime units (`apps/web`, `apps/api`, `apps/worker`, `services/scanner-runner`).
- **Consequences:** Single-command local development via Docker Compose, shared Zod/TS contracts, and independent scaling/isolation of scanner workers.

## ADR-002 — TypeScript & Zod Runtime Validation Across All Boundaries
- **Context:** Untrusted HTTP inputs, scanner JSON outputs, environment config, and LLM JSON responses require strict compile-time and runtime validation.
- **Decision:** Standardize on TypeScript 5.7+ with strict settings and Zod 3 schemas in `packages/contracts` and `packages/config`.
- **Consequences:** Prevents malformed data from entering persistence or UI flows; requires maintaining schema alignment during builds.

## ADR-003 — Fastify 5 REST API with OpenAPI 3.1
- **Context:** Need versioned REST endpoints (`/api/v1/*`) with rate limiting, security headers, cookie/CSRF + Bearer auth, consistent non-leaking errors, correlation IDs, and OpenAPI documentation.
- **Decision:** Use Fastify 5 with `@fastify/helmet`, `@fastify/cors`, `@fastify/cookie`, `@fastify/rate-limit`, and `@fastify/swagger` / `@fastify/swagger-ui`.
- **Consequences:** High throughput, automatic OpenAPI docs at `/docs`, and clean route testing via `app.inject()`.

## ADR-004 — PostgreSQL 16 + Drizzle ORM (with PGlite for Self-Contained Tests)
- **Context:** Multi-tenant projects, scans, findings, occurrences, status history, and audit trails require relational integrity, foreign keys, unique constraints, and composite indexes.
- **Decision:** Use PostgreSQL 16 with Drizzle ORM and SQL migrations (`packages/database/migrations/0001_initial.sql`). Support `@electric-sql/pglite` in automated test suites and dev fallback so real PostgreSQL DDL/SQL executes without requiring an external Postgres daemon.
- **Consequences:** Single ORM, strong schema guarantees, and fast, reproducible automated tests.

## ADR-005 — Redis + BullMQ for Asynchronous Scan Orchestration
- **Context:** Security scans are long-running and must never execute inside HTTP handlers.
- **Decision:** Use Redis-backed BullMQ queues (`apps/worker/src/jobs/scanQueue.ts`) with idempotent `jobId`s, retries, concurrency limits, and explicit scan states (`QUEUED` through `COMPLETED` / `COMPLETED_WITH_ERRORS` / `FAILED` / `CANCELLED`), plus an in-process async fallback for self-contained tests.
- **Consequences:** Resilient asynchronous UX and clean separation between API and worker execution.

## ADR-006 — Separation of Trusted Repository Ingestion from Untrusted Scanner Execution
- **Context:** Cloning private repositories requires short-lived GitHub App installation tokens and internet access, whereas scanning untrusted code must have neither credentials nor outbound network access.
- **Decision:** `apps/worker` performs hardened Git ingestion using transient HTTP authorization headers (never persisted to `.git/config`), sanitizes symlinks/paths/limits, and delegates scanning to `services/scanner-runner` over an internal-only Docker network (`scanner_internal: internal: true`).
- **Consequences:** Compromised scanner processes cannot access GitHub tokens, cloud metadata endpoints, or external networks.

## ADR-007 — Tenant-Keyed HKDF + HMAC-SHA256 Secret Fingerprinting & Mandatory Redaction
- **Context:** Plaintext credentials must never reach the DB, UI, logs, reports, or LLMs, yet duplicate occurrences of the same leaked secret across files and Git history must correlate.
- **Decision:** Derive per-organization 32-byte keys via `HKDF-SHA256(SECRET_FINGERPRINT_KEY, salt=organizationId, info="indicative:secret-fingerprint:v1")`, compute `HMAC-SHA256` (`hmac-sha256:v1:<hex>`), mask display values, and delete raw Gitleaks output immediately in `finally`.
- **Consequences:** Deterministic tenant-isolated correlation with zero plaintext persistence; requires Cloud KMS/HSM key management in production.

## ADR-008 — Category-Specific Deterministic Fingerprinting
- **Context:** Title-only deduplication breaks across edits, scanner updates, and multi-file secret leaks; naive SCA keys including `installedVersion` break tracking when a package bumps to another still-vulnerable version.
- **Decision:** Compute SHA-256 fingerprints per category (`SAST`: rule + file + code anchor; `SCA`: file/lockfile + package + CVE/rule; `IAC`: rule + file + resource/line bucket; `SECRET`: secretType + tenant HMAC fingerprint).
- **Consequences:** Stable cross-scan tracking and accurate multi-file/commit secret correlation.

## ADR-009 — Optional, Sanitized AI Security Analyst with Deterministic Core
- **Context:** Indicative must function completely without an LLM API key, and scanned repositories are untrusted inputs susceptible to prompt injection.
- **Decision:** Implement a provider-agnostic `AiProvider` with `DisabledAiProvider` default and `OpenAiCompatibleProvider`, enforce a fail-closed pre-LLM secret redaction gate, wrap repository text in `<UNTRUSTED_REPOSITORY_DATA>` fences, validate JSON responses with Zod, grant zero tool access, and store `model`, `promptVersion`, latency, and token usage.
- **Consequences:** Deterministic scans always succeed; AI guidance is auditable and clearly marked advisory.

## ADR-010 — Pinned Offline Scanner Versions & Controlled DB Updates
- **Context:** Unpinned scanners or scan-time internet downloads break determinism and weaken air-gapped runner isolation.
- **Decision:** Pin exact versions (`Semgrep CE 1.186.0`, `Trivy 0.76.2`, `Gitleaks 8.30.1`), bundle our versioned offline Semgrep ruleset (`indicative-sast-v1.0.0`), and update Trivy's offline vulnerability DB/checks cache only through a controlled maintenance/build step (`infrastructure/scripts/update-trivy-db.sh`).
- **Consequences:** Zero scan-time egress dependency and 100% reproducible regression corpus testing (`20/20` coverage).

## ADR-011 — Scanner Failure Transparency & Honest Verification
- **Context:** Treating a crashed/timed-out scanner or shallow clone as "0 findings" causes dangerous false assurance.
- **Decision:** Track explicit per-scanner outcomes (`SUCCESS`, `FAILED`, `TIMEOUT`, `CANCELLED`, `PARTIAL`, `UNAVAILABLE`) and mark absent findings `VERIFICATION_INCONCLUSIVE` whenever the responsible scanner did not succeed cleanly over full applicable scope. Never equate secret removal from Git with credential revocation.
- **Consequences:** Clear, trustworthy verification semantics across scans and reports.

## ADR-012 — Development-Only Demo Mode with Production Startup Guardrails
- **Context:** Evaluators need a zero-credential local flow without risking an authentication bypass in production.
- **Decision:** Gate `DEMO_MODE` strictly to `NODE_ENV !== "production"`, throw `SECURITY_VIOLATION` on startup if `NODE_ENV=production` has `DEMO_MODE=true` or default `dev-only-*` secrets, visibly badge demo records (`isDemo: true`), and run real scanners against controlled local fixtures.
- **Consequences:** Safe, honest local evaluation with zero fabricated scan results.

## ADR-013 — Documentation Reflects Verified Implementation
- **Context:** Architecture docs easily drift into unverified claims.
- **Decision:** Keep all docs synchronized with actual code, pinned scanner versions, and measured test/benchmark results, clearly separating implemented features from planned milestones.
- **Consequences:** Every documented claim is backed by executable code and automated tests, and planned architecture specs are explicitly tagged as planned.

## ADR-014 — Unified Three-Pillar Cross-Boundary Security Model (Code × CI/CD × Cloud Identity)
- **Context:** Standalone SAST/SCA/Secrets scanners, workflow linters, and CSPM tools each have strong incumbents; isolated alert lists fail to show how application flaws, insecure GitHub Actions workflows, broad OIDC trust policies, and over-privileged cloud IAM roles combine into production compromise paths.
- **Decision:** Anchor Indicative's 12-month product architecture on connecting three boundaries — Application Security Intelligence, CI/CD Security Intelligence, and Cloud Identity Risk — into one evidence-backed correlation layer, built sequentially in verified vertical slices rather than simultaneously.
- **Consequences:** Focuses engineering investment on cross-boundary correlation (OIDC/IAM linking, attack-path intelligence, reachability) rather than duplicating point-tool checklists.

## ADR-015 — PostgreSQL-Backed Typed Security Context Graph with Per-Hop Provenance & Uncertainty
- **Context:** Attack-path correlation requires traversing relationships (`Repository → Workflow → OIDC Trust → IAM Role → Cloud Resource`) across multi-tenant organizations, while remaining practical to self-host via Docker Compose without operating a separate graph database cluster (e.g., Neo4j). Additionally, black-box attack-path tools erode practitioner trust when they hide unverified assumptions.
- **Decision:** Store typed entities, typed edges, and materialized attack paths in PostgreSQL 16 (`security_entities`, `security_edges`, `attack_paths`, `attack_path_steps`, strictly tenant-scoped by `organization_id`) using recursive CTEs for bounded 2–6 hop traversals. Require every edge to record `evidence_basis` (`VERIFIED_STATIC`, `VERIFIED_RUNTIME`, `INFERRED`, `UNKNOWN`), source file/line provenance, and explicit `unknown_controls` caveats (e.g., GitHub branch protection, environment approval gates, AWS SCPs, Permission Boundaries).
- **Consequences:** Zero extra database infrastructure for self-hosted teams, strict relational tenant isolation, and transparent, auditable attack paths where path confidence is bounded by the weakest hop.

## ADR-016 — Hybrid Static-First CI/CD & Cloud Identity Architecture with Segregated Live Verification
- **Context:** Detecting workflow-to-cloud privilege risks requires both deep GitHub Actions analysis and cloud IAM policy evaluation, while preserving Indicative's zero-egress, zero-credential `scanner-runner` trust boundary (ADR-006).
- **Decision:**
  1. Keep `@indicative/cicd-security` as the native AST structural extractor for workflows and OIDC trust policies, while permitting optional pinned external `ScannerAdapter`s (`zizmor`, `actionlint`) inside `services/scanner-runner` with cross-engine canonical deduplication.
  2. Build static AWS IAM policy & privilege-escalation analysis (`packages/cloud-identity`) over IaC/JSON first so full code-to-IAM paths work offline with zero cloud credentials.
  3. Defer optional read-only live cloud/SCM verification (`v0.6.0`) to a strictly segregated, opt-in control-plane connector — never granting live cloud or GitHub credentials to `scanner-runner`.
- **Consequences:** Preserves air-gapped untrusted-code isolation, delivers immediate offline value on IaC repositories, and creates a clean upgrade path from `STATIC_CONFIG` to `VERIFIED_RUNTIME` evidence.

## ADR-017 — Modeling AI Agents & MCP Servers as Non-Human Identities (NHIs) on the Shared Graph
- **Context:** AI coding assistants, autonomous agents, and MCP servers increasingly hold delegated credentials and execute actions across repositories, CI/CD pipelines, and cloud infrastructure. Building an isolated "AI security" bolt-on would fragment identity visibility.
- **Decision:** Model AI agents and MCP servers as first-class Non-Human Identity nodes (`AI_AGENT`, `MCP_SERVER`) on Indicative's shared Security Context Graph (`v0.7.0`), beginning with deterministic static analysis of MCP/agent manifests, credential bindings, and tool scopes aligned with OWASP ASI and OWASP MCP Top 10.
- **Consequences:** Reuses existing secret-safety, canonical finding lifecycle, and graph-traversal infrastructure to answer over-privileged agent questions with the same evidence and uncertainty guarantees as CI/CD and cloud identities.
