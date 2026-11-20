# Indicative — Implementation Plan

## 0. Current repository state

At the time of writing, the repository `sarkarbikram90/indicative` contains only `.gitignore`, `Agent.md`, `LICENSE`, and `README.md`; there is no existing application code. This is a greenfield implementation. The proposed architecture in Agent.md §5 is therefore adopted directly, with the local working directory treated as the monorepo root.

Foundation files may be created by a separate workstream; this plan defines the target structure regardless of which files already exist.

## 1. Guiding constraints

- Build the smallest reliable, demonstrable MVP — not a mockup.
- No dead buttons, no fabricated findings, no mocked scanners presented as real.
- Security requirements are not weakened to simplify demonstration.
- Each phase must produce verifiable output before the next begins.
- Do not ask for approval after every small decision; document assumptions and proceed.

## 2. Phase 0 — Repository assessment and architecture

**Status:** Documentation produced (`docs/product/*`, `docs/architecture/*`, `docs/engineering/*`).

Deliverables:
- Recorded existing state (empty/greenfield)
- Confirmed technology stack
- System architecture, threat model, finding schema
- Implementation plan and architecture decisions

## 3. Phase 1 — Foundation

Build:
- Monorepo structure and workspace tooling
- `packages/contracts` — Zod schemas and shared types
- `packages/config` — validated environment configuration
- `packages/shared` — logging, errors, correlation IDs
- `packages/security` — redaction, keyed HMAC fingerprints, path safety
- `packages/database` — Drizzle schema, migrations, seeds
- `apps/api` — Fastify server, authN/authZ, error handling, audit
- `apps/web` — Next.js shell and design system
- Redis + BullMQ infrastructure
- Docker Compose for Postgres, Redis, MinIO, API, worker, web, runner
- `.env.example`

Verification: services start, health checks pass, migrations run, config validation rejects bad input.

## 4. Phase 2 — Repository integration

Build:
- GitHub App configuration and minimum read-only permissions
- OAuth state/CSRF handling and user authentication
- Repository discovery and selection
- Trusted ingestion with short-lived installation tokens
- Commit SHA and branch metadata capture
- Full Git history preservation for Gitleaks
- Scan creation, idempotency, and queueing

Verification: mocked GitHub responses in integration tests; authorization checks on every operation; no tokens in logs or frontend.

## 5. Phase 3 — Scanner execution

Build:
- `services/scanner-runner` with isolated, ephemeral workspaces
- Safe process spawning (argument arrays, allowlisted binaries, timeouts, resource limits)
- Semgrep adapter (pinned version and ruleset; JS/TS/Python)
- Trivy adapter (filesystem SCA + selected misconfigurations; controlled DB updates)
- Gitleaks adapter (current content + Git history, with explicit limitation reporting)
- Health checks, execution status, error classification, structured output parsing

Verification: each scanner demonstrated independently against the regression corpus; versions and command flags verified against official documentation for the pinned versions.

## 6. Phase 4 — Findings intelligence

Build:
- Canonical finding schema and Zod validation
- Parser → normalizer pipeline for all three scanners
- Severity/category normalization with original values preserved
- Category-specific deterministic fingerprints
- Secret redaction and keyed HMAC secret fingerprints
- Deduplication, occurrence tracking, status transitions
- Persistence and scan comparison (new / recurring / not detected)

Verification: unit tests for normalization, mapping, fingerprint stability, dedupe, redaction, and lifecycle; integration test persisting findings and comparing scans.

## 7. Phase 5 — AI Security Analyst

Build:
- Provider-agnostic LLM adapter, OpenAI-compatible where supported
- Graceful disable when no API key is configured
- Secret-redaction stage before every AI request
- Minimal scoped context collection
- Structured, schema-validated responses
- Handling for invalid JSON, refusals, timeouts, provider errors, rate limits, token limits
- Model and prompt version recorded per analysis

Verification: deterministic scanning works with AI disabled; tests cover redaction and malformed model output; prompt-injection tests confirm repository text is treated as data.

## 8. Phase 6 — Dashboard and reporting

Build:
- Landing/sign-in/GitHub connection flow
- Dashboard summaries (counts, trends, recent scans/activity — no meaningless scores)
- Projects, scan details, findings list with filters
- Finding detail page with evidence, source context, AI analysis, remediation, history
- AI Security Advisor scoped to project/scan/finding
- Reports: JSON, SARIF (where mappable), CSV — redacted, with provenance

Verification: UI renders real API data; reports contain no plaintext secrets.

## 9. Phase 7 — Verification and hardening

Build:
- Regression corpus with intentionally vulnerable and clean repositories, dummy credentials only
- Unit, integration, security, and end-to-end tests
- Security tests: tenant isolation, authz failures, prompt injection, malicious filenames, path traversal, symlinks, command injection, timeouts, resource exhaustion, SSRF, internal network restrictions, secret leakage, malformed output
- Resource limits, retention configuration, production-readiness assessment

Verification: actual scanner execution in e2e tests; measured precision/recall/false-positive baseline (no invented numbers); documented limitations.

## 10. Definition of complete

The MVP is complete only when acceptance criteria in `docs/product/mvp-scope.md` are demonstrable with evidence and the final deliverables in Agent.md §26 are present, with implemented vs planned functionality clearly distinguished.
