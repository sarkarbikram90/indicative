# Indicative — Architecture Decision Records

This file records important engineering decisions. Each decision captures context, choice, and consequences. Decisions may be revisited as the MVP is validated.

---

## ADR-001 — Modular monolith with separate workers

**Context:** The platform needs a web app, API, asynchronous scanning, isolated execution, and an AI module. Agent.md explicitly warns against unnecessary microservices and premature complexity.

**Decision:** Implement one modular codebase with clear package boundaries (`contracts`, `config`, `security`, `database`, `scanners`, `findings`, `ai`, `shared`) and separately deployable `api`, `worker`, and `scanner-runner` processes.

**Consequences:** Simpler local development and testing; shared types without network contracts. Execution still scales independently through workers. Boundaries must be enforced by discipline and tooling, not only by directory structure.

---

## ADR-002 — TypeScript everywhere

**Context:** Strong typing is needed for finding schemas, scanner output parsing, and API contracts.

**Decision:** Use TypeScript across web, API, worker, runner, and shared packages. Use Zod for runtime validation at boundaries.

**Consequences:** Compile-time safety plus runtime validation of untrusted input. Adds a build step and requires dependency version discipline.

---

## ADR-003 — Fastify + Zod for the API

**Context:** Need a versioned REST API with validation, consistent errors, pagination, filtering, rate limiting, and audit logging.

**Decision:** Fastify with Zod-validated request schemas and a shared error envelope.

**Consequences:** High performance and good typing; Zod schemas can be reused in the frontend where practical.

---

## ADR-004 — PostgreSQL + Drizzle ORM

**Context:** Finding lifecycle, tenant ownership, scan history, and audit events are relational concerns requiring integrity constraints.

**Decision:** PostgreSQL with Drizzle ORM, migrations, and seed scripts.

**Consequences:** Strong constraints and indexes; no second ORM. Tests that do not require a database should avoid depending on a live Postgres instance.

---

## ADR-005 — Redis + BullMQ for scan jobs

**Context:** Scanners must never run inside HTTP request handlers; jobs need retries, timeouts, cancellation, and concurrency control.

**Decision:** Redis-backed BullMQ queues with explicit scan states and idempotent job processing.

**Consequences:** Asynchronous UX and resilient processing. Requires Redis in local development and careful idempotency design.

---

## ADR-006 — Separate trusted ingestion from untrusted execution

**Context:** GitHub installation tokens must never reach scanners, and scanners must not clone arbitrary URLs.

**Decision:** The worker retrieves a validated repository snapshot through trusted ingestion; only the snapshot is mounted into the isolated scanner runner.

**Consequences:** Limits token exposure and SSRF risk. Requires careful workspace lifecycle management.

---

## ADR-007 — Secret redaction and keyed HMAC fingerprints

**Context:** Plaintext credentials must never appear in UI, logs, database, AI requests, or reports, yet the same leaked credential across files/commits must correlate.

**Decision:** Central redaction stage on all untrusted output; display masking; correlation using keyed HMAC with a tenant-specific key. No plaintext secret storage.

**Consequences:** Secure correlation without disclosure. Requires secure key management and rotation policy for production. Redaction is a safety net, not a guarantee.

---

## ADR-008 — Category-specific deterministic fingerprints

**Context:** Title-only deduplication fails when scanner messages vary or the same secret appears in multiple locations.

**Decision:** Build fingerprints from scanner, rule, normalized location, and category-specific identity (CVE/package for SCA, keyed secret HMAC for secrets).

**Consequences:** Stable cross-scan tracking and meaningful correlation. Location normalization must be consistent to avoid duplicate fingerprints.

---

## ADR-009 — AI is optional and sanitized

**Context:** The product must work without an LLM API key, and repositories are untrusted input that may attempt prompt injection.

**Decision:** Provider-agnostic adapter; AI disabled gracefully when unconfigured; redaction before requests; minimal scoped context; structured validated output; no tools or autonomous actions; model/prompt version recorded.

**Consequences:** Deterministic scanning always works. AI output is clearly labelled analysis, never evidence. Requires schema validation and careful prompt design.

---

## ADR-010 — Pinned scanners and controlled rule/DB updates

**Context:** Scanner flags, output schemas, and rulesets change between versions; untrusted scans cannot rely on internet access.

**Decision:** Pin and document scanner versions and rulesets; verify CLI flags and output schema against official docs for the pinned versions; update vulnerability databases through a controlled mechanism.

**Consequences:** Reproducible regression testing and safer execution. Requires periodic maintenance when versions are upgraded.

---

## ADR-011 — Failure transparency

**Context:** A crashed scanner can look like "no findings", which is dangerous in security tooling.

**Decision:** Distinguish success-with-findings, success-with-zero-findings, partial results, failure, timeout, cancellation, and scanner-unavailable. Surface these states in UI and reports. Never auto-resolve findings purely because they disappeared.

**Consequences:** More complex state model, but no false assurance. UI must communicate nuance with precise terminology.

---

## ADR-012 — Development demo mode is explicitly non-production

**Context:** Local demonstration needs credentials-free flows, but a hidden bypass would be a serious vulnerability.

**Decision:** If a demo mode exists, it is development-only, clearly labelled, and cannot silently become a production auth bypass. Demo fixtures are distinguishable from real scans.

**Consequences:** Easier local validation without weakening production security. Requires configuration guards and visible labelling.

---

## ADR-013 — Docs reflect implementation

**Context:** Large build prompts tend to produce documentation disconnected from code.

**Decision:** Documentation describes the actual architecture and decisions; acceptance criteria require evidence; implemented and planned functionality are clearly separated.

**Consequences:** Documentation must be updated as implementation progresses; no unverified capability claims.
