# Indicative — System Architecture

## 1. Architectural Style

Indicative is implemented as a **modular monolith with independently deployable execution workers** in a single TypeScript (`npm` workspaces) monorepo. Microservices are intentionally avoided for the MVP while preserving a strict trust boundary between trusted control-plane operations and untrusted repository scanning.

Core pipeline: `Detect → Understand → Prioritize → Recommend → Verify`

```text
+-----------------------------------------------------------------------------+
|                                  CLIENTS                                    |
|           Developer Browser (Next.js 15 App Router - apps/web :3000)        |
+--------------------------------------+--------------------------------------+
                                       | HTTPS / HttpOnly Cookie + CSRF
                                       v
+-----------------------------------------------------------------------------+
|                        CONTROL PLANE API (apps/api :4000)                   |
|  Fastify 5 + Zod + OpenAPI 3.1 + Rate Limit + Auth/Tenant Guard + Audit Log |
+------------------+-------------------+--------------------+-----------------+
                   |                   |                    |
                   v                   v                    v
            +------------+      +-------------+      +--------------+
            | PostgreSQL |      | Redis/BullMQ|      | MinIO (S3)   |
            | Drizzle ORM|      | Scan Queue  |      | Redacted     |
            +------------+      +------+------+      | Artifacts    |
                                       |             +--------------+
                                       v
+-----------------------------------------------------------------------------+
|                      BACKGROUND WORKER (apps/worker)                        |
|  1. Trusted GitHub Ingestion (short-lived installation token, size limits)  |
|  2. Ephemeral Workspace Preparation & Path/Symlink Sanitization             |
|  3. Dispatches Scan Job to Isolated Scanner Runner (no tokens passed)       |
|  4. Normalization, Deduplication, HMAC Fingerprinting, Scan Comparison      |
|  5. Persistence & Optional Sanitized AI Analysis (packages/ai)              |
+--------------------------------------+--------------------------------------+
                                       | scanner_internal (internal: true, ZERO egress)
                                       v
+-----------------------------------------------------------------------------+
|               ISOLATED SCANNER RUNNER (services/scanner-runner :4100)       |
|  Hardened non-root (10001) | Read-only rootfs | Cap-drop ALL | No Docker    |
|  socket | No cloud/GitHub creds | Network isolated (no outbound internet)   |
|                                                                             |
|    +------------------+  +------------------+  +------------------------+   |
|    | Semgrep 1.186.0  |  | Trivy 0.76.2     |  | Gitleaks 8.30.1        |   |
|    | Pinned offline   |  | Offline DB cache |  | Working tree (`dir`) + |   |
|    | JS/TS/Py ruleset |  | vuln,misconfig   |  | Git history (`git`)    |   |
|    +------------------+  +------------------+  +------------------------+   |
+-----------------------------------------------------------------------------+
```

## 2. Implemented Monorepo Layout

```text
indicative/
├── apps/
│   ├── web/                 # Next.js 15 + React 19 + Tailwind CSS dashboard
│   ├── api/                 # Fastify 5 REST API (/api/v1/*) + OpenAPI /docs
│   └── worker/              # BullMQ processor + trusted GitHub App ingestion
├── services/
│   └── scanner-runner/      # Isolated scanner execution + pinned Semgrep ruleset
├── packages/
│   ├── config/              # Zod env validation + production security guardrails
│   ├── contracts/           # Shared Zod schemas + TypeScript contracts
│   ├── security/            # Secret redaction, HKDF+HMAC fingerprints, SSRF, workspace & prompt safety
│   ├── shared/              # AppError, correlation IDs, Prometheus metrics, S3/MinIO & local storage
│   ├── database/            # Drizzle ORM schema (19 tables), SQL migrations, seed script
│   ├── scanners/            # ScannerAdapter contract + Semgrep, Trivy, Gitleaks adapters
│   ├── findings/            # Normalization, fingerprinting, lifecycle, risk prioritization, JSON/SARIF/CSV
│   └── ai/                  # Provider-agnostic OpenAI-compatible AI Analyst + redaction gate
├── infrastructure/          # Dockerfiles (node, web, scanner-runner) & Trivy DB update script
├── docs/                    # Product, architecture, threat model, schema, ADRs, readiness
├── tests/                   # Fixtures/corpus, integration, security, E2E, regression benchmark
├── docker-compose.yml
├── .env.example
└── README.md
```

## 3. Module Boundaries & Responsibilities

| Module | Owns | Must Not Do |
|---|---|---|
| `apps/web` | UI, presentation, authenticated developer workflows | Direct DB access, GitHub token handling, raw secret display |
| `apps/api` | AuthN/AuthZ, Zod validation, tenant scoping, audit logging, scan job creation, report streaming | Execute scanners synchronously, expose installation tokens |
| `apps/worker` | BullMQ orchestration, trusted GitHub ingestion, pipeline persistence, artifact archival | Trust repository content, pass tokens into scanner environment |
| `services/scanner-runner` | Isolated scanner execution, workspace sanitization, resource limits, immediate raw-output disposal | Write to DB, interpolate shell input, access network/cloud/GitHub creds |
| `packages/scanners` | `ScannerAdapter` contract, safe `spawn(..., { shell: false })`, output parsing, error classification | Persist findings or bypass binary allowlist |
| `packages/findings` | Canonical schema, normalization, category fingerprinting, dedupe, lifecycle, comparison, exports | Execute scanners directly or emit unredacted secrets |
| `packages/security` | Redaction, HKDF+HMAC fingerprints, path/symlink/SSRF guards, prompt fencing, redacting logger | Be bypassed by other modules |
| `packages/ai` | Provider abstraction, pre-LLM redaction gate, structured Zod analysis, scoped Advisor | Invent findings, suppress alerts, execute tools, receive plaintext secrets |
| `packages/database` | Drizzle schema, SQL migrations, PostgreSQL / PGlite client, seed script | Rely on frontend filtering for tenant isolation |

## 4. Scan States & Failure Transparency

```text
QUEUED → INITIALIZING → CLONING → SCANNING → ANALYZING
       → COMPLETED | COMPLETED_WITH_ERRORS | FAILED | CANCELLED
```

Per-scanner outcomes are tracked independently in `scanner_runs` (`SUCCESS`, `FAILED`, `TIMEOUT`, `CANCELLED`, `PARTIAL`, `UNAVAILABLE`) with exact scanner version, ruleset version, exit code, duration, error class, and scope limitations. A failed or partial scanner never produces a clean verification result.

## 5. Database Schema, Key Indexes & Retention

19 normalized tables in PostgreSQL 16 via Drizzle ORM (`packages/database/migrations/0001_initial.sql`):
- **Identity & Tenancy:** `users`, `organizations`, `organization_members`, `user_sessions`
- **Integrations & Projects:** `integrations`, `github_installations`, `projects`, `project_repositories`
- **Scanning & Artifacts:** `scans`, `scanner_runs`, `scanner_metadata`, `scan_artifacts`
- **Findings & Lifecycle:** `findings`, `finding_occurrences`, `finding_status_history`, `finding_ai_analyses`, `finding_evidence`
- **Governance:** `audit_events`, `security_policies`

Key indexes & retention controls:
- `UNIQUE(project_id, fingerprint)` on `findings` for deterministic cross-scan upserts.
- `INDEX(organization_id, project_id, status, severity)` on `findings` for fast tenant-scoped dashboard/filter queries.
- `INDEX(organization_id, secret_fingerprint)` on `findings` for tenant-isolated credential correlation.
- `UNIQUE(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL` on `scans` for idempotent scan creation.
- `INDEX(expires_at)` on `scan_artifacts` enforcing configurable `ARTIFACT_RETENTION_DAYS` (default 30 days).

## 6. Observability & Cost Controls

- Structured JSON logs (`packages/security/src/logger.ts`) carry `correlationId`, `organizationId`, and `scanId` and automatically scrub tokens, passwords, private keys, and authorization headers.
- `/metrics` exposes Prometheus counters/histograms for HTTP requests, scan counts/durations, scanner durations/failures, and AI latency/token usage/failures.
- Configurable limits: `MAX_REPO_SIZE_MB`, `MAX_FILES_PER_SCAN`, `SCANNER_TIMEOUT_MS`, `MAX_SCAN_DURATION_MS`, `MAX_CONCURRENT_SCANS_PER_ORG`, `MAX_GIT_HISTORY_COMMITS`, `AI_MAX_CONTEXT_CHARS`, `AI_MAX_TOKENS`, `AI_TIMEOUT_MS`, `AI_MAX_RETRIES`, and `ARTIFACT_RETENTION_DAYS`.
