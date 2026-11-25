# Indicative — System Architecture

**Last Updated:** 2026-11-24

## 1. Architectural Style

Indicative is implemented as a **modular monolith with independently deployable execution workers** in a single TypeScript (`npm` workspaces) monorepo. Microservices are intentionally avoided while preserving a strict trust boundary between trusted control-plane operations and untrusted repository scanning.

Core pipeline: `Detect → Understand → Correlate → Prioritize → Recommend → Verify`

For the planned cross-domain **Attack-Path Graph**, **Static Cloud IAM Analysis**, and **AI Agent / Non-Human Identity (NHI)** architectural evolution (`v0.3.0`–`v0.7.0`), see [Cross-Domain Attack-Path, Cloud Identity & NHI Architecture](./attack-path-and-identity-architecture.md).

```text
+-----------------------------------------------------------------------------+
|                                  CLIENTS                                    |
|  Developer Browser (Next.js 15 App Router - apps/web :3000)                 |
|  GitHub Webhooks (HMAC-SHA256) • Reusable GitHub Action (SARIF) • Local CLI |
+--------------------------------------+--------------------------------------+
                                       | HTTPS / HttpOnly Cookie + CSRF / Webhook Sig
                                       v
+-----------------------------------------------------------------------------+
|                        CONTROL PLANE API (apps/api :4000)                   |
|  Fastify 5 + Zod + OpenAPI 3.1 + Rate Limit + Auth/Tenant Guard + Audit Log |
|  Routes: /projects, /scans, /findings, /workflows, /webhooks, /schedules,   |
|          /notifications, /scanners, /advisor                                |
+------------------+-------------------+--------------------+-----------------+
                   |                   |                    |
                   v                   v                    v
            +------------+      +-------------+      +--------------+
            | PostgreSQL |      | Redis/BullMQ|      | MinIO (S3)   |
            | 23 tables  |      | Scan Queue  |      | Redacted     |
            | Drizzle ORM|      | + Cron Poll |      | Artifacts    |
            +------------+      +------+------+      +--------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                      BACKGROUND WORKER (apps/worker)                        |
|  1. Trusted GitHub Ingestion (short-lived installation token, size limits)  |
|  2. Ephemeral Workspace Preparation & Path/Symlink Sanitization             |
|  3. Dispatches Scan Job to Isolated Scanner Runner (no tokens passed)       |
|  4. Normalization, KEV/EPSS Enrichment, HMAC Fingerprinting, Comparison     |
|  5. Persistence, PR Checks/Comments, Notifications & Optional AI Analysis   |
+--------------------------------------+--------------------------------------+
                                       | scanner_internal (internal: true, ZERO egress)
                                       v
+-----------------------------------------------------------------------------+
|               ISOLATED SCANNER RUNNER (services/scanner-runner :4100)       |
|  Hardened non-root (10001) | Read-only rootfs | Cap-drop ALL | No Docker    |
|  socket | No cloud/GitHub creds | Network isolated (no outbound internet)   |
|                                                                             |
|  +-----------------+ +-----------------+ +---------------+ +--------------+ |
|  | Semgrep 1.186.0 | | Trivy 0.76.2    | | Gitleaks      | | Indicative   | |
|  | Pinned offline  | | Offline DB +    | | 8.30.1        | | CI/CD & OIDC | |
|  | JS/TS/Py rules  | | freshness check | | dir + git     | | AST (16 rule)| |
|  +-----------------+ +-----------------+ +---------------+ +--------------+ |
|                                                                             |
|  [Planned v0.3.0+ inside scanner-runner: optional pinned zizmor/actionlint, |
|   @indicative/cloud-identity static AWS IAM analyzer, static MCP analyzer]  |
+-----------------------------------------------------------------------------+
```

## 2. Monorepo Layout (Verified `v0.2.0-dev` & Planned Extensions)

```text
indicative/
├── apps/
│   ├── web/                 # Next.js 15 + React 19 + Tailwind UI (Dashboard, Findings, /workflows, /automations, AI Advisor)
│   ├── api/                 # Fastify 5 REST API (/api/v1/*) + OpenAPI /docs + GitHub Webhooks
│   └── worker/              # BullMQ processor, cron scheduler, GitHub PR/Check feedback, notifications & ingestion
├── services/
│   └── scanner-runner/      # Isolated scanner execution + pinned Semgrep ruleset + CI/CD & OIDC analyzer
├── packages/
│   ├── config/              # Zod env validation + production security guardrails
│   ├── contracts/           # Shared Zod schemas + TypeScript contracts (SAST, SCA, SECRET, IAC, CICD)
│   ├── security/            # Secret redaction, HKDF+HMAC fingerprints, AES-256-GCM secrets, SSRF, prompt safety
│   ├── shared/              # AppError, correlation IDs, Prometheus metrics, S3/MinIO & local storage
│   ├── database/            # Drizzle ORM schema (23 tables), SQL migrations, seed script
│   ├── scanners/            # ScannerAdapter contract + Semgrep, Trivy, Gitleaks adapters
│   ├── cicd-security/       # AST YAML GitHub Actions analyzer, static AWS/Azure/GCP OIDC correlator, CLI & policy engine
│   ├── findings/            # Normalization, fingerprinting, KEV/EPSS intelligence, lifecycle, prioritization, JSON/SARIF/CSV
│   ├── ai/                  # Provider-agnostic OpenAI-compatible AI Analyst + fail-closed pre-LLM redaction gate
│   ├── cloud-identity/      # [Planned v0.3.0] Static AWS IAM policy, wildcard & privilege-escalation analyzer
│   └── context-graph/       # [Planned v0.4.0] PostgreSQL-backed typed entity/edge graph & attack-path correlator
├── rules/
│   └── cicd/github-actions/ # Versioned CI/CD & OIDC rule documentation (indicative-cicd-gha-v1.0.0)
├── infrastructure/          # Dockerfiles (node, web, scanner-runner), gVisor/Kata profiles, Trivy DB update script
├── docs/                    # Strategy, roadmap, competitive analysis, architecture, threat models, audits, ADRs
├── tests/                   # Fixtures/corpora (AppSec + CI/CD + OIDC), integration, security, E2E, regression benchmarks
├── action.yml               # Reusable composite GitHub Action with SARIF 2.1.0 upload
├── docker-compose.yml
├── .env.example
└── README.md
```

## 3. Module Boundaries & Responsibilities

| Module | Owns | Must Not Do |
|---|---|---|
| `apps/web` | UI, presentation, authenticated developer workflows (`/workflows`, `/automations`, `/findings`) | Direct DB access, GitHub token handling, raw secret display |
| `apps/api` | AuthN/AuthZ, Zod validation, tenant scoping, audit logging, webhooks, schedules, notifications, report streaming | Execute scanners synchronously, expose installation tokens |
| `apps/worker` | BullMQ orchestration, trusted GitHub ingestion, PR Checks/comments, notification dispatch, pipeline persistence | Trust repository content, pass tokens into scanner environment |
| `services/scanner-runner` | Isolated scanner execution, workspace sanitization, resource limits, immediate raw-output disposal | Write to DB, interpolate shell input, access network/cloud/GitHub creds |
| `packages/scanners` | `ScannerAdapter` contract, safe `spawn(..., { shell: false })`, output parsing, error classification | Persist findings or bypass binary allowlist |
| `packages/cicd-security` | Safe AST YAML 1.2 GitHub Actions parsing, 16 CI/CD rules, static AWS/Azure/GCP OIDC trust correlation, CLI & SARIF | Make live network/cloud API calls or execute repository workflows |
| `packages/findings` | Canonical schema, normalization, KEV/EPSS enrichment, category fingerprinting, lifecycle, prioritization, exports | Execute scanners directly or emit unredacted secrets |
| `packages/security` | Redaction, HKDF+HMAC fingerprints, AES-256-GCM channel secret encryption, path/symlink/SSRF guards, prompt fencing | Be bypassed by other modules |
| `packages/ai` | Provider abstraction, pre-LLM redaction gate, structured Zod analysis, scoped Advisor | Invent findings, suppress alerts, execute tools, receive plaintext secrets |
| `packages/database` | Drizzle schema (23 tables), SQL migrations, PostgreSQL / PGlite client, seed script | Rely on frontend filtering for tenant isolation |
| `packages/cloud-identity` *(Planned v0.3.0)* | Static IAM policy parsing (Terraform/CFN/JSON), workflow-to-role linking, wildcard & escalation classification | Execute live cloud API calls inside `scanner-runner` |
| `packages/context-graph` *(Planned v0.4.0)* | Typed entity/edge graph construction, multi-hop attack-path correlation, per-hop provenance & uncertainty tracking | Hide `UNKNOWN` controls or fabricate unverified attack paths |

## 4. Scan States & Failure Transparency

```text
QUEUED → INITIALIZING → CLONING → SCANNING → ANALYZING
       → COMPLETED | COMPLETED_WITH_ERRORS | FAILED | CANCELLED
```

Per-scanner outcomes are tracked independently in `scanner_runs` (`SUCCESS`, `FAILED`, `TIMEOUT`, `CANCELLED`, `PARTIAL`, `UNAVAILABLE`) with exact scanner version, ruleset version, exit code, duration, error class, and scope limitations. A failed or partial scanner never produces a clean verification result.

## 5. Database Schema, Key Indexes & Retention

23 normalized tables currently verified in PostgreSQL 16 via Drizzle ORM (`packages/database/src/schema.ts`):
- **Identity & Tenancy (4):** `users`, `organizations`, `organization_members`, `user_sessions`
- **Integrations & Projects (4):** `integrations`, `github_installations`, `projects`, `project_repositories`
- **Scanning & Artifacts (4):** `scans`, `scanner_runs`, `scanner_metadata`, `scan_artifacts`
- **Findings & Lifecycle (5):** `findings`, `finding_occurrences`, `finding_status_history`, `finding_ai_analyses`, `finding_evidence`
- **Governance (2):** `audit_events`, `security_policies`
- **Webhooks, Schedules & Notifications (4):** `webhook_deliveries`, `scan_schedules`, `notification_channels`, `notification_deliveries`
- **Planned Graph Tables (`v0.4.0`):** `security_entities`, `security_edges`, `attack_paths`, `attack_path_steps` (see [attack-path-and-identity-architecture.md](./attack-path-and-identity-architecture.md)).

Key indexes & retention controls:
- `UNIQUE(project_id, fingerprint)` on `findings` for deterministic cross-scan upserts.
- `INDEX(organization_id, project_id, status, severity)` on `findings` for fast tenant-scoped dashboard/filter queries.
- `INDEX(organization_id, secret_fingerprint)` on `findings` for tenant-isolated credential correlation.
- `UNIQUE(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL` on `scans` for idempotent scan creation.
- `UNIQUE(delivery_id)` on `webhook_deliveries` for GitHub webhook replay protection.
- `INDEX(expires_at)` on `scan_artifacts` enforcing configurable `ARTIFACT_RETENTION_DAYS` (default 30 days).

## 6. Observability & Cost Controls

- Structured JSON logs (`packages/security/src/logger.ts`) carry `correlationId`, `organizationId`, and `scanId` and automatically scrub tokens, passwords, private keys, and authorization headers.
- `/metrics` exposes Prometheus counters/histograms for HTTP requests, scan counts/durations, scanner durations/failures, and AI latency/token usage/failures.
- Configurable limits: `MAX_REPO_SIZE_MB`, `MAX_FILES_PER_SCAN`, `SCANNER_TIMEOUT_MS`, `MAX_SCAN_DURATION_MS`, `MAX_CONCURRENT_SCANS_PER_ORG`, `MAX_GIT_HISTORY_COMMITS`, `AI_MAX_CONTEXT_CHARS`, `AI_MAX_TOKENS`, `AI_TIMEOUT_MS`, `AI_MAX_RETRIES`, and `ARTIFACT_RETENTION_DAYS`.
