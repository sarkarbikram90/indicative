# Indicative

**Open-source AI-powered repository security intelligence platform — find vulnerabilities and exposed secrets, understand their real-world impact, prioritize remediation with evidence, and verify fixes.**

> *Indicative transforms fragmented security findings into prioritized, evidence-backed remediation workflows.*
>
> **Core Philosophy:** `Detect → Understand → Prioritize → Recommend → Verify`
>
> *Working brand name: "Indicative" is used as the working product name; no trademark or domain availability has been verified.*

---

## Project Status

**MVP Implemented & Verified** (suitable for local evaluation, single-team pilots, and controlled demonstrations; see [Production-Readiness Assessment](docs/engineering/production-readiness.md) for multi-tenant SaaS hardening requirements).

| Phase | Area | Status |
|---|---|---|
| 0 | Product, architecture, threat model, schema & ADRs | ✅ Complete |
| 1 | Monorepo foundation, PostgreSQL (19 tables), auth/CSRF, Redis/BullMQ, Compose | ✅ Complete & verified |
| 2 | GitHub OAuth + GitHub App installation, repo discovery & hardened ingestion | ✅ Complete & verified |
| 3 | Isolated `scanner-runner` + pinned Semgrep `1.186.0`, Trivy `0.76.2`, Gitleaks `8.30.1` | ✅ Complete & verified |
| 4 | Canonical normalization, category fingerprinting, HKDF+HMAC secret dedupe, lifecycle & verification | ✅ Complete & verified |
| 5 | Optional OpenAI-compatible AI Security Analyst & scoped Advisor (prompt-injection & redaction hardened) | ✅ Complete & verified |
| 6 | Next.js 15 Dashboard, Projects, Scans, Findings, Finding Details, Advisor & JSON/SARIF/CSV exports | ✅ Complete & verified |
| 7 | Security regression corpus, unit/integration/security/real-scanner E2E tests & hardening assessment | ✅ Complete (`29/29` passing) |

---

## Implemented Architecture

Indicative is a **modular monolith with independently deployable execution workers** in a single TypeScript (`npm` workspaces) monorepo:

```text
indicative/
├── apps/
│   ├── web/               # Next.js 15 + React 19 + Tailwind CSS developer UI
│   ├── api/               # Fastify 5 + Zod REST API (/api/v1/*) + OpenAPI 3.1 (/docs)
│   └── worker/            # BullMQ scan processor + trusted GitHub App ingestion
├── services/
│   └── scanner-runner/    # Isolated scanner execution + pinned Semgrep ruleset
├── packages/
│   ├── config/            # Zod env validation + production security guardrails
│   ├── contracts/         # Shared TypeScript & Zod schemas across services
│   ├── security/          # Secret redaction, HKDF+HMAC-SHA256 fingerprints, SSRF, workspace & prompt safety
│   ├── shared/            # AppError hierarchy, correlation IDs, Prometheus metrics, S3/MinIO & local storage
│   ├── database/          # PostgreSQL 16 + Drizzle ORM (19 tables), SQL migrations, seed script
│   ├── scanners/          # ScannerAdapter contract + Semgrep, Trivy, Gitleaks adapters
│   ├── findings/          # Normalization, deduplication, lifecycle, scan comparison, risk prioritization, JSON/SARIF/CSV
│   └── ai/                # Optional provider-agnostic OpenAI-compatible AI Analyst + pre-LLM redaction gate
├── infrastructure/
│   ├── docker/            # Dockerfiles for node services, web, and hardened offline scanner-runner
│   └── scripts/           # Controlled offline Trivy DB update script
├── docs/                  # Product strategy, MVP scope, architecture, threat model, schema, ADRs, readiness
├── tests/                 # Regression corpus/fixtures, integration, security, E2E & benchmark suites
├── docker-compose.yml
└── .env.example
```

### Pinned Security Scanning Engines

| Engine | Pinned Version | Capabilities | License | Execution Mode |
|---|---|---|---|---|
| **Semgrep CE** | `1.186.0` | SAST (`JavaScript`, `TypeScript`, `Python`) | LGPL-2.1 | Offline pinned ruleset (`indicative-sast-v1.0.0`), `--metrics=off` |
| **Trivy** | `0.76.2` | SCA (lockfiles) & IaC misconfiguration (Docker, Kubernetes, Terraform) | Apache-2.0 | Air-gapped offline scan (`--skip-db-update --skip-check-update --offline-scan`) |
| **Gitleaks** | `8.30.1` | Exposed secrets in working tree (`dir`) AND full Git commit history (`git`) | MIT | Immediate in-memory tenant HMAC fingerprinting, redaction & `finally` raw disposal |

---

## Security Model (Summary)

- **Zero plaintext secret persistence or disclosure:** Secrets are masked and fingerprinted via tenant-keyed `HKDF-SHA256` + `HMAC-SHA256` before entering the database, UI, logs, artifacts, reports, or AI requests. Raw Gitleaks reports are deleted immediately in `finally`.
- **Honest credential status:** Secret validity is always reported as `NOT_VERIFIED` / `UNKNOWN`. Repository removal is never equated with credential revocation or rotation.
- **Trusted ingestion vs. untrusted execution:** Short-lived read-only GitHub App installation tokens are minted only on the backend worker and passed via transient HTTP headers (never saved in `.git/config`, never logged, never exposed to browsers or scanners). `scanner-runner` runs non-root (`10001`), read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges`, no Docker socket, and zero outbound internet egress (`scanner_internal: internal: true`).
- **Strict tenant isolation & auth:** Server-verified sessions (`HttpOnly`, `SameSite=Lax`), CSRF verification on cookie mutations, HMAC-signed OAuth `state`, and explicit `organization_id` scoping on every query. `DEMO_MODE` refuses to boot in `NODE_ENV=production`.
- **Failure transparency:** Failed, timed-out, or scope-limited scanners yield `COMPLETED_WITH_ERRORS` / `FAILED` and `VERIFICATION_INCONCLUSIVE` — never a silent clean scan.
- **AI safety:** Optional (`AI_PROVIDER=disabled` by default). Repository content is fenced in `<UNTRUSTED_REPOSITORY_DATA>`, checked by a fail-closed pre-LLM secret redaction gate, validated strictly with Zod, and granted zero tool permissions.

---

## Getting Started

### Option A: Docker Compose (Full Local Stack)

Starts PostgreSQL 16, Redis 7, MinIO (S3-compatible object storage), hardened no-egress `scanner-runner`, Fastify API, BullMQ Worker, and Next.js Web UI:

```bash
cp .env.example .env
docker compose up --build
```

- **Web UI:** http://localhost:3000
- **Backend API:** http://localhost:4000
- **OpenAPI 3.1 Docs:** http://localhost:4000/docs
- **Health Check:** http://localhost:4000/health
- **Prometheus Metrics:** http://localhost:4000/metrics
- **MinIO Console:** http://localhost:9001

### Option B: Native Local Development (Node.js >= 20 LTS)

```bash
npm install
npm run build
# Populate offline Trivy vulnerability DB & checks cache:
./infrastructure/scripts/update-trivy-db.sh
# Run migrations & seed (or start API in NODE_ENV=development DEMO_MODE=true):
npm run db:migrate
npm run db:seed
npm run dev:api
npm run dev:web
```

### Environment Configuration (`.env.example`)

Configure these groups in `.env` (never commit `.env` or real credentials):
1. **GitHub OAuth (User Login):** `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `GITHUB_OAUTH_CALLBACK_URL`.
2. **GitHub App (Read-Only Repo Access):** `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_PRIVATE_KEY` (`contents: read`, `metadata: read`).
3. **Database & Redis:** `DATABASE_URL`, `REDIS_URL`.
4. **Object Storage:** `ARTIFACT_STORAGE_DRIVER`, `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `ARTIFACT_RETENTION_DAYS`.
5. **Cryptographic Keys:** `SESSION_SECRET`, `SECRET_FINGERPRINT_KEY`, `SCANNER_RUNNER_SHARED_SECRET` (production refuses `dev-only-*` defaults).
6. **LLM Provider (Optional):** `AI_PROVIDER` (`disabled` | `openai-compatible`), `AI_API_BASE_URL`, `AI_API_KEY`, `AI_MODEL`, `AI_MAX_CONTEXT_CHARS`, `AI_MAX_TOKENS`.
7. **Scanner & Resource Limits:** `SEMGREP_BIN`, `TRIVY_BIN`, `GITLEAKS_BIN`, `TRIVY_CACHE_DIR`, `SEMGREP_RULES_DIR`, `MAX_REPO_SIZE_MB`, `MAX_FILES_PER_SCAN`, `SCANNER_TIMEOUT_MS`, `MAX_SCAN_DURATION_MS`, `MAX_CONCURRENT_SCANS_PER_ORG`, `MAX_GIT_HISTORY_COMMITS`.

---

## Automated Tests & Measured Regression Baseline

```bash
npm test                 # Full suite (Unit + Integration + Security + E2E + Regression)
npm run test:unit
npm run test:integration
npm run test:security
npm run test:e2e
npm run test:regression
```

### Actual Measured Results
- **Test suite:** `8/8` test files passed, `29/29` tests passed against real Semgrep `1.186.0`, Trivy `0.76.2`, Gitleaks `8.30.1`, and PostgreSQL 16.
- **Security Regression Corpus (`tests/regression/corpus-benchmark.test.ts`):**
  - **Expected targets (`vulnerable-app`):** `20` (12 JS/TS/Python SAST, 2 SCA CVEs, 3 IaC Docker/K8s/Terraform, 3 Secrets including removed-in-Git-history dummy GitHub PAT and RSA key)
  - **True Positives:** `20/20` | **False Negatives:** `0` | **Clean Repo False Positives (`clean-app`):** `0`
  - **Precision:** `1.0000` | **Recall:** `1.0000` | **False-Positive Rate:** `0.0000`
  - **Parsing Failures:** `0` | **Scanner Execution Failures:** `0`
  - **Measured Latencies:** Semgrep `4.68s` (12 findings), Trivy `2.34s` (44 raw), Gitleaks `2.05s` (7 raw across working tree + Git history).

---

## Documentation

- [Product Strategy](docs/product/product-strategy.md)
- [MVP Scope & Acceptance Criteria](docs/product/mvp-scope.md)
- [System Architecture](docs/architecture/system-architecture.md)
- [Security Threat Model](docs/architecture/security-threat-model.md)
- [Canonical Finding Schema & Lifecycle](docs/architecture/finding-schema.md)
- [Implementation Plan](docs/engineering/implementation-plan.md)
- [Architecture Decision Records (ADRs)](docs/engineering/architecture-decisions.md)
- [Production-Readiness Assessment & Cost Model](docs/engineering/production-readiness.md)
- [Future Performance Note (Optional Rust Hot-Path Evaluation)](Suggetion.md)

---

## Explicitly Out of Scope (Post-MVP)

Autonomous penetration testing, DAST, automated exploitation, arbitrary website scanning, cloud/Kubernetes posture management, runtime monitoring, automatic credential revocation/rotation, automatic source-code modification or PR creation, multi-agent security systems, Strix engine integration (extensible via `ScannerAdapter`), automated GitHub push webhooks, enterprise billing/RBAC, and mobile apps.

---

## Contributing & Engineering Principles

1. **Security first** — never weaken isolation, auth, or redaction for convenience.
2. **Deterministic detection** — AI never invents findings or overrides scanner severity.
3. **Evidence over assertions** — every finding and verification carries traceable provenance.
4. **Modular boundaries** — scanners, findings, AI, and orchestration remain decoupled.
5. **Simplicity before scale** — modular monolith + isolated execution workers.
6. **No fake functionality** — no dead controls or fabricated scan results.
7. **Failure transparency** — failed scanners are never clean scans.
8. **Maintainability** — strict TypeScript, Zod validation, tests, and pinned dependencies.

## License

Apache License 2.0. See [LICENSE](LICENSE).
