# Indicative

**Evidence-Driven Security Intelligence for Modern Software and Cloud Infrastructure.**

*Open-source application, CI/CD, and cloud workload identity security platform — detect vulnerabilities, exposed secrets, insecure GitHub Actions workflows, and permissive cloud OIDC trust policies; contextualize findings with transparent provenance; prioritize remediation honestly; and verify fixes.*

> **Core Philosophy:** `Detect → Understand → Prioritize → Recommend → Verify`
>
> *License: Apache 2.0. Working brand name: "Indicative" (no trademark or domain availability verified).*

---

## Project Status & Verified Capabilities

**v0.2.0-dev Implemented & Verified** — suitable for local evaluation, practitioner CI/CD auditing, single-team self-hosted pilots, and controlled demonstrations (see [Current-State Technical & Security Audit](docs/audits/current-state-assessment.md) and [Production-Readiness Assessment](docs/engineering/production-readiness.md) for multi-tenant SaaS prerequisites).

| Milestone | Area | Status |
|---|---|---|
| Core Platform (`v0.1.0`) | Modular TypeScript monorepo, PostgreSQL 16 (19 tables), Fastify 5 API + OpenAPI 3.1, Redis/BullMQ, GitHub OAuth & App, Next.js 15 UI | ✅ Verified |
| Core Scanners (`v0.1.0`) | Isolated `scanner-runner` + pinned Semgrep CE `1.186.0`, Trivy `0.76.2` (with offline DB freshness checks), Gitleaks `8.30.1` (working tree + Git history) | ✅ Verified |
| Secret & Verification Integrity (`v0.1.0`) | Tenant-keyed `HKDF+HMAC-SHA256` fingerprinting, linear-time PEM scrubbing, chunked redaction, honest `NOT_VERIFIED` credential status & `VERIFICATION_INCONCLUSIVE` failure transparency | ✅ Verified |
| Contextual Intelligence (`v0.2.0`) | Offline-capable CISA KEV + FIRST EPSS enrichment with explicit source/observation provenance and `[VERIFIED]` / `[INFERRED]` / `[UNKNOWN]` risk rationale | ✅ Verified |
| CI/CD & OIDC Security (`v0.2.0`) | `@indicative/cicd-security` AST YAML GitHub Actions analyzer (16 versioned rules), static AWS/Azure/GCP OIDC trust correlation, standalone CLI, policy modes, `/api/v1/workflows`, and `/workflows` UI view | ✅ Verified |
| Audit Hardening & OSS Foundation (`v0.2.0`) | Writable-phase symlink sanitization, UUID validation, production CORS restriction, `security_policies` enforcement, `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, dogfooded CI | ✅ Verified |

---

## Implemented Architecture

Indicative is a **modular monolith with independently deployable execution workers** in a single TypeScript (`npm` workspaces) monorepo:

```text
indicative/
├── apps/
│   ├── web/                    # Next.js 15 + React 19 + Tailwind UI (Dashboard, Projects, Scans, Findings, CI/CD & OIDC, AI Advisor)
│   ├── api/                    # Fastify 5 + Zod REST API (/api/v1/*) + OpenAPI 3.1 (/docs) + Prometheus (/metrics)
│   └── worker/                 # BullMQ scan processor + hardened GitHub App repository ingestion
├── services/
│   └── scanner-runner/         # Isolated scanner execution + pinned Semgrep ruleset + CI/CD analyzer
├── packages/
│   ├── config/                 # Zod env validation + strict production security guardrails
│   ├── contracts/              # Shared TypeScript & Zod schemas across services (SAST, SCA, SECRET, IAC, CICD)
│   ├── security/               # ReDoS-hardened redaction, HKDF+HMAC-SHA256 fingerprints, SSRF, workspace & prompt safety
│   ├── shared/                 # AppError hierarchy, correlation IDs, Prometheus metrics, S3/MinIO & local artifact storage
│   ├── database/               # PostgreSQL 16 + Drizzle ORM (19 tables), SQL migrations, seed script
│   ├── scanners/               # ScannerAdapter contract + Semgrep, Trivy (with DB freshness check), Gitleaks adapters
│   ├── cicd-security/          # GitHub Actions AST YAML analyzer, AWS/Azure/GCP static OIDC trust correlator, CLI & policy engine
│   ├── findings/               # Normalization, category fingerprinting, KEV/EPSS enrichment, lifecycle, prioritization, JSON/SARIF/CSV
│   └── ai/                     # Optional provider-agnostic OpenAI-compatible AI Analyst + fail-closed pre-LLM redaction gate
├── rules/
│   └── cicd/github-actions/    # Versioned CI/CD & OIDC rule documentation (indicative-cicd-gha-v1.0.0)
├── infrastructure/
│   ├── docker/                 # Dockerfiles for node services, web, and hardened offline scanner-runner
│   ├── sandbox/                # gVisor / Kata Containers / seccomp deployment profiles
│   └── scripts/                # Controlled offline Trivy DB update script
├── docs/                       # Audit assessment, competitive analysis, roadmap, architecture, threat models, community guide
└── tests/                      # Vulnerable & hardened regression corpora (AppSec + CI/CD + OIDC), integration, security & E2E suites
```

### Pinned Security Detection Engines

| Engine | Version | Capabilities | License | Execution Mode |
|---|---|---|---|---|
| **Semgrep CE** | `1.186.0` | SAST (`JavaScript`, `TypeScript`, `Python`) | LGPL-2.1 | Offline pinned ruleset (`indicative-sast-v1.0.0`), `--metrics=off` |
| **Trivy** | `0.76.2` | SCA (lockfiles) & IaC misconfiguration (Docker, K8s, Terraform) | Apache-2.0 | Air-gapped offline scan + `metadata.json` DB staleness detection |
| **Gitleaks** | `8.30.1` | Exposed secrets in working tree (`dir`) AND Git commit history (`git`) | MIT | Immediate in-memory tenant HMAC fingerprinting, redaction & `finally` raw disposal |
| **Indicative CI/CD & OIDC** | `1.0.0` | GitHub Actions workflows (permissions, triggers, script injection, SHA pinning, secrets, build integrity) & static AWS/Azure/GCP OIDC trust correlation | Apache-2.0 | Offline AST YAML 1.2 parser (`maxAliasCount`, size limits), `STATIC_CONFIG` evidence basis |

---

## Quick Start

### 1. Run the Standalone CI/CD & OIDC Analyzer Locally (Zero Infrastructure Required)

Audit any local repository's `.github/workflows/*.yml` and static AWS/Azure/GCP OIDC IaC configs in seconds:

```bash
npm install
npm run build

# Markdown Pull Request summary (non-blocking warning mode by default)
npm run scan:cicd -- . --format markdown

# Inspect deliberately vulnerable CI/CD + OIDC fixture
npm run scan:cicd -- tests/fixtures/cicd-vulnerable --format markdown

# GitHub Actions annotations or strict CI policy gate
npm run scan:cicd -- . --format annotations
npm run scan:cicd -- . --format json --policy failure
```

### 2. Full Local Platform via Docker Compose

Starts PostgreSQL 16, Redis 7, MinIO, hardened no-egress `scanner-runner`, Fastify API, BullMQ Worker, and Next.js Web UI:

```bash
cp .env.example .env
docker compose up --build
```

- **Web UI:** http://localhost:3000 (including `/workflows` CI/CD & OIDC Security View)
- **Backend API:** http://localhost:4000 (`/docs` OpenAPI 3.1, `/health`, `/metrics`)
- **MinIO Console:** http://localhost:9001

### 3. Native Local Development (Node.js >= 20.18 LTS)

```bash
npm install
npm run build
./infrastructure/scripts/update-trivy-db.sh
npm run db:migrate
npm run db:seed
npm run dev:api
npm run dev:web
```

---

## Automated Tests & Measured Regression Baselines

```bash
npm test                 # Full suite (Unit + Integration + Security + E2E + AppSec & CI/CD Regression)
npm run test:unit
npm run test:integration
npm run test:security
npm run test:e2e
npm run test:regression
```

### Verified Measured Results

- **Core Security Regression Corpus (`tests/regression/corpus-benchmark.test.ts`):**
  - Expected targets (`vulnerable-app`): `20/20` True Positives, `0` False Negatives, `0` False Positives on `clean-app`
  - Precision `1.0000`, Recall `1.0000`, `0` parsing or execution failures across real Semgrep `1.186.0`, Trivy `0.76.2`, and Gitleaks `8.30.1`.
- **CI/CD & OIDC Regression Corpus (`tests/regression/cicd-corpus-benchmark.test.ts`):**
  - Expected rule families (`tests/fixtures/cicd-vulnerable` — 2 workflows + AWS/Azure/GCP Terraform OIDC policies): `16/16` True Positives (`25` total findings), `0` missed rules
  - Hardened corpus (`tests/fixtures/cicd-hardened` — hardened CI + safe `pull_request_target` labeler + environment-bound AWS/Azure/GCP OIDC policies): `0` False Positives
  - Precision `1.0000`, Recall `1.0000`.
- **Benchmark Disclosure:** Fixture corpora prove deterministic behavior and false-positive discipline on covered rule patterns, not universal detection accuracy across arbitrary enterprise repositories.

---

## Security Model & Honest Boundaries

- **Zero plaintext secret persistence or disclosure:** Tenant-keyed `HKDF-SHA256` + `HMAC-SHA256` fingerprinting, linear-time PEM scrubbing, fail-closed artifact and pre-LLM redaction gates, and immediate `finally` deletion of raw Gitleaks reports.
- **Honest credential & static evidence status:** Secret validity is always `NOT_VERIFIED`; repository removal never implies credential revocation. CI/CD and OIDC findings explicitly declare `STATIC_CONFIG` provenance and list unknown runtime controls (live cloud IAM permissions, SCPs, GitHub environment approval gates).
- **Trusted ingestion vs. untrusted execution:** Short-lived GitHub App tokens (`contents: read`, `metadata: read`) are passed only via transient HTTP headers during worker ingestion; symlinks are sanitized before handing off to the no-egress, non-root (`10001`), `read_only`, `cap_drop: [ALL]` `scanner-runner`.
- **Production multi-tenant caveat:** Docker containers share the host Linux kernel; untrusted multi-tenant SaaS production requires gVisor (`runsc`), Kata Containers, or Firecracker microVMs plus PostgreSQL RLS and KMS (see `infrastructure/sandbox/` and [Production-Readiness Assessment](docs/engineering/production-readiness.md)).

---

## Documentation & Community

- **Audit & Strategy:** [Current-State Audit](docs/audits/current-state-assessment.md) | [Competitive Landscape](docs/product/competitive-landscape.md) | [Product Roadmap](docs/product/product-roadmap.md) | [Public Roadmap](ROADMAP.md)
- **Architecture & Security:** [System Architecture](docs/architecture/system-architecture.md) | [Platform Threat Model](docs/architecture/security-threat-model.md) | [CI/CD Security Architecture](docs/architecture/ci-cd-security-architecture.md) | [CI/CD Threat Model](docs/architecture/ci-cd-security-threat-model.md) | [Canonical Finding Schema](docs/architecture/finding-schema.md)
- **Rules & Engineering:** [GitHub Actions & OIDC Rule Catalog](rules/cicd/github-actions/README.md) | [ADRs](docs/engineering/architecture-decisions.md) | [Production Readiness](docs/engineering/production-readiness.md)
- **Open-Source Governance:** [SECURITY.md](SECURITY.md) | [CONTRIBUTING.md](CONTRIBUTING.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | [GOVERNANCE.md](GOVERNANCE.md) | [CHANGELOG.md](CHANGELOG.md) | [SUPPORT.md](SUPPORT.md) | [Community Guide](docs/community/README.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
