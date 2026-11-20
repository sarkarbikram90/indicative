# Indicative

**Open-source tool to find and fix your leaked secrets — and to understand the security findings behind them.**

Indicative is an AI-powered repository security intelligence platform in development. It aims to help developers and small engineering teams find vulnerabilities and exposed secrets in their GitHub repositories, understand what those findings actually mean, prioritize remediation with evidence, and verify that fixes hold up in a later scan.

> Working product name. "Indicative" is used as the working brand name; no trademark or domain availability has been verified.

---

## ⚠️ Project status

**MVP under active development.**

| Area | Status |
|------|--------|
| Product & architecture documentation | ✅ Complete and published |
| Monorepo foundation (workspace config, tooling) | 🔧 In progress |
| GitHub integration | ⏳ Planned |
| Scanner adapters (Semgrep, Trivy, Gitleaks) | ⏳ Planned |
| Findings normalization, deduplication, lifecycle | ⏳ Planned |
| AI Security Analyst | ⏳ Planned |
| Dashboard, scan history, reports | ⏳ Planned |
| Test suite, security corpus, Docker Compose | ⏳ Planned |

Nothing in this README should be read as a claim that scanning is working yet. Capabilities described below are the **MVP target**, not shipped features. See [Roadmap](#roadmap) and [Implementation plan](docs/engineering/implementation-plan.md) for the current phase.

---

## Philosophy

> **Detect → Understand → Prioritize → Recommend → Verify**

Indicative is not intended to be another dashboard that displays raw scanner alerts. Deterministic scanners remain the authoritative source of findings; AI is used only to explain and contextualize them. The product favors a smaller number of reliable, well-explained findings over hundreds of unexplained alerts.

## What the MVP will do

- Connect to GitHub through a GitHub App with minimum read-only permissions
- Discover and select authorized repositories, and start manual scans
- Run real scanners: **Semgrep** (SAST), **Trivy** (dependencies and misconfigurations), **Gitleaks** (secrets, including Git history)
- Normalize all results into one canonical finding schema with scanner provenance preserved
- Deduplicate findings with deterministic, category-specific fingerprints
- Redact secrets everywhere and correlate them with keyed HMAC fingerprints — never storing plaintext credentials
- Provide evidence-backed severity and confidence, plus AI-assisted explanations when an LLM provider is configured
- Track finding status across scans and verify whether issues are still detected in scanned scope
- Export redacted JSON, SARIF (where mappable), and CSV reports

Explicitly out of scope for the MVP: autonomous penetration testing, DAST, automated exploitation, arbitrary website scanning, cloud/Kubernetes posture management, automatic credential revocation or rotation, automatic code modification, autonomous pull requests, multi-agent security systems, enterprise billing/RBAC, and mobile apps.

---

## How a scan is intended to work

```text
Developer initiates scan
  → API authenticates + authorizes project ownership
  → Scan record created (QUEUED) and job enqueued (Redis/BullMQ)
  → Worker performs trusted GitHub ingestion (short-lived installation token)
  → Isolated scanner runner executes Semgrep, Trivy, Gitleaks
  → Results parsed → redacted → normalized → fingerprinted → deduplicated
  → Findings persisted; optional AI analysis on selected findings
  → Scan completes; dashboard shows findings, evidence and remediation
  → A later scan compares fingerprints to verify what is still detected
```

Trust boundaries are deliberate: repository retrieval happens in a **trusted ingestion** step, while repository content is executed only inside an **isolated, untrusted scanner runner**. Scanners never receive GitHub tokens and cannot clone arbitrary URLs.

---

## Planned architecture

```text
indicative/
├── apps/
│   ├── web/                 # Next.js dashboard
│   ├── api/                 # Fastify REST API (auth, authz, validation, audit)
│   └── worker/              # BullMQ scan orchestration
├── services/
│   └── scanner-runner/      # isolated scanner execution
├── packages/
│   ├── contracts/           # Zod schemas + shared types
│   ├── config/              # validated environment configuration
│   ├── security/            # redaction, keyed HMAC fingerprints, path safety
│   ├── database/            # Drizzle schema, migrations, seeds
│   ├── scanners/            # adapter contract + Semgrep/Trivy/Gitleaks
│   ├── findings/            # normalization, fingerprinting, lifecycle
│   ├── ai/                  # provider abstraction, analysis pipeline
│   └── shared/              # logging, errors, correlation IDs
├── infrastructure/          # docker, compose, scripts
├── docs/
├── tests/                   # fixtures, integration, security, e2e
├── docker-compose.yml
├── .env.example
└── README.md
```

### Technology stack

| Concern | Choice |
|---------|--------|
| Frontend | Next.js, React, TypeScript, Tailwind CSS |
| API | Node.js LTS, Fastify, REST, Zod |
| Queue | Redis, BullMQ |
| Database | PostgreSQL, Drizzle ORM |
| Scanners | Semgrep, Trivy, Gitleaks (pinned versions/rulesets) |
| AI | Provider-agnostic adapter, OpenAI-compatible where supported |
| Artifacts | S3-compatible storage (MinIO locally) |
| Local environment | Docker Compose |

No second ORM, queue system, or competing framework is intended.

---

## Security model (summary)

- **Secrets are never exposed** in UI responses, logs, the findings database, AI requests, or reports. Redaction is applied to all raw scanner output before it is used anywhere.
- **Secret fingerprints use a keyed HMAC** with a tenant-specific key, so the same leaked credential can be correlated across files and commits without storing its plaintext.
- **Credential validity is always `UNKNOWN` / `NOT_VERIFIED`.** Indicative does not claim a credential is active, revoked, or rotated. Revocation and rotation are performed by the credential owner.
- **Tenant isolation** is enforced in service and database layers — never by frontend filtering.
- **Failure transparency:** a failed or partial scanner run is never presented as a clean scan. A finding that disappears from a later scan is not automatically marked resolved.
- **Untrusted repositories** are treated as hostile: ephemeral workspaces, no Docker socket, no cloud credentials or metadata access, restricted egress, resource limits, and timeouts.
- **Repositories are untrusted input to AI.** Source code, READMEs, and scanner output are data, never instructions. The analyst has no tools, cannot suppress findings, and cannot override authorization.
- **AI is optional.** With no provider configured, deterministic scanning still works.

For the full threat model, see [security-threat-model.md](docs/architecture/security-threat-model.md).

---

## Getting started

> **Target workflow — not yet functional.** These instructions describe the intended developer experience once the foundation, scanner, and deployment phases are implemented.

### Prerequisites

- Docker with Compose
- Node.js LTS (20+) and npm
- A GitHub App and OAuth credentials for real repository integration

### Target setup

```bash
git clone https://github.com/sarkarbikram90/indicative.git
cd indicative
cp .env.example .env
# Fill in GitHub App, database, Redis, object storage, and optional LLM settings
docker compose up --build
```

The development environment is intended to start PostgreSQL, Redis, MinIO, the API, worker, web app, and an isolated scanner runner. Database migrations and seed scripts would run as part of startup. A clearly labelled development-only demo mode may be provided; it must never become a production authentication bypass.

Configuration is intended to cover: GitHub OAuth and GitHub App credentials, database, Redis, object storage, LLM provider, secret fingerprint key, and scanner settings. Never commit real credentials.

---

## Documentation

- [Product strategy](docs/product/product-strategy.md)
- [MVP scope and acceptance criteria](docs/product/mvp-scope.md)
- [System architecture](docs/architecture/system-architecture.md)
- [Security threat model](docs/architecture/security-threat-model.md)
- [Canonical finding schema](docs/architecture/finding-schema.md)
- [Implementation plan](docs/engineering/implementation-plan.md)
- [Architecture decisions](docs/engineering/architecture-decisions.md)

---

## Roadmap

The build proceeds in phases, with each phase producing verifiable output before the next begins:

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Repository assessment and architecture | ✅ Complete |
| 1 | Foundation (DB, auth, API, UI shell, queue, Compose) | ⏳ Planned / in progress |
| 2 | GitHub repository integration | ⏳ Planned |
| 3 | Scanner execution and isolation | ⏳ Planned |
| 4 | Findings intelligence and lifecycle | ⏳ Planned |
| 5 | AI Security Analyst | ⏳ Planned |
| 6 | Dashboard and reporting | ⏳ Planned |
| 7 | Verification, tests, hardening | ⏳ Planned |

Detailed acceptance criteria are in [mvp-scope.md](docs/product/mvp-scope.md). Do not treat a phase as complete without evidence.

---

## Contributing

Contributions are welcome as the MVP takes shape. Engineering principles that must be preserved:

1. Security first — no shortcuts that expose repositories, credentials, or execution environments.
2. Deterministic detection — AI never invents findings.
3. Evidence over assertions — findings and verification results carry provenance.
4. Modular boundaries — scanners, findings, AI, and orchestration stay independent.
5. Simplicity before scale — modular monolith plus separate workers.
6. No fake functionality — no dead buttons, fabricated findings, or mocked integrations presented as real.
7. Failure transparency — failed scanners are never clean scans.
8. Maintainability — typed contracts, tests, linting, pinned dependencies.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
