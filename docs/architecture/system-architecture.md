# Indicative — System Architecture

## 1. Architectural style

Indicative is a **modular monolith with separately deployed execution workers**. The application code lives in one repository with strict package boundaries; scans run asynchronously in isolated workers. Microservices are deliberately avoided for the MVP.

The product philosophy drives the pipeline:

```
Detect → Understand → Prioritize → Recommend → Verify
```

## 2. Component map

```text
                         ┌──────────────────────┐
                         │   Browser / Web app  │
                         │   (Next.js, TS)      │
                         └──────────┬───────────┘
                                    │ HTTPS / REST
                         ┌──────────▼───────────┐
                         │   API service        │
                         │   Fastify + Zod      │
                         │   auth, authz, audit │
                         └───┬──────────────┬───┘
                             │              │
              ┌──────────────▼──┐    ┌──────▼──────────────┐
              │  PostgreSQL     │    │  Redis / BullMQ     │
              │  Drizzle ORM    │    │  job queue          │
              └──────────────▲──┘    └──────┬──────────────┘
                             │              │
                         ┌───┴──────────────▼───┐
                         │   Worker service     │
                         │   scan orchestration │
                         └──────────┬───────────┘
                                    │
                 ┌──────────────────▼──────────────────┐
                 │  Repository ingestion (trusted)     │
                 │  GitHub installation token          │
                 └──────────────────┬──────────────────┘
                                    │ source + history
                 ┌──────────────────▼──────────────────┐
                 │  Scanner runner (isolated, untrusted)│
                 │  Semgrep | Trivy | Gitleaks          │
                 └──────────────────┬──────────────────┘
                                    │ structured output
                 ┌──────────────────▼──────────────────┐
                 │  Findings pipeline                  │
                 │  parse → normalize → redact →       │
                 │  fingerprint → dedupe → persist     │
                 └──────────────────┬──────────────────┘
                                    │ sanitized context
                 ┌──────────────────▼──────────────────┐
                 │  AI Security Analyst (optional)     │
                 └──────────────────────────────────────┘
```

## 3. Repository layout (planned structure)

```text
indicative/
├── apps/
│   ├── web/                 # Next.js dashboard
│   ├── api/                 # Fastify REST API
│   └── worker/              # BullMQ job processors
├── services/
│   └── scanner-runner/      # isolated scanner execution
├── packages/
│   ├── contracts/           # Zod schemas + shared types
│   ├── config/              # validated environment config
│   ├── security/            # redaction, HMAC fingerprints, path safety
│   ├── database/            # Drizzle schema, migrations, seeds
│   ├── scanners/            # adapter interface + Semgrep/Trivy/Gitleaks
│   ├── findings/            # normalization, fingerprinting, lifecycle
│   ├── ai/                  # provider abstraction, analysis pipeline
│   └── shared/              # logging, errors, utilities
├── infrastructure/          # docker, compose, scripts
├── docs/
├── tests/                   # fixtures, integration, security, e2e
├── docker-compose.yml
├── .env.example
└── README.md
```

## 4. Module boundaries and responsibilities

| Module | Owns | Must not do |
|--------|------|-------------|
| `apps/web` | UI, presentation, user interactions | Direct DB access, token handling, raw secret display |
| `apps/api` | AuthN/AuthZ, validation, tenant scoping, audit, job creation | Execute scanners, hold installation tokens beyond retrieval |
| `apps/worker` | Job orchestration, ingestion coordination, pipeline execution | Trust repository content, expose tokens to scanners |
| `services/scanner-runner` | Isolated scanner process execution, output capture | Write to DB, interpolate shell input, access tokens |
| `packages/scanners` | Adapter contract, safe spawning, output parsing | Persist findings |
| `packages/findings` | Canonical schema, normalization, fingerprints, dedupe, lifecycle | Call scanners directly |
| `packages/security` | Redaction, keyed HMAC fingerprints, path validation | Be bypassed by other modules |
| `packages/ai` | Provider abstraction, structured analysis, redaction gate | Invent findings, receive secrets |
| `packages/database` | Schema, migrations, persistence | Enforce tenant isolation in the browser |

## 5. Request and scan flows

### 5.1 Scan initiation

```
Developer clicks "Scan"
  → API authenticates and authorizes project ownership
  → API validates request (Zod) and applies idempotency key
  → API creates scan record (QUEUED) and enqueues BullMQ job
  → Worker claims job, updates state INITIALIZING → CLONING
  → Trusted ingestion retrieves repository + history via installation token
  → Worker mounts workspace into isolated runner
  → Runner executes Semgrep, Trivy, Gitleaks independently
  → Worker parses/normalizes/redacts/deduplicates/persists findings
  → Optional AI analysis on selected findings
  → Scan transitions to COMPLETED / COMPLETED_WITH_ERRORS / FAILED
  → Dashboard reflects results
```

### 5.2 Verification flow

A later scan compares fingerprints against previous scans:

- detected again → recurring / still open
- not detected → "not detected in latest scan" (not automatically "fixed")
- new fingerprint → newly introduced
- verification success is stated only "within scanned scope"

## 6. Scan states

```
QUEUED → INITIALIZING → CLONING → SCANNING → ANALYZING
       → COMPLETED | COMPLETED_WITH_ERRORS | FAILED | CANCELLED
```

Scanner-level outcomes must be distinguishable: success with findings, success with zero findings, partial results, failure, timeout, cancellation, scanner unavailable.

## 7. Technology decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Frontend | Next.js + React + TypeScript + Tailwind | Modern developer-tool UX, type-safe contracts |
| API | Node.js LTS + Fastify + Zod | Fast, typed, strong validation story |
| Queue | Redis + BullMQ | Mature job model with retries, timeouts, concurrency |
| Database | PostgreSQL + Drizzle ORM | Relational integrity for finding lifecycle |
| Scanners | Semgrep, Trivy, Gitleaks | Covers SAST, SCA/misconfig, secrets |
| AI | Provider-agnostic adapter, OpenAI-compatible | Works with or without an API key |
| Storage | S3-compatible (MinIO local) | Artifact retention and portability |
| Local env | Docker Compose | Reproducible development |

No second ORM, queue, or competing framework is introduced.

## 8. Isolation and trust boundaries

1. **Trusted ingestion** uses short-lived GitHub installation tokens and retrieves source through approved endpoints. It cannot be invoked with arbitrary user URLs.
2. **Untrusted execution** happens in an ephemeral workspace inside a scanner runner with no Docker socket, no cloud credentials, no metadata endpoint access, restricted egress, and CPU/memory/disk/process/time limits.
3. **Findings pipeline** treats scanner output as untrusted data, parses defensively, and redacts secrets before persistence.
4. **AI boundary** receives only sanitized, scoped context and never raw repository content or secrets.

Local development may use a clearly labeled isolation profile; it must not be silently treated as production-grade isolation. See `docs/architecture/security-threat-model.md`.

## 9. Observability

Structured logs with correlation IDs, scan/scanner latency and failure metrics, queue depth and processing latency, DB health checks, AI latency/token/failure metrics, and ingestion failure metrics. Telemetry must never contain credentials, tokens, plaintext secrets, or sensitive source code.

## 10. Cost controls

Configurable repository size, scan duration, concurrent scans per organization, worker resources, AI context size, model token cap, AI timeout, retries, and artifact retention. AI is invoked only when configured and only for selected findings after deterministic scanning.
