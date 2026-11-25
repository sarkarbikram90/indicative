# Changelog

All notable changes to **Indicative** are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — `0.3.0-dev`

### Added
- **Repository Config, Audited Suppressions & Baseline Ratchet Mode (`@indicative/cicd-security`):**
  - Strict Zod-validated `.indicative.yml` / `.indicative.yaml` / `.indicative.json` configuration (`policy`, `failOnSeverities`, `ignore`, per-rule severity overrides or `off`, and scoped `suppressions` with required `reason` and optional `expires`).
  - Inline YAML/IaC suppression comments (`# indicative-ignore: RULE-ID reason="..." expires=YYYY-MM-DD`) with strict expiration enforcement (expired suppressions are rejected and surfaced as `EXPIRED_SUPPRESSION` limitations).
  - Baseline / differential ratchet mode (`--write-baseline`, `--baseline`) using stable line-number-independent finding keys so teams can gate CI strictly on newly introduced findings.
- **Open-Source Distribution, Tooling & Release Infrastructure:**
  - Pre-bundled standalone Action CLI (`scripts/bundle-action.mjs` → `action-dist/cicd-cli.cjs`) for instant zero-install execution in `action.yml`, plus new `config` / `baseline` inputs and `new-findings-count` / `suppressed-count` outputs.
  - Hardened tag-triggered release workflow (`.github/workflows/release.yml`) publishing signed/attested GHCR images (`api`, `web`, `worker`, `scanner-runner`) and GitHub Releases with SHA-256 checksums.
  - `.pre-commit-hooks.yaml`, `.github/dependabot.yml`, ESLint 9 flat config (`eslint.config.mjs`), Prettier (`.prettierrc.json`), and dogfooded root `.indicative.yml`.
- **Static Cloud Identity & AWS IAM Risk Intelligence (`@indicative/cloud-identity`, `v0.3.0-dev`):**
  - Workflow cloud-identity reference extractor (`aws-actions/configure-aws-credentials` `role-to-assume`, `azure/login` `client-id`, `google-github-actions/auth` `workload_identity_provider`).
  - Offline static AWS IAM parser for Terraform HCL (`.tf` including cross-file `aws_iam_role`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_policy`, `data "aws_iam_policy_document"`), CloudFormation (`.yml`/`.yaml`/`.json`), and standalone IAM Policy JSON.
  - 8 versioned, documented rules (`indicative-cloud-iam-v1.0.0`, `rules/cloud-identity/aws-iam/README.md`) covering Admin access (`IAM-ADMIN-001`), broad service wildcards (`IAM-PERM-001`), `NotAction`/`NotResource` Allow (`IAM-PERM-002`), sensitive secret/KMS/S3 wildcard read (`IAM-DATA-001`), IAM mutation & `iam:PassRole` privilege escalation (`IAM-ESC-001`), unrestricted `sts:AssumeRole` (`IAM-ESC-002`), missing `permissions_boundary` (`IAM-BOUND-001`), and cross-file GitHub Actions → OIDC → AWS IAM attack-chain correlation (`IAM-CORR-001`) with explicit `UNKNOWN` runtime control disclosures.
  - End-to-end integration via `CloudIdentityIamAdapter` (`cloud-identity-iam`, category `CLOUD_IDENTITY`) in `scanner-runner`, canonical fingerprinting, prioritization, API/UI breakdowns, standalone CLI (`npm run scan:cloud-identity`), and vulnerable/hardened regression corpora (`8/8` TP, `0` FP).

## [0.2.0-dev]

### Added
- **CI/CD & OIDC Federation Security Intelligence (`@indicative/cicd-security`):**
  - Safe AST-based YAML 1.2 GitHub Actions workflow parser with exact line-number tracking and YAML alias-bomb (`maxAliasCount`) and file-size protections.
  - 16 versioned, documented detection rules (`indicative-cicd-gha-v1.0.0`) across Permissions (`GHA-PERM-001..004`), Unsafe Triggers (`GHA-TRIG-001..002`), Expression Injection (`GHA-INJ-001` with safe `env:` indirection recognition), Third-Party Action & Reusable Workflow Pinning (`GHA-ACT-001..003`), Secret Exposure & Static Cloud Credentials (`GHA-SEC-001..002`), Build Integrity (`GHA-INT-001..002`), and Static OIDC Federation Trust & Cross-File Correlation (`GHA-OIDC-001..003`) across AWS IAM, Azure Federated Identity Credentials, and GCP Workload Identity Federation.
  - Configurable policy evaluation (`informational`, `warning` [default non-blocking], `failure`), injection-safe GitHub Actions annotations, Pull-Request Markdown summaries, and standalone local CLI (`npm run scan:cicd`).
  - Integrated `CicdGitHubActionsAdapter` into `scanner-runner`, canonical `CICD` finding category & anchor-based fingerprinting, `/api/v1/workflows`, `/api/v1/projects/:projectId/workflows`, `/api/v1/scanners`, and the Next.js `/workflows` Workflow Security UI view.
  - Vulnerable and hardened CI/CD + OIDC regression corpus (`tests/fixtures/cicd-vulnerable`, `tests/fixtures/cicd-hardened`) and precision/recall benchmark suite (`tests/regression/cicd-corpus-benchmark.test.ts`).
- **Core Intelligence & Reliability Enhancements:**
  - Offline-capable Vulnerability Intelligence enrichment (`packages/findings/src/intelligence.ts`) supporting CISA KEV and FIRST EPSS snapshots with source provenance, observation timestamps, and non-blocking failure isolation.
  - Upgraded contextual risk prioritization explicitly distinguishing `[VERIFIED]`, `[INFERRED]`, and `[UNKNOWN]` signals while preserving original scanner severity.
  - Trivy offline vulnerability DB freshness inspection (`db/metadata.json`) emitting `TRIVY_DB_STALE` limitations when stale.
- **Developer Workflow & Automation:**
  - Verified GitHub App Webhook receiver (`POST /api/v1/webhooks/github`) enforcing constant-time `X-Hub-Signature-256` verification over raw request bytes, durable `X-GitHub-Delivery` replay deduplication (`webhook_deliveries`), automated `push` & `pull_request` scans, GitHub Check Runs with inline annotations, and sticky Markdown PR summary comments (`<!-- indicative-security-summary -->`).
  - Reusable composite GitHub Action (`action.yml`) and reusable workflow (`.github/workflows/reusable-cicd-scan.yml`) with SHA-pinned steps, `env:`-isolated inputs, SARIF 2.1.0 Code Scanning upload (`formatCicdReportAsSarif` + `--sarif-file`), and GitHub Job Summaries.
  - Scheduled/recurring scans (`scan_schedules` table, deterministic 5-field UTC cron engine, worker poller, and `/api/v1/schedules` CRUD + manual trigger API).
  - Encrypted-at-rest (`HKDF-SHA256` + `AES-256-GCM`) notification channels (`notification_channels` & `notification_deliveries`) supporting Slack Incoming Webhooks, Jira Cloud REST v3 Issues, and GitHub Issues with strict SSRF validation, fail-closed secret redaction, `/api/v1/notifications/*` APIs, and the `/automations` Next.js UI page.
- **Audit, Architecture & Open-Source Community Foundation:**
  - `docs/audits/current-state-assessment.md`, `docs/product/competitive-landscape.md`, `docs/product/product-roadmap.md`, `docs/architecture/ci-cd-security-architecture.md`, `docs/architecture/ci-cd-security-threat-model.md`, `rules/cicd/github-actions/README.md`, `docs/community/README.md`.
  - `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `ROADMAP.md`, `SUPPORT.md`, GitHub issue/PR templates, and dogfooded `.github/workflows/ci.yml`.

### Security & Bug Fixes
- Pre-sanitize escaping/broken symlinks during writable worker ingestion before handing off to read-only (`:ro`) `scanner-runner` mounts, and handle `EROFS`/`EACCES` cleanly in `sanitizeUntrustedWorkspace`.
- Restrict CORS origins in `NODE_ENV=production` strictly to `WEB_PUBLIC_URL` (removing hardcoded localhost origins in production).
- Enforce strict UUID validation on `:projectId`, `:scanId`, and `:findingId` API route parameters (returning HTTP 400 instead of PostgreSQL 500).
- Confine dev `DEMO_MODE` `localFixturePath` strictly to approved fixture/temp roots via `validateSafePathWithinRoot`.
- Enforce per-organization `security_policies` (`maxConcurrentScans`, `allowAiAnalysis`) on scan initiation, AI analysis, and AI Advisor endpoints.
- Fix dashboard `repositoriesScanned` metric to count distinct projects across all organization scans rather than only the 10 most recent scans, and surface `CICD` category counts and `inconclusiveVerification` totals.
- Fix root `npm run build` script to compile workspaces in deterministic topological dependency order.

## [0.1.0] — MVP Baseline

### Added
- TypeScript monorepo (`apps/web`, `apps/api`, `apps/worker`, `services/scanner-runner`, `packages/*`).
- PostgreSQL 16 + Drizzle ORM (19 tables), Redis/BullMQ async processing, GitHub OAuth + GitHub App short-lived read-only token ingestion.
- Pinned Semgrep CE `1.186.0`, Trivy `0.76.2`, and Gitleaks `8.30.1` isolated scanner adapters.
- Tenant-keyed HKDF+HMAC-SHA256 secret fingerprinting, ReDoS-hardened PEM scrubbing and chunked redaction.
- Optional OpenAI-compatible AI Security Analyst & scoped Advisor with `<UNTRUSTED_REPOSITORY_DATA>` fencing and pre-LLM redaction gate.
- Streaming JSON, SARIF 2.1.0, and formula-safe CSV report exports, gVisor/Kata sandbox profiles, and full automated test suite.
