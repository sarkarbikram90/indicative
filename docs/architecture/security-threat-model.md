# Indicative — Security Threat Model

## 1. Scope & Assumptions

Indicative processes untrusted customer and third-party source code alongside sensitive security findings. Every repository file, filename, branch name, commit message, README, comment, manifest, and scanner stdout/stderr stream is treated as hostile.

Docker containers are **not** by themselves a sufficient production multi-tenant security boundary. Local development enforces hardened container controls; production multi-tenant SaaS deployments require microVM/gVisor isolation (documented in §6 and [production-readiness.md](../engineering/production-readiness.md)).

## 2. Protected Assets

- User identities, sessions (`user_sessions.token_hash`), and organization memberships
- GitHub App private key and short-lived installation tokens
- Repository source code, commit history, and metadata
- Security findings, redacted evidence, and exported reports
- Master HMAC root key (`SECRET_FINGERPRINT_KEY`) and tenant-derived secret fingerprints
- Optional LLM provider API keys and AI analysis records
- Audit trail (`audit_events`, `finding_status_history`)

## 3. Trust Boundaries

| Boundary | Trusted Side | Untrusted Side |
|---|---|---|
| Browser → API | API authN/authZ, Zod validation, CSRF check | Browser inputs, query params, cookies |
| API → Worker | Validated queue payload & scan DB record | User-supplied scan/project parameters |
| Ingestion → Runner | Validated GitHub App clone / sanitized workspace | Repository source files & Git history |
| Runner → Findings Pipeline | Isolated process/container boundary | Scanner stdout/stderr & JSON outputs |
| Findings → AI | Redacted, fenced context & Zod output schema | Repository excerpts embedded as data |
| Service → PostgreSQL | Parameterized Drizzle SQL + `organizationId` scoping | Persisted data values |

## 4. Threats & Implemented Mitigations (`T1`–`T11`)

| Threat ID | Threat | Implemented MVP Mitigation |
|---|---|---|
| **T1** | **Malicious repository code executed during scanning** | Ephemeral per-scan workspace destroyed in `finally`; Docker `scanner-runner` runs as non-root `10001:10001`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, `pids_limit: 256`, CPU/memory caps, no Docker socket, no cloud/GitHub credentials, and `scanner_internal` (`internal: true`) network with zero outbound internet egress. |
| **T2** | **Scanner used as a command-injection primitive** | Zero shell execution (`spawn(..., { shell: false })` with explicit argument arrays only); strict binary allowlist (`semgrep`, `trivy`, `gitleaks`, `git`); `--` end-of-options markers; stripped scanner environment removing control-plane secrets. |
| **T3** | **Plaintext secret leakage** | Immediate tenant-keyed HKDF+HMAC-SHA256 fingerprinting (`packages/security/src/secrets.ts`), safe masking, `finally` deletion of raw Gitleaks JSON output, redacting logger, artifact persistence secret guard, pre-LLM redaction gate, and automated zero-leak assertions across DB/UI/logs/reports/AI. Secret validity is always `NOT_VERIFIED` / `UNKNOWN`. |
| **T4** | **Prompt injection via repository content** | Untrusted repository text wrapped in `<UNTRUSTED_REPOSITORY_DATA>` tags with tag-breakout stripping and injection-signal detection; system prompt enforces data-only treatment; AI has zero tool-execution or write permissions; strict Zod output validation; deterministic scanner severity/status cannot be overwritten. |
| **T5** | **Cross-tenant data access (IDOR)** | Every tenant-owned record carries `organization_id`; all API/service queries derive `organizationId` from server-verified sessions and enforce `organization_id` predicates (verified by cross-tenant security tests). |
| **T6** | **GitHub token exposure & SSRF** | Short-lived read-only GitHub App installation tokens minted only on backend worker, passed via transient `git -c http.extraHeader=...` (never saved in `.git/config`, never logged, never sent to browser). Git clone disables hooks (`core.hooksPath=/dev/null`), `core.fsmonitor=false`, `protocol.file.allow=never`, and `submodule.recurse=false`. Strict `owner/repo` slug validation and private/loopback/link-local/metadata IP blocking (`169.254.169.254`). |
| **T7** | **Malicious filenames, path traversal & symlinks** | `validateSafePathWithinRoot` and `normalizeRepoRelativePath` block `..`, null bytes, and root escapes; `sanitizeUntrustedWorkspace` inspects with `lstat`, removes symlinks escaping workspace root, and flags suspicious filenames (`--`, shell metacharacters). |
| **T8** | **Denial of service / resource exhaustion** | Configurable `MAX_REPO_SIZE_MB`, `MAX_FILES_PER_SCAN`, `SCANNER_TIMEOUT_MS`, `MAX_SCAN_DURATION_MS`, `MAX_CONCURRENT_SCANS_PER_ORG`, capped stdout/stderr buffers, API rate limiting, and AI context/token/timeout/retry limits. |
| **T9** | **Malformed or hostile scanner output** | Defensive JSON parsers (`parseSemgrepOutput`, `parseTrivyOutput`, `parseAndRedactGitleaksOutput`) classify corrupt output as `FAILED` / `MALFORMED_OUTPUT` rather than clean scans. |
| **T10** | **False assurance** | Distinct `ScannerExecutionStatus` and `ScanStatus` (`COMPLETED_WITH_ERRORS`, `FAILED`). Missing findings during a failed/truncated scan yield `VERIFICATION_INCONCLUSIVE`, never `RESOLVED_VERIFIED`. Secret removal explicitly states credential revocation is unverified. |
| **T11** | **Audit gap** | `audit_events` and `finding_status_history` capture actor, timestamps, correlation ID, and justification for auth events, installations, scans, exports, AI requests, and human finding status decisions. |

## 5. Development Demo Mode Guardrail

`DEMO_MODE` is strictly prohibited in production: `packages/config` throws `SECURITY_VIOLATION` on startup if `NODE_ENV=production` with `DEMO_MODE=true` or default `dev-only-*` secrets. Demo users, organizations, projects, and scans are visibly labeled (`isDemo: true`) and execute real scanners against controlled local fixtures.

## 6. Residual Risks Requiring Additional Production Hardening

1. **Multi-tenant kernel isolation:** Replace standard Docker containers with microVMs (**Firecracker** / **Kata Containers**) or **gVisor (`runsc`)** before running untrusted multi-tenant customer scans in production.
2. **Database defense-in-depth:** Enable PostgreSQL Row-Level Security (RLS) in addition to service-layer `organization_id` checks.
3. **Key management & encryption:** Store master HMAC/session/GitHub keys in Cloud KMS/HSM with envelope encryption and key rotation; enforce TLS and encryption at rest across DB, Redis, and object storage.
4. **VPC egress controls:** Enforce cloud network policies blocking `169.254.169.254/32` and restricting worker egress solely to GitHub API endpoints.
5. **Redaction bounds:** Pattern/entropy redaction is a strong safety net, not an absolute proof against novel secret formats; combine with operational log-retention and access policies.
