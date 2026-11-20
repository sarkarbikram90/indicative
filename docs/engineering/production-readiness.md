# Indicative — Production-Readiness Assessment & Cost Model

## 1. Current MVP Readiness Summary

The Indicative MVP delivers a working, tested, security-conscious end-to-end platform suitable for **local evaluation, single-team pilot deployments, and controlled demonstrations**. It is **not yet hardened for untrusted public multi-tenant SaaS production** without the additional infrastructure controls documented below.

## 2. Implemented Security Controls (Verified by Automated Tests)

| Control Area | Implemented in MVP | Verification Evidence |
|---|---|---|
| Secret Handling | Tenant-keyed HKDF + HMAC-SHA256 secret fingerprinting, safe masking, immediate deletion of raw Gitleaks reports, pre-LLM redaction gate, redacting logger, artifact persistence secret guard | `packages/security/src/security.test.ts`, `tests/e2e/full-workflow.e2e.test.ts` |
| Tenant Isolation | Server-derived `organizationId` from validated DB session enforced in every API query & AI Advisor scope | `tests/security/security-controls.test.ts` |
| Authentication & CSRF | HttpOnly `SameSite=Lax` session cookies, SHA-256 hashed session tokens, HMAC-signed OAuth `state` cookie, `X-CSRF-Token` verification on cookie mutations, strict production block on `DEMO_MODE` and default dev keys | `tests/integration/platform.integration.test.ts`, `tests/security/security-controls.test.ts` |
| Untrusted Code Execution | Dedicated `services/scanner-runner`, zero shell execution (`shell: false`), strict binary allowlist, stripped scanner environment (no GitHub/DB/AI keys), symlink escape removal, path traversal validation, file/size ceilings, timeouts, Docker `read_only`, `cap_drop: ALL`, `no-new-privileges`, `internal: true` no-egress network | `packages/scanners/src/scanners.test.ts`, `tests/security/security-controls.test.ts` |
| SSRF & Git Hardening | Strict `owner/repo` slug validation, private/loopback/link-local/metadata IP blocking, git clone with `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `protocol.file.allow=never`, `submodule.recurse=false`, transient HTTP auth header | `packages/security/src/security.test.ts`, `apps/worker/src/ingestion/repositoryIngestor.ts` |
| Scanner Failure Transparency | Explicit per-scanner statuses (`SUCCESS`, `FAILED`, `TIMEOUT`, `CANCELLED`, `PARTIAL`, `UNAVAILABLE`), `COMPLETED_WITH_ERRORS`, `VERIFICATION_INCONCLUSIVE` on scanner failure or truncated Git history | `packages/findings/src/findings.test.ts`, `tests/security/security-controls.test.ts` |
| AI Safety & Prompt Injection | Optional `DisabledAiProvider` default, `<UNTRUSTED_REPOSITORY_DATA>` fencing, injection signal detection, strict Zod schema validation, zero tool-execution authority | `packages/ai/src/ai.test.ts` |

## 3. Security Risks Requiring Additional Production Hardening

1. **Multi-Tenant Container Isolation (Critical for SaaS):** Standard Docker containers share the host Linux kernel. Before scanning untrusted code from competing customer organizations in production, deploy `services/scanner-runner` on microVM or hardened sandbox runtimes (**AWS Firecracker**, **Kata Containers**, or **gVisor `runsc`**) with single-use ephemeral sandboxes destroyed after every scan.
2. **Database Defense-in-Depth (High):** Enable **PostgreSQL Row-Level Security (RLS)** policies keyed on `app.current_organization_id` in addition to the existing service-layer `organization_id` predicates.
3. **Key Management & Encryption at Rest (High):** Manage `SECRET_FINGERPRINT_KEY`, `SESSION_SECRET`, and `GITHUB_APP_PRIVATE_KEY` via a Cloud KMS / HSM (AWS KMS, GCP KMS, HashiCorp Vault) with envelope encryption and scheduled key rotation. Enable TLS everywhere (API, Postgres, Redis, S3/MinIO) and volume/bucket encryption at rest.
4. **Network Egress Firewalling (High):** Enforce VPC/Kubernetes `NetworkPolicy` rules blocking cloud metadata endpoints (`169.254.169.254/32`) for all workloads, allowing `apps/worker` egress strictly to `github.com` and `api.github.com`, and enforcing zero egress on `services/scanner-runner`.
5. **Artifact Retention Sweeper (Medium):** While `scan_artifacts.expires_at` is persisted on every report artifact, add a scheduled background retention cleanup cron worker in production to purge expired S3 objects and database rows automatically.
6. **GitHub Webhook Verification & Push Scans (Planned):** Currently scans are initiated manually or via API; automated PR/push-triggered scans require HMAC-SHA256 `X-Hub-Signature-256` webhook verification and replay protection.

## 4. Infrastructure & Operating Cost Considerations

| Cost Driver | MVP Safeguard | Production Sizing Guidance |
|---|---|---|
| Scanner CPU & Memory | `MAX_REPO_SIZE_MB=250`, `MAX_FILES_PER_SCAN=25000`, `SCANNER_TIMEOUT_MS=120000`, `MAX_CONCURRENT_SCANS_PER_ORG=3`, Docker `cpus: 2`, `mem_limit: 2g` | Scale scanner worker pools independently on spot/preemptible compute (e.g., 2 vCPU / 4 GB RAM handles typical JS/TS/Python repos in 5–15 seconds). |
| LLM API Token Spend | Deterministic scanning always runs first; AI is disabled by default (`AI_PROVIDER=disabled`), invoked only on user request or top 5 Critical/High findings, bounded by `AI_MAX_CONTEXT_CHARS=12000` & `AI_MAX_TOKENS=1200`, with token telemetry recorded per analysis in `finding_ai_analyses`. | Estimate ~500–1,500 tokens per analyzed finding (< \$0.002/finding on small models like `gpt-4o-mini`). Enforce per-organization monthly AI token budgets before GA. |
| Object Storage & Database | Redacted JSON/SARIF artifacts only (raw unredacted scanner outputs are immediately deleted), `ARTIFACT_RETENTION_DAYS=30`. | Typical normalized JSON + SARIF report is 20–200 KB per scan; PostgreSQL storage scales linearly with `finding_occurrences` and `audit_events`. |
| Vulnerability DB Distribution | Controlled offline Trivy DB update script (`infrastructure/scripts/update-trivy-db.sh`) baked into runner image or shared read-only cache volume. | Refresh Trivy DB every 6–24 hours in CI/maintenance pipeline and mount read-only to air-gapped runners to avoid per-scan egress charges. |
