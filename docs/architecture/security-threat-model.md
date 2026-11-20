# Indicative — Security Threat Model

## 1. Scope and assumptions

Indicative processes untrusted source code and untrusted scanner output. Every repository file, branch name, commit message, filename, README, comment, package manifest, and scanner result is treated as potentially malicious.

The MVP runs as a modular monolith with a separate scanner runner. Docker containers are **not** by themselves a sufficient multi-tenant security boundary. Production-grade isolation requires the additional controls below; any deviation must be documented as a known limitation.

## 2. Assets

- User identity, sessions, and organization membership
- GitHub App private key and short-lived installation tokens
- Repository source, history, and metadata
- Security findings, evidence, and reports
- Secret fingerprints (keyed HMAC) and redaction keys
- AI provider credentials and prompt/analysis history
- Audit events

## 3. Trust boundaries

| Boundary | Trusted side | Untrusted side |
|----------|--------------|----------------|
| Browser → API | API validates/authz | Browser input, uploads |
| API → Worker | Queue payloads validated | Job metadata from users |
| Ingestion → Runner | Controlled repository snapshot | Repository contents |
| Runner → Findings pipeline | Process boundary | Scanner stdout/stderr |
| Findings → AI | Sanitized context | Scanned repository text (via context) |
| Service → PostgreSQL | Parameterized queries | Data values |

## 4. Threats and mitigations

### T1 — Malicious repository code executed during scanning
**Threat:** A repository contains code designed to escape the scanner environment, contact the network, or read host files.
**Mitigation:** Ephemeral isolated workspace per scan; no privileged containers; no Docker socket; rootless/non-root execution where supported; dropped Linux capabilities; seccomp/AppArmor or equivalent; read-only root filesystem where practical; CPU/memory/disk/process limits; hard timeouts; no host mounts beyond approved workspace; no cloud credentials or metadata endpoint access; restricted egress.

### T2 — Scanner used as an execution primitive
**Threat:** User-influenced paths or flags are passed to a shell and cause command injection.
**Mitigation:** No shell execution with interpolated input. Safe process spawning with argument arrays. Allowlisted binaries only. All paths validated and confined to the workspace. Exit codes and durations captured. Output size bounded.

### T3 — Secret leakage
**Threat:** Plaintext credentials reach the UI, logs, database, reports, or an LLM request.
**Mitigation:** Central redaction stage applied to all scanner output before persistence, display, logging, or AI requests. Safe masking for display. Keyed HMAC fingerprints using a tenant-specific key for correlation without plaintext. No plaintext credentials stored in the findings database. Unredacted scanner output is disposed of immediately. Audit logging on sensitive operations. Secret validity always reported as `UNKNOWN` / `NOT_VERIFIED`.

### T4 — Prompt injection through repository content
**Threat:** Source code, READMEs, comments, or scanner output instruct the AI to ignore rules, reveal secrets, make network requests, or suppress findings.
**Mitigation:** Repository content is data, never instructions. Narrow, sanitized context only. No tools granted to the analyst. Structured, schema-validated outputs. The analyst cannot execute commands, change repository contents, suppress findings, or override authorization. Prompt and model versions stored with each analysis.

### T5 — Cross-tenant data access
**Threat:** A user reads another organization's findings by manipulating IDs.
**Mitigation:** Every tenant-owned record has explicit ownership. Tenant scoping enforced in service layer and, where feasible, at the database layer. Never rely on frontend filtering. Authorization checked on every relevant operation, including repository access validation.

### T6 — GitHub token exposure / SSRF
**Threat:** Installation tokens leak to the frontend or logs, or the scanner clones arbitrary user-supplied URLs.
**Mitigation:** Short-lived installation tokens, never sent to the frontend or written to logs. Trusted ingestion validates repository identity and uses approved endpoints. Scanner cannot clone arbitrary URLs. OAuth state/CSRF protections. Minimum required read-only GitHub App permissions.

### T7 — Malicious filenames, paths, and symlinks
**Threat:** Path traversal, archive slips, or symbolic links escape the workspace.
**Mitigation:** Path normalization and confinement checks; reject absolute paths and traversal segments; symlink handling policy (do not follow outside workspace); validated artifact names.

### T8 — Denial of service / resource exhaustion
**Threat:** Oversized repositories, huge output, slow scanners, or excessive AI calls exhaust resources.
**Mitigation:** Repository size and scan duration limits; output size caps; per-organization concurrency limits; worker resource limits; AI context/token/timeout caps; rate limiting; bounded retries.

### T9 — Malformed or hostile scanner output
**Threat:** Scanner stdout is not valid JSON, is enormous, or contains crafted fields.
**Mitigation:** Defensive parsers with schemas, size limits, and safe failure. Malformed output produces an explicit parse error, never a clean result.

### T10 — False assurance
**Threat:** A failed scanner is interpreted as "no findings", or repository removal is claimed as credential revocation.
**Mitigation:** Distinct execution statuses and scan states. Failures surfaced in UI and reports. Precise terminology: "not detected in latest scan" / "verification successful within scanned scope". Credential revocation explicitly out of scope.

### T11 — Audit gap
**Threat:** Human decisions such as accepting risk or marking a false positive cannot be reconstructed.
**Mitigation:** Audit events for status changes, sensitive operations, and administrative actions, with actor, timestamp, and correlation ID.

## 5. Data security controls

- Secure session management; authentication and authorization on all protected endpoints
- Encryption in transit; encryption at rest where supported by the platform
- Secrets management via environment/secret store; no real credentials in the repository
- Input validation (Zod) and output sanitization
- Secure file handling and artifact retention/deletion configuration
- Error handling that does not leak sensitive data
- Never log raw credentials, installation tokens, or plaintext secrets

## 6. Local development exception

A local demo mode is acceptable only if it is explicitly restricted to development and cannot silently become a production authentication bypass. Demonstration fixtures must be clearly distinguished from real customer scans. The development runner profile must be labeled as not providing production isolation.

## 7. Residual risks requiring production hardening

- Container-based isolation may be insufficient for hostile multi-tenant workloads without a stronger sandbox (microVM or equivalent).
- Secret redaction is pattern/entropy based and may miss novel credential formats or produce false positives; it is a safety net, not a guarantee.
- AI analysis can be wrong; it is presented as analysis/recommendation, not verified evidence.
- Scanner rulesets and vulnerability databases require controlled update and verification; stale data reduces coverage.
- Object storage, backup encryption, and key rotation require operational configuration.
