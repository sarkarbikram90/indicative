# Indicative — Product Strategy

## 1. Product identity

**Indicative** is an open-source, AI-powered repository security intelligence platform. It helps developers and small engineering teams find security vulnerabilities and exposed secrets in their GitHub repositories, understand what those findings actually mean, prioritize remediation with evidence, and verify that fixes hold up in a later scan.

**Working brand name.** "Indicative" is used as the working product name. No trademark or domain availability has been verified; this is not a claim of ownership.

**Product positioning**

> Indicative transforms fragmented security findings into prioritized, evidence-backed remediation workflows.

**Core philosophy**

> Detect → Understand → Prioritize → Recommend → Verify

## 2. The problem

Developers who do not have a dedicated application security engineer face three recurring problems:

1. **Noise.** Security scanners produce large volumes of findings with little explanation of which ones matter in context.
2. **Loss of context.** A finding from a SAST tool, a dependency scanner, and a secret scanner each arrive in a different format, with different severity scales and no shared history.
3. **No verification loop.** After a fix, there is no reliable way to establish whether the issue actually went away in the scanned scope.

Existing tools are good at *detection*. Indicative is built to help with *understanding, prioritization, recommendation, and verification* on top of deterministic scanner output.

## 3. The five questions the product must answer

1. What security vulnerabilities exist in my repository?
2. Which findings actually matter?
3. What is the underlying cause?
4. What should I do to fix the problem?
5. How can I establish whether the problem has been resolved?

## 4. Target customers

**Initial segments**

- Individual software developers
- Independent software consultants
- Early-stage startups
- Small engineering teams
- Software development agencies
- Small DevSecOps teams

**Primary persona**

A developer or engineering lead who maintains one or more software repositories but has no dedicated AppSec specialist. They need an easy way to identify vulnerabilities, understand significance, and decide what to fix first — without becoming a security expert.

## 5. MVP boundaries

The MVP solves one clearly defined problem:

> Help developers understand and manage security vulnerabilities and exposed secrets in their GitHub repositories.

The MVP is a **modular monolith with independently deployable execution workers**, not a distributed microservices platform. A smaller number of trustworthy, well-explained findings is preferred over hundreds of unexplained alerts.

**In scope (MVP)**

- GitHub App-based repository integration
- Repository discovery, selection, and secure retrieval
- Semgrep (SAST), Trivy (SCA + misconfiguration), Gitleaks (secrets)
- Full-history secret scanning with explicit limitation reporting
- Canonical finding schema, normalization, deduplication, fingerprinting
- Evidence-backed severity and confidence
- Optional AI-assisted contextual analysis
- Findings dashboard, scan history, and comparison
- Remediation guidance and scanner-based verification
- JSON / SARIF / CSV reporting

**Out of scope (MVP)**

Autonomous penetration testing, DAST, automated exploitation, arbitrary website scanning, cloud/Kubernetes posture management, runtime monitoring, automatic credential revocation or rotation, automatic source modification, autonomous PR creation, multi-agent security systems, enterprise billing, complex RBAC, and mobile apps. These are future capabilities and must not complicate the MVP.

## 6. Competitive stance and design principles

1. **Deterministic detection.** Findings originate from real scanner results. AI never invents vulnerabilities.
2. **Evidence over assertion.** Every finding carries scanner provenance and evidence; every verification result carries execution evidence.
3. **Failure transparency.** A failed or partial scanner run is never presented as a clean scan.
4. **Security first.** Untrusted repository content and untrusted scanner output are treated as hostile. Secrets are redacted before they reach any UI, log, database, report, or LLM request.
5. **Simplicity over premature scale.** One codebase, clear module boundaries, separate workers.
6. **No fake functionality.** No dead buttons, no fabricated findings, no mocked integrations presented as real.
7. **Extensibility.** The scanner adapter contract allows future engines (e.g. Strix, DAST, CSPM) to be added without rewriting the findings engine.

## 7. Success criteria for the MVP

The MVP is demonstrable when a user can authenticate, authorize a GitHub repository, run real Semgrep/Trivy/Gitleaks scans, see normalized findings in a dashboard, open a finding with evidence and remediation, optionally receive AI analysis, and re-scan to verify whether a finding is still detected — all with tenant isolation, audit logging, and secret redaction. See `docs/product/mvp-scope.md` for the concrete acceptance criteria and `docs/engineering/implementation-plan.md` for the build sequence.

## 8. What is explicitly *not* claimed

- Indicative does not determine whether an exposed credential is active, revoked, or rotated. Credential validity is always `UNKNOWN` / `NOT_VERIFIED`.
- Removing a secret from a repository does not prove the credential is safe.
- AI-generated confidence is not confirmed exploitability.
- Docker containers alone are not a production multi-tenant security boundary; isolation limitations must be documented.
