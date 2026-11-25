# Indicative — Product Strategy

**Last Updated:** 2026-11-24  
**Positioning:** *Indicative — Evidence-Driven Security Intelligence Across Application Code, Software Delivery Pipelines, and Cloud Identities.*

> **Core Product Principle:** Understand the relationship between **code risk**, **delivery risk**, and **access risk** — and prove every link with explicit evidence and honest uncertainty.
>
> **Core Philosophy:** `Detect → Understand → Correlate → Prioritize → Recommend → Verify`

---

## 1. Strategic Thesis

Modern software delivery forms one tightly coupled security boundary across three domains that traditional cybersecurity tooling treats in isolation:

```text
Application Source Code  ──►  GitHub Repository & CI/CD   ──►  Cloud Identity & Permissions  ──►  Production Infrastructure
(Java, Python, Go, JS/TS)     (GitHub Actions, Build/Deploy)    (OIDC, AWS IAM, STS, SAs)         (AWS, K8s, DBs, S3, APIs)
```

- A **vulnerability or exposed secret in application code** is one problem.
- An **insecure GitHub Actions workflow** (`pull_request_target`, `write-all`, expression injection, unpinned actions) is a second problem.
- An **overly permissive cloud OIDC trust policy and IAM role** (`sub: repo:org/*`, `s3:*` on `*`, `iam:PassRole`) is a third problem.

Individually, dozens of point tools already scan each layer (Semgrep, Trivy, Gitleaks, `zizmor`, `actionlint`, Prowler, PMapper, Cloudsplaining). **The highest-value gap is connecting evidence across the boundaries between them.** When weaknesses in all three layers align, they form an end-to-end attack path from untrusted code or pull requests straight to production cloud resources.

Indicative's strategic scope for the next 12 months is therefore **not** to build yet another standalone code scanner, workflow linter, or cloud posture checklist, but to build an open-source, evidence-driven **Security Intelligence Platform** spanning three connected pillars — with a natural fourth extension into **AI Agent & Non-Human Identity (NHI) Security**.

---

## 2. The Three Connected Pillars (and Fourth Evolution)

### Pillar 1 — Application Security Intelligence *(Foundation Verified in `v0.2.0-dev`; Reachability Planned)*
Answers: ***"Is the software we are developing secure — and does a finding actually matter in context?"***

- **Verified today:** Deterministic multi-engine analysis via pinned **Semgrep CE** (SAST), **Trivy** (SCA + Docker/K8s/Terraform IaC, with offline DB staleness detection), and **Gitleaks** (working tree + Git history), enriched with offline-capable **CISA KEV** and **FIRST EPSS** intelligence, tenant-keyed `HKDF+HMAC-SHA256` secret fingerprinting, and transparent `[VERIFIED]` / `[INFERRED]` / `[UNKNOWN]` risk rationale.
- **Next evolution:** Move beyond vulnerability detection to true **application security intelligence** — understanding where a vulnerability lives, whether vulnerable functionality is reachable, which application/service consumes the dependency, whether external users can reach it, whether a fix exists, whether a privileged deployment workflow ships it, and whether remediation actually resolved the issue.

### Pillar 2 — CI/CD Security Intelligence *(Native Engine Verified in `v0.2.0-dev`; Deeper Coverage Planned)*
Answers: ***"Can someone compromise our software delivery process and use it to attack our systems?"***

CI/CD pipelines are privileged infrastructure with access to repository write tokens, container registries, cloud credentials, and production deployments.

- **Verified today (`@indicative/cicd-security`):** Offline AST-based YAML 1.2 GitHub Actions analyzer with 16 versioned rules covering `GITHUB_TOKEN` permissions (`write-all`, missing/excessive scopes, `id-token: write`), unsafe triggers (`pull_request_target`, `workflow_run`), expression injection (with safe `env:` indirection recognition), mutable action/reusable-workflow pinning, secret exposure, and build integrity — integrated with PR comments, Check Runs, SARIF 2.1.0, CLI, and `/workflows` UI.
- **Next evolution:** Deepen coverage across artifact security, cache poisoning, and runner privileges — combining Indicative's native structural AST extractor with optional pinned external adapters (`zizmor`, `actionlint`) and cross-engine deduplication.

### Pillar 3 — Cloud Identity Risk *(Static OIDC Trust Verified in `v0.2.0-dev`; IAM Policy & Live Verification Planned)*
Answers: ***"Who or what can access our cloud infrastructure, and what can they do with that access?"***

Cloud identity is the bridge between software delivery and production infrastructure (e.g., `GitHub Actions → GitHub OIDC Provider (JWT) → AWS IAM Trust Policy → STS AssumeRoleWithWebIdentity → AWS IAM Role → Production Resources`).

- **Verified today:** Static OIDC trust-policy analysis across AWS IAM, Azure Federated Identity Credentials, and GCP Workload Identity Federation (`sub`/`aud` claim scoping) with cross-file correlation to `id-token: write` workflows.
- **Next evolution:**
  1. **Workflow-to-Role Identity Linking:** Resolve explicit `role-to-assume`, `client-id`, and `workload_identity_provider` targets from workflows to IaC role definitions.
  2. **Static AWS IAM Policy & Blast-Radius Analysis:** Analyze inline and managed policies, wildcard actions/resources (`s3:*`, `*`), sensitive data/secret access, cross-account trust, and privilege-escalation primitives (`iam:PassRole`, `iam:PutRolePolicy`, `sts:AssumeRole`) across Terraform, CloudFormation, and IAM JSON — before requiring any live cloud access.
  3. **Optional Read-Only Live Cloud Verification (Later):** Authorized, temporary-credential, strictly read-only cloud verification to resolve controls that static analysis must mark `UNKNOWN` (live attached policies, AWS SCPs, Permission Boundaries, GitHub branch/environment protection gates).

> **Contextual Honesty Rule:** Having `id-token: write` in a workflow is **not** automatically a vulnerability. A credible attack path requires the token request, workflow execution context, federation trust conditions, and resulting IAM role permissions to align. Indicative validates each hop and explicitly discloses unverified controls.

### Pillar 4 (Future Research Evolution) — AI Agent & Non-Human Identity (NHI) Security
Answers: ***"Which autonomous agents and MCP tools hold delegated credentials, what can they execute or access, and where do they exceed least privilege?"***

Engineering teams are rapidly adopting AI coding assistants, autonomous development/deployment agents, and MCP servers. From a security architecture standpoint, **an AI agent is another Non-Human Identity (NHI)** operating across repositories, CI/CD, APIs, and cloud infrastructure.

The exact same identity and authorization questions apply:
- Who authenticated the agent and who delegated its permissions?
- What repositories, secrets, MCP tools, APIs, or cloud roles can it reach?
- Can it trigger privileged workflows or pass credentials across tool boundaries?
- How is its access revoked and audited?

Because Pillars 1–3 establish an evidence-backed Identity Relationship Graph, AI Agent & NHI Security builds naturally on the same foundation — starting with deterministic static analysis of MCP server configurations, tool scopes, and credential exposure aligned with **OWASP Agentic Security Initiative (ASI)** and **OWASP MCP Top 10**.

---

## 3. Differentiating Questions Indicative Must Answer

Rather than competing on "how many Critical alerts exist," Indicative aims to answer five high-value cross-boundary questions with inspectable evidence:

1. *"Which repositories can indirectly obtain production cloud access?"*
2. *"Which deployment workflows have permissions beyond their intended responsibilities?"*
3. *"Which cloud identities are reachable through our CI/CD configuration?"*
4. *"Which vulnerabilities exist in applications deployed by privileged workflows?"*
5. *"Which AI agents or MCP servers have access to resources they do not need?"*

---

## 4. Target Customers & Primary Personas

### Target Segments
- **Startups & Growth Engineering Teams (5–100 engineers):** Need unified AppSec + CI/CD + OIDC guardrails without enterprise CNAPP pricing or per-seat SCM tax.
- **Platform & DevSecOps Teams (50–500 engineers):** Need to audit GitHub Actions pipelines, enforce OIDC/IAM least privilege across repositories, and prove remediation deterministically.
- **Security Consultants, Auditors & Software Agencies:** Need repeatable, self-hosted, data-sovereign baseline assessments with clean SARIF/JSON/CSV/PR deliverables.

### Primary Persona
A staff engineer, engineering lead, or DevSecOps practitioner responsible for code, GitHub Actions, and cloud delivery pipelines who needs:
- Deterministic, line-accurate detection with zero hallucinated findings.
- Clear explanation of **how** code, pipeline, and identity findings connect — and **what remains unknown**.
- Strict guarantees that plaintext secrets never leak into databases, logs, exports, or LLM prompts.
- Honest scan-over-scan verification of whether fixes actually removed the risk.

---

## 5. Non-Negotiable Strategic Principles

1. **Evidence and honesty over hype:** Every finding and every attack-path hop explicitly declares its evidence basis (`VERIFIED_STATIC`, `VERIFIED_RUNTIME`, `INFERRED`, `UNKNOWN`) and lists unverified controls.
2. **Deterministic engines are the source of truth:** Scanners and graph correlators produce authoritative evidence. Optional AI explains, contextualizes, and drafts remediation — it never invents vulnerabilities, fabricates attack paths, or suppresses alerts.
3. **Strict secret safety:** Plaintext credentials are never stored in findings, shown in normal UI responses, written to logs, sent to LLMs, or included in exported reports (`HKDF+HMAC-SHA256` tenant-keyed fingerprinting + fail-closed redaction).
4. **Honest verification semantics:** Secret removal from Git never implies credential revocation (`NOT_VERIFIED`); failed or partial scanners mark absent findings `VERIFICATION_INCONCLUSIVE`.
5. **Staged, vertical-slice execution:** Never build all pillars simultaneously in half-finished form. Every milestone ships end-to-end with positive/negative regression fixtures, strict typechecking, and synchronized documentation (see [ADR-013](../engineering/architecture-decisions.md)).

---

## 6. Brand & Naming Note

"Indicative" is used as a working product brand name (Apache-2.0 license). Trademark and domain availability have not been verified.
