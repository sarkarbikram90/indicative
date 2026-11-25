# Indicative — Strategic Product & Engineering Roadmap

**Last Updated:** 2026-11-24  
**Positioning:** *Indicative — Evidence-Driven Security Intelligence Across Application Code, Software Delivery Pipelines, and Cloud Identities.*

This roadmap reflects the verified baseline from [Current-State Assessment](../audits/current-state-assessment.md) and formalizes our 12-month strategic direction defined in [Product Strategy](./product-strategy.md) and [Cross-Domain Attack-Path & Identity Architecture](../architecture/attack-path-and-identity-architecture.md). Every milestone ships as a complete, tested vertical slice — never half-finished parallel tracks.

---

## 1. Strategic Progression Overview

| Stage | Milestone | Core Capability | Security Domain Learned & Delivered | Status |
|---|---|---|---|---|
| **Stage 0** | `v0.1.0` | Multi-engine SAST, SCA, Secrets, IaC + secret safety + honest lifecycle | Application Security foundation | ✅ **Completed & Verified** |
| **Stage 1** | `v0.2.0` | Audit hardening, KEV/EPSS intelligence, native GitHub Actions & static OIDC analyzer (`@indicative/cicd-security`), webhooks, PR/Check feedback, reusable SARIF Action, schedules, notifications | Contextual AppSec + CI/CD threat modeling + OIDC trust basics | ✅ **Completed & Verified** |
| **Stage 2** | `v0.3.0-alpha` | Deeper CI/CD coverage (optional pinned `zizmor`/`actionlint` adapters + artifact/cache/runner rules) & workflow-to-role identity linking | Complete CI/CD delivery threat surface | **Next (P1)** |
| **Stage 3** | `v0.3.0` | Static AWS IAM Policy & Blast-Radius Analyzer (`packages/cloud-identity`) — inline/managed policies, wildcards, sensitive resource access, privilege escalation | Cloud IAM authorization & least privilege (static, zero cloud creds) | **Next (P1)** |
| **Stage 4** | `v0.4.0` | **Typed Security Context Graph & Evidence-Backed Attack-Path Engine** (`packages/context-graph`, PostgreSQL-backed) + `/api/v1/attack-paths` + interactive Attack Path UI | Cross-boundary attack-path intelligence (Code × CI/CD × OIDC × IAM) | **Planned (P1)** |
| **Stage 5** | `v0.5.0` | AppSec Reachability, Exposure Signals & Supply-Chain Provenance (SBOM CycloneDX/SPDX, SLSA provenance, OpenSSF Scorecard) | Reachable application risk & build provenance | **Planned (P2)** |
| **Stage 6** | `v0.6.0` | Optional Authorized Read-Only Live Cloud Verification (AWS STS/IAM/SCPs, GitHub branch/env protection; then Azure/GCP) | Upgrading `UNKNOWN` static controls to `VERIFIED_RUNTIME` | **Planned (P3)** |
| **Stage 7** | `v0.7.0` | **AI Agent & Non-Human Identity (NHI) Security** — static MCP server & agent manifest analysis, tool scope/delegation graph edges (OWASP ASI & MCP Top 10) | Autonomous agent identity & permission intelligence | **Research / Future (P4)** |
| **Stage 8** | Post-Validation | Managed Multi-Tenant SaaS Hardening (gVisor/Kata/Firecracker microVMs, PostgreSQL RLS, Cloud KMS, SSO) | Enterprise multi-tenant SaaS operations | **Deferred (Post-Validation)** |

---

## 2. Verified Baseline (`v0.1.0` & `v0.2.0-dev`)

Already implemented, tested, and verified in this repository:
- **Core Platform & AppSec (`v0.1.0`):** TypeScript monorepo (`apps/web`, `apps/api`, `apps/worker`, `services/scanner-runner`, `packages/*`), PostgreSQL 16 (23 tables), Redis/BullMQ, pinned Semgrep CE `1.186.0`, Trivy `0.76.2`, Gitleaks `8.30.1`, tenant-keyed `HKDF+HMAC-SHA256` secret fingerprinting, honest `NOT_VERIFIED` / `VERIFICATION_INCONCLUSIVE` verification semantics, optional fail-closed AI Analyst.
- **Contextual Intelligence (`v0.2.0`):** Trivy offline DB freshness checks (`TRIVY_DB_STALE`), offline-capable CISA KEV + FIRST EPSS enrichment with provenance timestamps, explicit `[VERIFIED]` / `[INFERRED]` / `[UNKNOWN]` priority rationale.
- **Native CI/CD & Static OIDC Security (`v0.2.0`):** `@indicative/cicd-security` AST YAML 1.2 parser, 16 versioned rules (`indicative-cicd-gha-v1.0.0`), static AWS/Azure/GCP OIDC trust extraction & cross-file workflow correlation, standalone CLI, policy engine, `/api/v1/workflows`, `/workflows` UI, vulnerable & hardened regression corpora (`16/16` TP, `0` FP).
- **Developer Workflow & Automation (`v0.2.0`):** HMAC-SHA256 GitHub Webhooks with replay deduplication, automated PR comments & Check Runs, reusable composite GitHub Action (`action.yml`) with SARIF 2.1.0 Code Scanning upload, cron-scheduled scans, encrypted Slack/Jira/GitHub Issue notifications, `/automations` UI.

---

## 3. Detailed Problem Statements for Next 12-Month Milestones

### Milestone 1 (`v0.3.0-alpha` & `v0.3.0`): Deeper CI/CD Coverage + Static Cloud Identity & IAM Policy Risk
- **Problem:** Today, Indicative detects dangerous GitHub Actions workflows and overly broad OIDC trust policies (`sub`/`aud`), answering *"who can request a token and assume a role?"* — but it cannot yet answer ***"what can that cloud IAM role actually do once assumed?"*** Nor does it yet cover deeper GHA supply-chain edge cases (cache poisoning, artifact tampering, self-hosted runner risks) or link explicit `role-to-assume` ARNs in workflows to specific Terraform/CloudFormation role resources.
- **Solution:**
  1. **CI/CD Depth:** Expand native rules for artifact security, cache poisoning, and runner privileges, and evaluate/integrate pinned `zizmor` and `actionlint` as optional complementary `ScannerAdapter`s in `services/scanner-runner` with deterministic cross-engine deduplication.
  2. **Workflow-to-Identity Linking:** Extract concrete target identities from workflow steps (`aws-actions/configure-aws-credentials` `role-to-assume`, `azure/login` `client-id`, `google-github-actions/auth` `workload_identity_provider`).
  3. **Static AWS IAM Policy Analyzer (`packages/cloud-identity`):** Parse inline policies (`aws_iam_role_policy`), managed attachments (`aws_iam_role_policy_attachment`), standalone policies (`aws_iam_policy`, `aws_iam_policy_document`), and CloudFormation/JSON IAM documents to classify effective permissions:
     - Wildcard admin/resource scopes (`Action: "*"`, `s3:*` on `*`, `secretsmanager:*`)
     - Privilege escalation primitives (`iam:PassRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` chaining)
     - Sensitive resource classes (S3, RDS, Secrets Manager, KMS, EKS, IAM)
  4. **Zero live credentials required:** Entire stage runs offline inside `scanner-runner` with explicit `STATIC_CONFIG` evidence basis and `UNKNOWN` markers for AWS SCPs and Permission Boundaries.

### Milestone 2 (`v0.4.0`): Typed Security Context Graph & Evidence-Backed Attack-Path Intelligence
- **Problem:** Even with AppSec, CI/CD, OIDC, and IAM findings in one database, engineers still see four disconnected alert lists instead of understanding how a repository vulnerability, a privileged workflow, a broad OIDC trust policy, and an over-privileged IAM role combine into a single production risk.
- **Solution:**
  1. **PostgreSQL-Backed Context Graph (`packages/context-graph`):** Persist typed nodes (`Repository`, `ApplicationComponent`, `Dependency`, `Secret`, `Workflow`, `WorkflowJob`, `ThirdPartyAction`, `OidcTrustPolicy`, `CloudIdentityRole`, `CloudResourceTarget`, `Finding`) and typed edges (`TRIGGERS`, `MINTS_OIDC_TOKEN`, `ASSUMES_ROLE`, `GRANTS_PERMISSION`, `DEPLOYS`, `CONTAINS_VULNERABILITY`) in PostgreSQL — avoiding separate graph-DB operational overhead for self-hosted users.
  2. **Deterministic Multi-Hop Correlation:** Materialize evidence-backed `attack_paths` with per-hop provenance (`VERIFIED_STATIC`, `VERIFIED_RUNTIME`, `INFERRED`, `UNKNOWN`), source file/line evidence, explicit `unknownControls` caveats, and prioritized remediation recommendations (highlighting which single broken link neutralizes the entire chain).
  3. **Core Query APIs & UI:** Ship `/api/v1/attack-paths`, `/api/v1/graph`, and an interactive **Attack Paths** view in `apps/web` that directly answers:
     - Which repositories can indirectly obtain production cloud access?
     - Which deployment workflows hold permissions beyond their responsibilities?
     - Which cloud identities are reachable through CI/CD configuration?
     - Which vulnerabilities live in applications deployed by privileged workflows?

### Milestone 3 (`v0.5.0`): Application Reachability & Supply-Chain Provenance
- **Problem:** Two CVEs with identical CVSS scores carry vastly different real-world risk depending on whether the vulnerable dependency/function is actually imported and reachable via an exposed entrypoint or shipped by a privileged deployment workflow.
- **Solution:**
  1. Static import/entrypoint reachability heuristics (JS/TS, Python first) and internet-facing/service-exposure tagging mapped onto `ApplicationComponent` nodes in the Context Graph.
  2. CycloneDX/SPDX SBOM generation, SLSA build provenance checks, and OpenSSF Scorecard signal correlation.

### Milestone 4 (`v0.6.0`): Optional Read-Only Live Cloud & SCM Control Verification
- **Problem:** Static analysis must honestly report `UNKNOWN` for runtime guardrails such as GitHub branch protection, GitHub Environment required reviewers, AWS Service Control Policies (SCPs), Permission Boundaries, and out-of-repo IAM policy attachments.
- **Solution:**
  1. Introduce an **opt-in, least-privileged, read-only** verification connector running strictly in a segregated control-plane/connector boundary (never inside the no-egress `scanner-runner`).
  2. Upgrade graph edges from `VERIFIED_STATIC` / `UNKNOWN` to `VERIFIED_RUNTIME` with observation timestamps, starting with AWS IAM/STS + GitHub repository/environment protection metadata, then Azure and GCP.

### Milestone 5 (`v0.7.0` — Research): AI Agent & Non-Human Identity (NHI) Security
- **Problem:** AI coding assistants, autonomous agents, and MCP servers act as Non-Human Identities with delegated credentials and tool permissions across repositories, CI/CD, and cloud APIs — yet teams lack visibility into what these agents can access.
- **Solution:**
  1. Deterministic static analyzer for MCP server configurations (`.mcp.json`, Claude/Cursor/IDE/agent manifests), agent tool definitions, hardcoded API keys/tokens, and unrestricted shell/repo/cloud tool scopes aligned with **OWASP ASI** and **OWASP MCP Top 10**.
  2. Add `AiAgent`, `McpServer`, and `AgentTool` node types and `DELEGATES_CREDENTIAL` / `INVOKES_TOOL` / `ACCESSES_RESOURCE` edges to the existing Context Graph — enabling Indicative to answer *"Which AI agents have access to resources they do not need?"* using the exact same evidence and uncertainty model.

---

## 4. Acceptance Gates Before Advancing Milestones

No milestone is marked complete until:
1. All unit, integration, security, and regression tests pass (`npm test`).
2. Strict TypeScript typechecking and production builds pass (`npm run typecheck && npm run build`).
3. Every new rule, IAM classifier, or attack-path correlator has documented threat rationale, evidence format, false-positive/uncertainty disclosures, and both positive (vulnerable) and negative (hardened) regression fixtures.
4. Documentation (`README.md`, `CHANGELOG.md`, threat models, rule docs, ADRs) matches actual verified behavior ([ADR-013](../engineering/architecture-decisions.md)).
