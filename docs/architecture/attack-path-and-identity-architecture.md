# Indicative — Cross-Domain Attack-Path, Cloud Identity & NHI Architecture

**Document Version:** 1.0  
**Last Updated:** 2026-11-24  
**Status:** Architectural Specification (Builds on verified `v0.2.0-dev` foundation; target implementation `v0.3.0` – `v0.7.0`)

---

## 1. Architectural Thesis

Most security platforms isolate telemetry into disconnected silos: SAST/SCA/Secrets tools inspect application code, CI/CD linters inspect workflow YAML, and CSPM/CIEM tools inspect cloud accounts.

Indicative's unifying architecture connects all three security boundaries — **Application Code**, **Software Delivery Pipelines (CI/CD)**, and **Cloud Identities** — into a single **evidence-backed Typed Security Context Graph**, with a clean extension model for **AI Agents and Non-Human Identities (NHIs)**.

```text
+---------------------------------------------------------------------------------------------------+
|                        EVIDENCE-BACKED CROSS-DOMAIN RISK BOUNDARY                                 |
|                                                                                                   |
|  [1. Application Code] ──► [2. CI/CD Pipeline] ──► [3. Federation & Cloud IAM] ──► [4. Target]    |
|  • Vulnerable code/dep     • pull_request_target   • GitHub OIDC JWT (sub/aud)     • S3 / RDS     |
|  • Reachable entrypoint    • permissions:write-all • Broad IAM trust policy        • EKS / Prod   |
|  • Exposed secret          • Expression injection  • Over-privileged IAM role      • Secrets Mgr  |
|                            • Unpinned actions      • Escalation (PassRole/STS)     • Cross-Acct   |
|                                                                                                   |
|  [Future 4th Layer: AI Agents & MCP Servers as Non-Human Identities]                              |
|  • Agent / MCP Manifest ──► Tool Scope ──► Delegated Token/Secret ──► Repo / CI / Cloud Identity  |
+---------------------------------------------------------------------------------------------------+
```

### Core Trustworthiness Requirement
Not every combination of findings across these layers is exploitable together. A workflow declaring `id-token: write` is **not** automatically vulnerable; an outdated dependency that is never imported carries different practical risk than one reachable from a public endpoint.

Therefore, Indicative's architecture enforces two strict invariants:
1. **Every graph relationship must carry explicit evidence provenance** (file path, line range, extractor/scanner, and verification level).
2. **Every unverified control along a path must be disclosed explicitly as `UNKNOWN`** (never silently assumed exploitable or assumed safe).

---

## 2. Architecture Layers & Package Boundaries

Building on Indicative's existing modular monolith (`apps/*`, `services/scanner-runner`, `packages/*`), the cross-domain intelligence pipeline introduces two planned packages while preserving the air-gapped `scanner-runner` trust boundary:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ISOLATED SCANNER RUNNER (services/scanner-runner — NO egress, NO credentials)          │
│                                                                                        │
│  Pillar 1: AppSec Engines          Pillar 2: CI/CD Engines       Pillar 3: Static IAM  │
│  • Semgrep CE (SAST) [v0.1]        • @indicative/cicd-security   • @indicative/        │
│  • Trivy (SCA/IaC) [v0.1]            AST YAML + OIDC [v0.2]        cloud-identity      │
│  • Gitleaks (Secrets) [v0.1]       • Optional pinned zizmor /      (AWS IAM policies,  │
│  • Reachability extractor [v0.5]     actionlint adapters [v0.3]    escalation) [v0.3]  │
│                                                                                        │
│  Pillar 4 (Future): Static AI Agent / MCP Manifest Extractor [v0.7]                    │
└────────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ Redacted findings + typed entity/edge facts
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ CONTROL PLANE WORKER & INTELLIGENCE CORE (apps/worker + packages/*)                    │
│                                                                                        │
│  • packages/findings       — Normalization, KEV/EPSS, canonical fingerprints [v0.1-0.2]│
│  • packages/context-graph  — Entity resolution, edge builder, path scorer [v0.4]       │
│  • Optional Live Cloud/SCM Read-Only Verifier (segregated connector, opt-in) [v0.6]    │
└────────────────────────────────────────────┬───────────────────────────────────────────┘
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ POSTGRESQL 16 (packages/database)                                                      │
│  • Existing 23 tables (findings, occurrences, evidence, scans, workflows, etc.)        │
│  • Planned Graph Tables: security_entities, security_edges, attack_paths,              │
│    attack_path_steps (strictly tenant-scoped by organization_id)                       │
└────────────────────────────────────────────┬───────────────────────────────────────────┘
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ API & UI (apps/api + apps/web)                                                         │
│  • /api/v1/attack-paths, /api/v1/identities, /api/v1/graph                             │
│  • Interactive Attack-Path Explorer, Identity Exposure Matrix, Remediation Breakpoints │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Pillar-by-Pillar Technical Design

### 3.1 Pillar 1 — Application Security Intelligence (`v0.1.0`–`v0.5.0`)
- **Current verified baseline:** Semgrep CE (`1.186.0`), Trivy (`0.76.2`), Gitleaks (`8.30.1`), CISA KEV + FIRST EPSS enrichment, and category-specific deterministic fingerprinting.
- **Planned intelligence upgrades (`v0.5.0`):**
  - **Static Reachability Signals:** Map lockfile dependencies (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`) to actual source imports and call sites where deterministically resolvable (`REACHABLE_STATIC`, `IMPORTED_ONLY`, `NOT_IMPORTED`, `UNKNOWN`).
  - **Exposure & Service Context:** Detect HTTP route handlers, container `EXPOSE` / Kubernetes `Ingress` / Terraform load-balancer definitions, and map them to `ApplicationComponent` entities.
  - **Pipeline Coupling:** Link each `ApplicationComponent` to the CI/CD workflows that build, test, containerize, or deploy it.

### 3.2 Pillar 2 — CI/CD Security Intelligence (`v0.2.0`–`v0.3.0`)
- **Current verified baseline (`@indicative/cicd-security`):** Offline AST YAML 1.2 workflow parser, 16 versioned rules (`GHA-PERM-*`, `GHA-TRIG-*`, `GHA-INJ-*`, `GHA-ACT-*`, `GHA-SEC-*`, `GHA-INT-*`, `GHA-OIDC-*`), standalone CLI, reusable Action, and `/workflows` UI.
- **Planned hybrid engine strategy (`v0.3.0`):**
  - **Keep `@indicative/cicd-security` as the primary structural extractor:** Even if external linters run alongside it, Indicative's AST parser extracts the typed graph primitives (`Workflow`, `WorkflowJob`, triggers, effective token permissions, `environment:`, `secrets.*` references, `uses:` actions, and cloud auth action inputs like `role-to-assume`).
  - **Optional pinned `zizmor` and `actionlint` adapters:** Implemented via the standard `ScannerAdapter` contract inside `services/scanner-runner` (no egress, `shell: false`, binary allowlist, version-pinned) to expand deep GitHub Actions vulnerability coverage (template injection subtleties, cache poisoning, artifact poisoning, impostor commits, expression type checking) without duplicating maintenance.
  - **Cross-Engine Deduplication:** Canonical `CICD` fingerprinting keys on `(projectId, normalizedRuleFamily, filePath, workflowOrJobAnchor)` so overlapping detections from `@indicative/cicd-security` and `zizmor` merge into one finding with multi-engine corroborating evidence rather than duplicate noise.

### 3.3 Pillar 3 — Cloud Identity Risk (`v0.2.0`–`v0.6.0`)

Cloud identity analysis progresses in **three deliberate phases**:

#### Phase 3A — Static OIDC Federation Trust Analysis *(Verified in `v0.2.0-dev`)*
Implemented in `packages/cicd-security/src/oidc/oidcAnalyzer.ts`:
- Extracts static GitHub OIDC trust policies (`token.actions.githubusercontent.com`) from Terraform/IaC across AWS IAM, Azure FIC, and GCP WIF.
- Validates `sub` claim narrowness (repo + branch/tag/environment vs. wildcard `repo:org/*` or `repo:org/repo:*`) and `aud` validation.

#### Phase 3B — Static AWS IAM Policy & Blast-Radius Analysis *(Planned `v0.3.0`, `packages/cloud-identity`)*
Completes the missing authorization half of Cloud Identity Risk **without requiring live AWS credentials**:
1. **Workflow-to-Role Identity Extraction:**
   - Parse `aws-actions/configure-aws-credentials` (`role-to-assume`, `role-session-name`, `audience`), `azure/login` (`client-id`, `tenant-id`, `subscription-id`), and `google-github-actions/auth` (`workload_identity_provider`, `service_account`).
   - Resolve Terraform/CloudFormation role identifiers and ARN templates statically where defined in the repository (marking unresolved external ARNs explicitly as `EXTERNAL_UNRESOLVED`).
2. **Static IAM Policy Parser (Terraform HCL, CloudFormation YAML/JSON, Raw IAM JSON):**
   - Resolve `aws_iam_role` → `assume_role_policy` (trust), `inline_policy`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment` (AWS managed policies such as `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`, `AmazonS3FullAccess`), and `aws_iam_policy` / `aws_iam_policy_document`.
   - Respect explicit `Effect: "Deny"` statements and `Condition` blocks (never over-claiming unrestricted access when a `Condition` narrows scope — instead classify scope as `CONDITIONAL` and record the condition keys).
3. **Deterministic Capability & Privilege-Escalation Classification:**
   - **Admin / Full Wildcard:** `Action: "*"` + `Resource: "*"` or managed `AdministratorAccess`.
   - **Service Wildcard:** e.g., `s3:*`, `iam:*`, `ec2:*`, `secretsmanager:*` on `Resource: "*"`.
   - **Sensitive Data / Secret Access:** `s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, `rds:*`.
   - **Privilege Escalation Primitives (deterministic catalog):** `iam:PassRole` (+ compute/lambda/ecs/ec2 creation), `iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` to higher-privilege roles.
   - **Permission Boundaries:** Detect whether `permissions_boundary` is attached on the role resource; if absent in IaC, note that an account-level SCP may still apply (`UNKNOWN` statically).

#### Phase 3C — Optional Read-Only Live Cloud & SCM Verification *(Planned `v0.6.0`)*
- Strictly opt-in, configured with dedicated **read-only**, short-lived credentials (e.g., AWS `AssumeRole` with narrow read-only `iam:Get*`/`iam:List*`/`organizations:ListPoliciesForTarget`, and GitHub read-only metadata API for branch protection & environment required reviewers).
- Runs in a **segregated control-plane verification worker**, NEVER inside the no-egress `scanner-runner` that processes untrusted repository code.
- Upgrades static graph edges and `unknownControls` from `UNKNOWN` to `VERIFIED_RUNTIME` with exact observation timestamps.

---

## 4. Typed Security Context Graph (`packages/context-graph`, Planned `v0.4.0`)

### 4.1 Storage Strategy: PostgreSQL 16 (No Separate Graph DB)
For self-hosted and mid-sized deployments, introducing Neo4j or a dedicated graph database adds heavy operational overhead, backup complexity, and tenant-isolation risk. Indicative's per-organization graph has hundreds to tens of thousands of nodes and bounded attack-path depth (typically 2–6 hops) — ideal for **PostgreSQL 16 with Drizzle ORM and recursive CTEs (`WITH RECURSIVE`)**, strictly partitioned by `organization_id`.

### 4.2 Typed Entity Model (`security_entities`)

| Entity Type | Domain | Examples / Key Attributes |
|---|---|---|
| `REPOSITORY` | AppSec / SCM | `org/repo`, default branch, visibility |
| `APPLICATION_COMPONENT` | AppSec | Service/module path, runtime language, exposed routes/ports |
| `DEPENDENCY` | AppSec | Package name, ecosystem, version, reachability state, KEV/EPSS |
| `SECRET_IDENTITY` | AppSec / Identity | Tenant-keyed `HMAC-SHA256` fingerprint, secret type, working-tree vs. git-history |
| `WORKFLOW` | CI/CD | `.github/workflows/deploy.yml`, triggers, root permissions |
| `WORKFLOW_JOB` | CI/CD | Job ID, `runs-on`, job permissions, `environment:`, `id-token: write` |
| `THIRD_PARTY_ACTION` | CI/CD | `owner/action@ref`, SHA-pinned boolean |
| `OIDC_TRUST_POLICY` | Cloud Identity | Provider (`AWS`/`AZURE`/`GCP`), issuer, `sub` patterns, `aud` patterns, scope classification |
| `CLOUD_IAM_ROLE` | Cloud Identity | Role name/ARN, provider, trust policy ref, effective capability tier, escalation flags |
| `CLOUD_RESOURCE_TARGET` | Cloud Infra | Target service/resource pattern (`arn:aws:s3:::*`, `secretsmanager:*`, `prod-eks`) |
| `AI_AGENT` *(Future `v0.7.0`)* | AI / NHI | Agent/config name, manifest file path, execution mode |
| `MCP_SERVER` *(Future `v0.7.0`)* | AI / NHI | Server name, transport (`stdio`/`http`), declared tools, credential bindings |
| `FINDING` | Canonical | Reference to existing `findings.id` |

### 4.3 Typed Edge Model (`security_edges`)

Every edge stores:
- `organization_id`, `scan_id`, `source_entity_id`, `target_entity_id`, `edge_type`
- `evidence_basis`: `VERIFIED_STATIC` | `VERIFIED_RUNTIME` | `INFERRED` | `UNKNOWN`
- `confidence`: `HIGH` | `MEDIUM` | `LOW`
- `source_location`: `{ filePath, lineStart, lineEnd, extractor, ruleId? }`
- `conditions`: JSON summary of constraints (e.g., branch filters, IAM `Condition` keys)
- `unknown_controls`: array of explicit caveats (e.g., `["GITHUB_BRANCH_PROTECTION_UNKNOWN", "AWS_SCP_UNKNOWN"]`)

Core edge types:
- **App → CI/CD:** `CONTAINS_WORKFLOW`, `DEPLOYS_COMPONENT`, `HAS_FINDING`, `EXPOSES_SECRET`
- **CI/CD Internal:** `HAS_JOB`, `USES_ACTION`, `TRIGGERED_BY_UNTRUSTED_INPUT`, `CONSUMES_SECRET`, `MINTS_OIDC_TOKEN`
- **CI/CD → Cloud Identity:** `TARGETS_CLOUD_ROLE`, `SATISFIES_OIDC_TRUST`
- **Cloud Identity → Cloud Infra:** `ATTACHES_POLICY`, `CAN_ESCALATE_TO`, `ASSUMES_ROLE`, `CAN_ACCESS_RESOURCE`
- **AI Agent / NHI *(Future `v0.7.0`)*:** `CONFIGURES_MCP_SERVER`, `EXPOSES_TOOL`, `DELEGATES_CREDENTIAL`, `CAN_TRIGGER_WORKFLOW`, `CAN_ACCESS_RESOURCE`

---

## 5. Evidence-Backed Attack-Path Correlation & Honesty Model

### 5.1 Example Correlated Chain (Enterprise E-Commerce Scenario)

Instead of emitting four disconnected alerts, `packages/context-graph` materializes one inspectable `AttackPath` record linked to its underlying canonical findings:

| Hop | Entity / Transition | Evidence (`source_location`) | Evidence Basis | Unknown Controls Disclosed |
|---|---|---|---|---|
| **1** | External PR / Untrusted Input → `deploy.yml` (`pull_request_target` + expression injection + `write-all`) | `.github/workflows/deploy.yml:3-18` (`GHA-TRIG-001`, `GHA-INJ-001`, `GHA-PERM-002`) | `VERIFIED_STATIC` | GitHub fork-PR workflow approval settings (`require_approval_for_fork_pr`) |
| **2** | `deploy.yml` job → Requests GitHub OIDC JWT (`id-token: write` + `configure-aws-credentials`) | `.github/workflows/deploy.yml:10-24` (`GHA-PERM-004`) | `VERIFIED_STATIC` | GitHub `environment:` required reviewers (if environment declared) |
| **3** | OIDC JWT → AWS IAM Trust Policy (`sub: repo:acme/*` matches workflow repository/branch) | `infra/iam.tf:12-34` (`GHA-OIDC-001`, `GHA-OIDC-003`) | `VERIFIED_STATIC` | Live AWS IAM trust policy drift vs. Terraform state |
| **4** | Assumed AWS IAM Role (`acme-deploy-role`) → `s3:*` on `Resource: "*"` | `infra/iam.tf:40-58` (`IAM-PERM-001`) | `VERIFIED_STATIC` | Account-level AWS SCPs and runtime Permission Boundaries |

### 5.2 Honest Path Confidence & Remediation Breakpoints
- **Path Status:** An attack path's overall confidence is bounded by its weakest hop (`min(hop.evidence_basis)`), and any `UNKNOWN` control is surfaced directly in the API response and UI banner — never hidden inside an opaque numerical score.
- **Remediation Breakpoints:** Because attack paths are chains, Indicative highlights **minimum-effort breakpoints** (e.g., removing `pull_request_target` checkout, tightening the OIDC `sub` claim to a single protected `environment:production`, and scoping `s3:*` to the specific deployment bucket ARN) so engineers can neutralize maximum risk with the smallest safe change.

### 5.3 Answering the Five Strategic Queries
The graph schema directly powers structured API queries under `/api/v1/graph` and `/api/v1/attack-paths`:

| Strategic Question | Graph Traversal Pattern |
|---|---|
| *"Which repositories can indirectly obtain production cloud access?"* | `REPOSITORY → WORKFLOW → WORKFLOW_JOB (MINTS_OIDC_TOKEN) → OIDC_TRUST_POLICY → CLOUD_IAM_ROLE → CLOUD_RESOURCE_TARGET (prod/wildcard)` |
| *"Which deployment workflows have permissions beyond their intended responsibilities?"* | `WORKFLOW / WORKFLOW_JOB` with `write-all` / broad write scopes or linked `CLOUD_IAM_ROLE` with Admin / Escalation capabilities |
| *"Which cloud identities are reachable through our CI/CD configuration?"* | All `CLOUD_IAM_ROLE` nodes with inbound `TARGETS_CLOUD_ROLE` or `SATISFIES_OIDC_TRUST` edges (including wildcard cross-repo trust matches) |
| *"Which vulnerabilities exist in applications deployed by privileged workflows?"* | `FINDING (SAST/SCA/SECRET)` on `APPLICATION_COMPONENT` ← `DEPLOYS_COMPONENT` ← `WORKFLOW` → `CLOUD_IAM_ROLE` |
| *"Which AI agents have access to resources they do not need?"* *(v0.7.0)* | `AI_AGENT → MCP_SERVER → DELEGATES_CREDENTIAL / EXPOSES_TOOL → REPOSITORY / WORKFLOW / CLOUD_IAM_ROLE` |

---

## 6. Future Extension: AI Agent & Non-Human Identity (NHI) Security (`v0.7.0`)

AI coding assistants, autonomous agents, and MCP servers fit cleanly into Indicative's existing architecture without inventing a parallel product because they are **Non-Human Identities operating over the same repositories, pipelines, and cloud roles**.

### Planned Initial Scope (Deterministic & Static-First)
Grounded in **OWASP Top 10 for Agentic Applications (ASI)** and **OWASP MCP Top 10**:
1. **Manifest & Config Discovery:** Parse repository-committed MCP and agent configuration files (e.g., `.mcp.json`, `.cursor/mcp.json`, Claude/agent YAML/JSON manifests, tool registries).
2. **Static Risk Rules:**
   - Hardcoded secrets/API tokens in MCP server `env` blocks or headers (reusing `packages/security` HKDF+HMAC redaction).
   - Unpinned remote/NPX/UVX MCP server packages (`npx -y @org/server` without pinned versions/hashes — parallel to `GHA-ACT-001`).
   - Over-privileged tool scopes (unrestricted shell execution, write access to production repos/clusters, broad cloud credentials passed into agent environment).
   - Cross-boundary credential delegation (an agent config holding tokens that can trigger CI/CD workflows or assume cloud IAM roles).
3. **Graph Integration:** Emit `AI_AGENT` and `MCP_SERVER` entities and edges into `security_entities` / `security_edges` with explicit `STATIC_CONFIG` evidence basis — explicitly noting that runtime prompt-injection behavior or dynamic OAuth consent scopes cannot be verified statically.

---

## 7. Security Boundaries for New Capabilities

1. **Untrusted Repository Content Stays Air-Gapped:** All static AppSec, CI/CD, `zizmor`/`actionlint`, static IAM policy, and static MCP manifest parsing executes inside `services/scanner-runner` with zero network egress, read-only rootfs, non-root UID `10001`, and zero cloud/GitHub credentials.
2. **Future Live Cloud Verification Is Strictly Isolated:** When `v0.6.0` introduces optional read-only live cloud/SCM verification, it executes in a separate control-plane connector with explicit per-organization opt-in, least-privileged read-only roles, strict SSRF/endpoint allowlists, and full `audit_events` logging — never sharing a container or network with `scanner-runner`.
3. **Multi-Tenant Isolation:** Every graph table (`security_entities`, `security_edges`, `attack_paths`) enforces mandatory `organization_id` scoping on all queries and foreign keys, matching existing `findings` tenant isolation guarantees.
4. **Secret Safety Across Graph Metadata:** Graph node attributes and edge snippets pass through `packages/security` redaction before persistence; `SECRET_IDENTITY` nodes store only tenant-keyed `HMAC-SHA256` fingerprints and masked previews.
