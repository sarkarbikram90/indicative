# Indicative Public Roadmap

For the full product vision, 3-pillar + Attack-Path Graph + AI Agent/NHI strategy, competitive analysis, and acceptance criteria, see [docs/product/product-strategy.md](docs/product/product-strategy.md), [docs/product/product-roadmap.md](docs/product/product-roadmap.md), and [docs/architecture/attack-path-and-identity-architecture.md](docs/architecture/attack-path-and-identity-architecture.md).

## Completed & Verified

- **v0.1.0 — Core Application Security Platform:** Multi-engine deterministic scanning (Semgrep CE, Trivy, Gitleaks), tenant-keyed HKDF+HMAC secret protection, canonical finding lifecycle & honest verification, optional advisory AI Analyst, streaming JSON/SARIF/CSV exports, Docker Compose deployment.
- **v0.2.0 — Contextual AppSec Intelligence, CI/CD & Static OIDC Security, and Developer Automation:**
  - Verified technical/security audit & security hardening fixes
  - Trivy offline DB freshness checks & offline-capable CISA KEV / EPSS enrichment with explicit provenance
  - Transparent `[VERIFIED]` / `[INFERRED]` / `[UNKNOWN]` contextual risk prioritization
  - `@indicative/cicd-security` GitHub Actions AST analyzer (16 versioned rules) & static AWS/Azure/GCP OIDC trust correlation, standalone CLI, policy engine, `/api/v1/workflows`, and `/workflows` UI view
  - GitHub App webhooks with replay protection, automated PR comments & Check Runs, reusable composite GitHub Action with SARIF 2.1.0 upload, scheduled scans, and encrypted Slack/Jira/GitHub Issue notifications
  - Full open-source governance, security disclosure, templates, and dogfooded CI workflow.

## Next Milestones (12-Month Prioritized Progression)

1. **v0.3.0 — Deeper CI/CD Coverage & Static Cloud Identity Risk (AWS IAM Policy Analysis):** Workflow-to-IAM-role linking (`role-to-assume`), static AWS IAM permissions/wildcard/privilege-escalation analysis (`packages/cloud-identity`), expanded CI/CD artifact/cache/runner rules, and optional pinned `zizmor` / `actionlint` adapter integration.
2. **v0.4.0 — Typed Security Context Graph & Evidence-Backed Attack-Path Intelligence (PostgreSQL-backed):** Connect Application Code/Secrets/Dependencies, GitHub Actions Workflows, OIDC Trust Policies, Cloud IAM Roles, and Production Targets into explainable multi-hop risk chains with per-hop provenance and explicit uncertainty disclosure.
3. **v0.5.0 — Application Reachability & Software Supply-Chain Provenance:** Code/dependency reachability & exposure signals, CycloneDX/SPDX SBOM generation, SLSA provenance verification, and OpenSSF Scorecard correlation.
4. **v0.6.0 — Optional Read-Only Live Cloud & SCM Control Verification:** Least-privileged, read-only verification of live AWS IAM/SCPs/Permission Boundaries and GitHub branch/environment protection gates (followed by Azure/GCP) to upgrade static `UNKNOWN` controls to `VERIFIED_RUNTIME`.
5. **v0.7.0 — AI Agent & Non-Human Identity (NHI) Security (Research):** Model AI coding assistants, autonomous agents, and MCP servers as Non-Human Identities on the shared Context Graph — starting with static analysis of MCP server configs, tool scopes, delegated credentials, and over-privileged access aligned with OWASP ASI & MCP Top 10.
