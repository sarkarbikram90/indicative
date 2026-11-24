# Indicative Public Roadmap

For the full problem-first product strategy, competitive analysis, and acceptance criteria, see [docs/product/product-roadmap.md](docs/product/product-roadmap.md).

## Completed & Verified

- **v0.1.0 — Core Security Intelligence Platform:** Multi-engine deterministic scanning (Semgrep CE, Trivy, Gitleaks), tenant-keyed HKDF+HMAC secret protection, canonical finding lifecycle & honest verification, optional advisory AI Analyst, streaming JSON/SARIF/CSV exports, Docker Compose deployment.
- **v0.2.0 — Core Intelligence Hardening + GitHub Actions & OIDC Security:**
  - Verified technical/security audit & security hardening fixes
  - Trivy offline DB freshness checks & offline-capable CISA KEV / EPSS enrichment with explicit provenance
  - Transparent `[VERIFIED]` / `[INFERRED]` / `[UNKNOWN]` contextual risk prioritization
  - `@indicative/cicd-security` GitHub Actions & static AWS/Azure/GCP OIDC trust analyzer, standalone CLI, policy engine, `/api/v1/workflows`, and `/workflows` UI view
  - Full open-source governance, security disclosure, templates, and dogfooded CI workflow.

## Next Milestones (Prioritized)

1. **v0.3.0 — Typed Security Context Graph & Attack-Path Intelligence (PostgreSQL-backed):** Connect Repositories, Workflows, Actions, Secrets, Dependencies, OIDC Identities, Cloud Trust Policies, and Findings into explainable multi-hop risk chains.
2. **v0.4.0 — Software Supply-Chain Provenance & SBOM:** CycloneDX/SPDX SBOM generation, SLSA provenance verification, and OpenSSF Scorecard correlation.
3. **v0.5.0 — Cloud IAM & Workload Identity Intelligence:** Deep static AWS IAM policy/SCP/trust analysis correlated with CI/CD pipelines, followed by Azure/GCP and optional least-privileged read-only live cloud verification.
4. **v0.6.0 — AI Agent & MCP Configuration Security (Research):** Threat-model-backed static analysis of MCP server configurations, tool scopes, and credential exposure aligned with OWASP ASI & MCP Top 10.
