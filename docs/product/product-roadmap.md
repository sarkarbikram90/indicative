# Indicative — Strategic Product & Engineering Roadmap

**Last Updated:** 2026-11-23  
**Positioning:** *Indicative — Evidence-Driven Security Intelligence for Modern Software and Cloud Infrastructure.*

This roadmap reflects the verified baseline from [Current-State Assessment](../audits/current-state-assessment.md) and follows a strict **problem-first, milestone-driven** discipline. Every major phase ships a complete, tested vertical slice rather than speculative placeholders.

---

## Milestone Priority Overview

| Priority | Phase | Initiative | Status | Target Outcome |
|---|---|---|---|---|
| **P0** | Phase 0 | Source-code & security audit + audit remediation | **Active / Completing** | Verified assessment + security fixes (`EROFS` symlink order, UUID validation, prod CORS, `localFixturePath` confinement, `security_policies` enforcement) |
| **P0** | Phase 0 | Open-source project foundation | **Active / Completing** | `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `CHANGELOG.md`, `ROADMAP.md`, `SUPPORT.md`, `docs/community/`, issue/PR templates, CI workflow |
| **P1** | Phase 1 | Core engine reliability & contextual prioritization | **Active / Completing** | Trivy DB freshness checks, offline-capable KEV/EPSS intelligence enrichment with explicit provenance, transparent `VERIFIED`/`INFERRED`/`UNKNOWN` risk rationale |
| **P1** | Phase 2 | GitHub Actions CI/CD & OIDC Federation Security Analyzer | **Active / Completing** | `packages/cicd-security` integrated end-to-end (ScannerAdapter → Runner → Normalizer → API → Web Workflow Security View → CLI/SARIF/PR summary) with vulnerable/hardened corpus |
| **P2** | Phase 3 | Typed Security Context Graph & Attack-Path Intelligence | **Planned** | PostgreSQL-backed typed entities & edges (`Repo → Workflow → Token/Secret/OIDC → Cloud Trust Policy → Finding`) with explainable multi-hop risk chains |
| **P2** | Phase 3 | Supply-Chain Provenance & SBOM Integration | **Planned** | CycloneDX/SPDX SBOM generation (Syft/Trivy), SLSA provenance checks, OpenSSF Scorecard signal correlation |
| **P3** | Phase 4 | Cloud IAM & Workload Identity Intelligence (AWS → Azure/GCP) | **Planned** | Static AWS IAM/SCP/trust policy deep analysis correlated with repository workflows; optional read-only temporary-credential live assessment |
| **P4** | Phase 5 | AI Agent & MCP Configuration Security | **Research** | Threat-model-backed static analysis of MCP server manifests, agent tool scopes, hardcoded credentials, and unsafe delegation boundaries |
| **P4** | Phase 6 | Managed Multi-Tenant SaaS | **Deferred (Post-Validation)** | MicroVM/gVisor per-scan isolation, PostgreSQL RLS, Cloud KMS, scheduled scans, SSO, enterprise reporting (after practitioner validation) |

---

## Problem Statements for Active P1 Milestones

### Problem Statement 1: Unreliable Scanner Health & Context-Free Prioritization (Phase 1)
- **Who experiences it:** AppSec engineers, platform teams, and small engineering teams triaging SCA/SAST/IaC/secret alerts.
- **Frequency:** Every scan cycle.
- **Current workaround:** Manually cross-checking CVEs against CISA KEV / EPSS websites and manually checking whether offline Trivy databases are stale.
- **Impact:** Teams waste hours patching non-exploited CVEs while known-exploited vulnerabilities or stale offline DB gaps go unnoticed.
- **Indicative solution:**
  1. Inspect offline Trivy DB metadata (`UpdatedAt`) and surface staleness as a transparent `ScannerLimitation`.
  2. Support deterministic, offline-capable vulnerability intelligence enrichment (CISA KEV + EPSS snapshots / pluggable provider) that preserves source provenance and observation timestamps, never blocks scans on external API failure, and never treats missing intelligence as safety.
  3. Upgrade risk prioritization to explicitly separate **verified evidence**, **inferred context**, and **unknown context**, while preserving original scanner severity.

### Problem Statement 2: GitHub Actions & OIDC Cloud Trust Misconfigurations (Phase 2)
- **Who experiences it:** DevSecOps, platform engineering, and cloud security teams operating GitHub Actions pipelines connected to AWS, Azure, or GCP.
- **Frequency:** Continuous — introduced whenever developers add workflows, fork PR automation, third-party actions, or Terraform/IaC OIDC trust roles.
- **Current workaround:** Fragmented point tools (`actionlint` for syntax, `zizmor`/`poutine` for workflow lint, manual review of Terraform/IAM JSON trust policies). None of these link workflow OIDC token requests to overly broad cloud trust policies in the same repository or track remediation verification across scans.
- **Impact:** A single `pull_request_target` script injection or wildcard AWS IAM `sub: repo:org/*` OIDC trust policy grants external PR authors full production cloud compromise.
- **Indicative solution:**
  1. Build `@indicative/cicd-security` — a deterministic, line-accurate YAML analyzer for `.github/workflows/*.{yml,yaml}` and static IaC/JSON OIDC trust policies (AWS IAM, Azure Federated Identity Credentials, GCP Workload Identity Federation).
  2. Cover 6 high-signal rule families: **Permissions & Authorization**, **Unsafe Triggers**, **Expression Injection**, **Third-Party Action Pinning & Supply Chain**, **Secret Exposure**, **Build/Artifact Integrity**, plus **Static OIDC Trust Correlation**.
  3. Integrate seamlessly into Indicative's `ScannerAdapter` pipeline, canonical `CICD` category, SARIF/JSON/CSV/PR-summary reporters, policy enforcement engine (`info` / `warn` / `fail`), and a dedicated **Workflow Security** view in the Web UI.
  4. Validate against a realistic vulnerable + hardened GitHub Actions & OIDC corpus with measured precision, recall, and false-positive rate.

---

## Acceptance Gates Before Advancing Phases

No phase is marked complete until:
1. All unit, integration, security, and regression tests pass (`npm test`).
2. Strict TypeScript typechecking and production builds pass (`npm run typecheck && npm run build`).
3. New rules have documented threat rationale, evidence format, false-positive considerations, and both positive and negative fixture tests.
4. Documentation (`README.md`, `CHANGELOG.md`, threat model, rule docs) matches actual verified behavior.
