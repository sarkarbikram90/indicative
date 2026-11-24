# Indicative — Competitive Landscape & Market Validation Plan

**Research Date:** 2026-11-23  
**Purpose:** Objective market analysis of application security, CI/CD supply-chain security, cloud IAM security, and AI/agent security ecosystems to ground Indicative's product positioning and roadmap without fabricating competitor weaknesses.

---

## 1. Strategic Market Thesis

The security tooling market is crowded with standalone vulnerability scanners and enterprise CNAPPs. Indicative **cannot** win by being "yet another wrapper around Semgrep/Trivy/Gitleaks" or an "AI security chatbot."

Real operational gaps observed across engineering and security teams:
1. **Fragmented findings with weak provenance and noisy triage:** Teams stitch together 4–6 open-source CLI tools (Semgrep, Trivy, Gitleaks, actionlint, zizmor, Checkov/Prowler) with incompatible outputs, no unified lifecycle/deduplication, and no trustworthy fix-verification semantics.
2. **The code-to-CI/CD-to-cloud blind spot:** Traditional AppSec tools scan source code and packages, while Cloud Security (CSPM/CIEM) tools scan live cloud accounts. The **bridge between them** — GitHub Actions workflows, `GITHUB_TOKEN` scopes, untrusted PR execution, third-party actions, and **OIDC federation trust policies** linking a GitHub repository directly to AWS/Azure/GCP IAM roles — frequently falls between AppSec and CloudSec teams.
3. **Opaque risk scores & hallucinated AI triage:** Many commercial tools emit unexplained 0–100 risk scores or let LLMs rewrite/suppress findings. Practitioners distrust black-box scores and want explicit separation between **verified evidence**, **inferred risk**, and **unknown context**.

---

## 2. Competitive Matrix

### 2.1 Application & Repository Security

| Product | Category | Primary Customer | Open Source? | Commercial Model | Core Strengths / Differentiators | Known Limitations / Gaps |
|---|---|---|---|---|---|---|
| **GitHub Advanced Security (GHAS)** | Native SCM AppSec (CodeQL, Secret Scanning, Dependabot) | GitHub Enterprise teams | Partial (CodeQL CLI/queries free for public repos; Dependabot OSS) | Paid per active committer on private repos | Deep native PR UX, CodeQL semantic dataflow, GitHub push-protection for secrets | Expensive per-seat pricing for private repos; tightly coupled to GitHub; limited cross-repo/cloud OIDC correlation |
| **GitLab Application Security** | Integrated DevSecOps | GitLab Ultimate teams | Open-core (basic scanners in CE; governance/dashboards in Ultimate) | Enterprise tier subscription | All-in-one SCM + CI + security policies | Locked to GitLab ecosystem; Ultimate tier cost barrier for startups |
| **Snyk** | Developer-first AppSec (SCA, SAST, Container, IaC) | Mid-market to enterprise dev teams | Proprietary (CLI open-source; engines & vuln DB proprietary) | Freemium + per-developer SaaS | Mature vulnerability DB, IDE/PR integration, automated upgrade PRs | Opaque enterprise pricing; acquired modules can feel uneven; high alert volume without tuning |
| **Semgrep** | SAST, Supply Chain & Secrets | AppSec & platform engineering teams | Open-core (Semgrep CE is LGPL-2.1; Pro cross-file engine & Managed Scans commercial) | Commercial per-contributor SaaS | Fast, developer-readable YAML rules; strong custom rule ecosystem | Cross-file taint & reachability require paid Pro tier; no native CI/CD-to-cloud OIDC graph |
| **Aikido Security** | Unified All-in-One AppSec + CSPM | Lean startups & mid-market teams (5–500 devs) | Proprietary SaaS (integrates & tunes OSS engines) | Flat/transparent tiered SaaS | Low-noise triage, rapid onboarding, broad coverage (SAST/SCA/Secrets/Cloud/DAST) | Closed-source proprietary platform; not self-hostable open-source for data-sovereign teams |
| **Endor Labs** | Software Supply Chain & Dependency Reachability | Large enterprises with complex dependency trees | Proprietary SaaS | Enterprise SaaS | Industry-leading function-level call-graph reachability for SCA; strong noise reduction | Enterprise-only pricing/complexity; narrower focus on dependencies rather than CI/CD identity paths |
| **Socket** | Behavioral Supply-Chain / Malware Detection | JS/Python/Go teams worried about malicious packages | Proprietary SaaS (free tier for OSS/individuals) | Freemium + per-seat SaaS | Detects zero-day malicious packages via install-time/behavioral signals before CVEs exist | Focused specifically on package behavior, not broader SAST/IaC/CI-CD/cloud identity intelligence |

### 2.2 CI/CD & GitHub Actions Security (Adjacent Open-Source Ecosystem)

| Project | Language | License | Core Strengths | Limitations / Complementary Fit with Indicative |
|---|---|---|---|---|
| **zizmor** | Rust | MIT | Fast, deep security static analyzer for GitHub Actions (template injection, `pull_request_target`, `GITHUB_TOKEN`, unpinned actions, SARIF output) | Standalone CLI; does not correlate workflows with IaC OIDC trust policies, repo secrets, SCA/SAST findings, or track remediation verification over time |
| **actionlint** | Go | MIT | Gold-standard GitHub Actions syntax/type linter with ShellCheck integration | Linter/correctness focus rather than security intelligence or cross-file trust-boundary correlation |
| **poutine** | Go | Apache-2.0 | High-precision CI/CD supply-chain scanner (artifact tampering, untrusted checkout exec, GitHub/GitLab pipelines) | CLI scanner; no persistent finding lifecycle, verification engine, or cloud IaC correlation |
| **OpenSSF Scorecard** | Go | Apache-2.0 | Automated repository supply-chain hygiene checks (branch protection, pinned deps, token permissions, SAST) | Repo-level posture score (0–10); does not provide line-level remediation workflows, secret history correlation, or cross-file OIDC analysis |

### 2.3 Cloud Security & IAM Analysis

| Product / Project | Category | Open Source? | Core Strengths | Known Limitations |
|---|---|---|---|---|
| **Prowler** | Open Cloud Security / CSPM / Compliance | Yes (Apache-2.0) + Prowler Cloud SaaS | Comprehensive multi-cloud checks (AWS, Azure, GCP, K8s, M365, GitHub), compliance frameworks, active community | Primarily assesses live cloud posture; limited source-code/CI-CD-workflow correlation |
| **ScoutSuite** | Multi-cloud auditing | Yes (GPL-2.0) | Historically clean HTML audit reports | Effectively unmaintained; users have migrated to Prowler or CNAPPs |
| **Cloudsplaining** | AWS IAM policy assessment | Yes (BSD-3) | Deep least-privilege analysis of AWS IAM JSON policies (privilege escalation, data exfiltration, resource exposure) | AWS-only standalone CLI; no CI/CD workflow correlation |
| **PMapper** | AWS IAM privilege-escalation graph | Yes (BSD-3) | Graph-based simulation of IAM principal-to-admin escalation paths | Niche CLI script; AWS-only; live account focus without source/CI-CD linkage |
| **AWS IAM Access Analyzer** | Cloud-native IAM validation | Managed AWS service | Authoritative policy validation, external access findings, unused access analysis | AWS-only; requires live AWS deployment |
| **Wiz / Orca / Prisma Cloud** | Enterprise CNAPP | Proprietary SaaS | Agentless cloud security graph, toxic-combination attack paths, runtime/exposure context | Enterprise SaaS budgets (\$50k–\$500k+/yr); cloud-down perspective often disconnects from self-hosted OSS developer workflows |

### 2.4 Software Supply Chain & AI/Agent Security

- **Supply Chain Standards:** **SLSA** (build provenance levels), **Sigstore** (keyless signing & transparency log), **OSV** (distributed open-source vulnerability schema), **CISA KEV** (authoritative known-exploited vulnerabilities), **FIRST EPSS** (exploit prediction scoring). Indicative should **consume and surface** these standards rather than reinvent them.
- **AI & Agent Security:** **OWASP Top 10 for Agentic Applications (ASI01–ASI10)** and **OWASP MCP Top 10 (MCP01–MCP10)** define emerging static and runtime threat models (token exposure, excessive MCP tool permissions, tool poisoning, indirect prompt injection, shadow MCP servers). The tooling market here is nascent — Indicative should ground any future Phase 5 capabilities strictly in verifiable static configuration analysis (e.g., MCP server configs, hardcoded tokens, unrestricted shell tool scopes) rather than making unsubstantiated runtime claims.

---

## 3. Where Indicative Differentiates (Defensible Wedge)

Indicative does **not** claim an uncontested market. Instead, it occupies a clear, practitioner-focused wedge:

1. **Apache-2.0, Self-Hostable, Data-Sovereign Intelligence Platform:** Full UI, API, PostgreSQL lifecycle, SARIF/JSON/CSV exports, and isolated offline scanning without per-seat SCM tax or sending customer source code to a third-party SaaS.
2. **Code + Secrets + CI/CD + Cloud OIDC Correlation in One Evidence Layer:** Unlike standalone CLIs (`zizmor`, `poutine`, `trivy`, `gitleaks`), Indicative normalizes SAST, SCA, IaC, Secrets, and **CI/CD + OIDC Federation** into a single canonical finding model with traceable provenance, workflow inventory, and cross-file correlation (e.g., matching a GitHub Actions workflow requesting `id-token: write` to an overly broad Terraform/CloudFormation/JSON AWS/Azure/GCP trust policy in the same repository).
3. **Radical Honesty in Verification & Prioritization:** Every priority decision cites concrete inputs (`VERIFIED` vs. `INFERRED` vs. `UNKNOWN`), scanner failures never look like clean scans, and secret removal never claims credential revocation.

---

## 4. Target Initial Customer Segments

| Segment | Job-to-Be-Done | Current Alternative | Buying / Adoption Path | Willingness to Pay (Future Managed Service) |
|---|---|---|---|---|
| **Startups (5–50 engineers, no dedicated AppSec)** | Meet customer security questionnaires (SOC 2 / ISO 27001), catch secrets & dangerous CI/CD workflows before production incidents | Ad-hoc GitHub Actions running Trivy/Gitleaks with ignored logs, or expensive GHAS seats | Bottom-up OSS Docker Compose adoption by CTO/staff engineer | \$200–\$800/mo flat workspace tier once team grows past self-hosting |
| **Platform / DevSecOps Teams (50–300 engineers)** | Standardize multi-repo scanning, enforce CI/CD & OIDC least privilege, verify fixes deterministically | Stitching OSS CLIs into custom scripts + spreadsheets or DefectDojo | Self-hosted Kubernetes/gVisor pilot → managed control plane | \$1k–\$3k/mo for multi-org policies, scheduled scans, SSO, audit retention |
| **Software Agencies & Security Consultants** | Run repeatable, evidence-backed baseline assessments across client repos with clean SARIF/JSON/CSV deliverables | Manual CLI runs + bespoke Word/PDF reports | Immediate local/Docker usage per engagement | \$300–\$1k/mo for multi-client isolated workspaces & white-label reports |

---

## 5. Customer Discovery & Validation Plan

Before building commercial SaaS billing or enterprise RBAC, validate practitioner demand via structured discovery interviews:

- **Target Cohort (30 interviews):**
  - 10 Application Security Engineers
  - 10 DevSecOps / Platform Engineers
  - 5 Cloud Security / IAM Engineers
  - 5 Security Consultants or Technical Founders
- **Interview Protocol (Problem-First — No Pitch in First 15 Minutes):**
  1. Walk me through the last security finding that actually caused an incident or an emergency sprint interrupt.
  2. Which scanner alerts does your team routinely ignore today, and why?
  3. How do you currently audit GitHub Actions workflows and cloud OIDC trust policies across repositories?
  4. When an engineer marks a finding "fixed," how do you prove it is actually gone (especially secrets and CI/CD misconfigurations)?
  5. What tools have you tried and abandoned in the last 12 months?
  6. What single workflow would save your team 5+ hours per week if solved reliably?
- **Design Partner Goal:** Recruit 3–5 organizations willing to run self-hosted Indicative against explicitly authorized repositories for 4 weeks, measuring:
  - Triage time per finding (before vs. after)
  - True-positive rate on real repositories (especially CI/CD & OIDC findings)
  - Number of findings verified resolved via re-scan
  - False-positive feedback turned directly into regression corpus fixtures.

---

## 6. References (Verified 2026-11-23)

- OWASP GitHub Actions Security Cheat Sheet & CI/CD Top 10: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- zizmor (Woodruff / GitHub Actions static security auditor): https://github.com/woodruffw/zizmor
- actionlint (rhysd): https://github.com/rhysd/actionlint
- poutine (BoostSecurity): https://github.com/boostsecurityio/poutine
- OpenSSF Scorecard: https://securityscorecards.dev/
- Prowler Open Cloud Security: https://github.com/prowler-cloud/prowler
- Cloudsplaining (Salesforce): https://github.com/salesforce/cloudsplaining
- PMapper (NCC Group): https://github.com/nccgroup/PMapper
- CISA Known Exploited Vulnerabilities (KEV) Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
- OWASP GenAI / Agentic AI Security Initiative & MCP Top 10: https://genai.owasp.org/
