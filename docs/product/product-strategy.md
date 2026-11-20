# Indicative — Product Strategy

## 1. Product Vision

**Indicative** is an AI-powered repository security intelligence and engineering platform designed to help developers and small engineering teams identify security vulnerabilities and exposed secrets in their GitHub repositories, understand real-world implications, prioritize remediation, and verify fixes through repeatable deterministic scans.

> **Positioning:** Indicative transforms fragmented security findings into prioritized, evidence-backed remediation workflows.

**Core Philosophy:** `Detect → Understand → Prioritize → Recommend → Verify`

## 2. The Problem

Modern repositories routinely accumulate three overlapping classes of risk:

1. **Application code vulnerabilities (SAST):** Injection flaws, unsafe deserialization, weak cryptography, and broken authentication patterns.
2. **Third-party supply-chain and configuration flaws (SCA & IaC):** Known CVEs in transitive and direct dependencies, plus insecure Docker, Kubernetes, and Terraform configurations.
3. **Exposed secrets in code and Git history:** Credentials, API keys, and private keys committed in current files or lingering in historical commits even after deletion.

Developers without a dedicated AppSec team face fragmented scanner outputs, noisy severity labels detached from context, unredacted secret leaks in ad-hoc tooling, and no structured way to verify whether a remediation actually removed the risk within scanned scope.

## 3. Target Customers & Primary Persona

### Initial Target Segments
- Individual software developers
- Independent software consultants
- Early-stage startups
- Small engineering teams and software agencies
- Small DevSecOps teams

### Primary Persona
A developer or engineering lead maintaining one or more GitHub repositories without a dedicated AppSec specialist. They need:
- Reliable, deterministic vulnerability and secret detection with traceable scanner provenance.
- Clear explanation of why a finding matters and how to fix it safely.
- Confidence that sensitive credentials will never leak into logs, UIs, reports, or LLM prompts.
- Repeatable scan-over-scan verification showing what remains detected, what is no longer detected, and what was newly introduced.

## 4. Strategic Principles

1. **Accuracy and transparency over aggressive automation:** Fewer reliable, evidence-backed findings beat noisy alert floods.
2. **Deterministic scanners as the source of truth:** Semgrep, Trivy, and Gitleaks produce authoritative findings. AI explains, prioritizes contextually, and recommends remediation—it never invents vulnerabilities or overrides scanner evidence.
3. **Strict secret safety:** Plaintext credentials are never stored in findings, shown in normal UI responses, written to logs, sent to LLMs, or included in exported reports.
4. **Honest verification semantics:** Removal of a secret from a Git repository does not establish that the credential was revoked; credential validity is explicitly reported as `UNKNOWN` / `NOT_VERIFIED`.
5. **Extensible scanner and intelligence core:** The modular `ScannerAdapter` and canonical `SecurityFinding` contracts support future engines (e.g., Strix, additional SAST/SCA/DAST/CSPM tools) without rewriting the findings pipeline.

## 5. Brand & Naming Note

"Indicative" is used as a working product brand name for this MVP. Trademark and domain availability have not been verified.
