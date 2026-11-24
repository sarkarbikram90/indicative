# Indicative Community & Contributor Guide

## Project Mission

Build an open-source, evidence-driven application and cloud security intelligence platform that engineering teams genuinely trust — connecting code, dependencies, secrets, CI/CD workflows, and cloud workload identities with transparent prioritization and verifiable remediation.

## Design Principles

1. **Evidence Before Opinions:** Always preserve original scanner provenance, line numbers, and explicit limitations. Never invent reachability or runtime exposure.
2. **Honest Boundaries:** Clearly distinguish `STATIC_CONFIG`, `SCANNER_MATCH`, and `LIVE_VERIFIED` evidence, and never equate repository removal with credential revocation.
3. **Composable Modular Architecture:** Keep scanners, CI/CD analyzers, findings normalization, and AI advisory strictly decoupled via `@indicative/contracts`.
4. **Practitioner-First Ergonomics:** Every feature must be locally runnable and reproducible without requiring a complex cloud setup.

## Code Review Expectations

Pull requests are reviewed for:
- **Security invariants:** No plaintext secret persistence, no shell interpolation, strict tenant isolation, bounded parsing against DoS/ReDoS.
- **Detection quality:** Both true-positive (vulnerable) and true-negative (hardened) test fixtures proving low false-positive rates.
- **Backward compatibility:** Existing canonical finding schemas, API routes, and database migrations remain intact.

## Extension Contracts

- **Scanner Adapters:** Implement `ScannerAdapter` in `@indicative/contracts` (`packages/contracts/src/scanners.ts`).
- **CI/CD Rules:** Add versioned rules to `packages/cicd-security/src/rules/registry.ts` and evaluators in `packages/cicd-security/src/rules/engine.ts`.
- **Vulnerability Intelligence Providers:** Implement `VulnerabilityIntelligenceProvider` in `packages/findings/src/intelligence.ts`.
