# Contributing to Indicative

Thank you for your interest in contributing to **Indicative**! We welcome security researchers, AppSec/CloudSec engineers, DevSecOps practitioners, and full-stack developers.

## Engineering Principles

Every contribution must uphold Indicative's core invariants:
1. **Security first** — never weaken isolation, tenant scoping, CSRF, or secret redaction.
2. **Deterministic detection** — AI is strictly advisory and never invents or overrides scanner findings.
3. **Evidence over assertions** — every finding carries traceable provenance, explicit limitations, and honest verification state (`VERIFIED` vs. `INFERRED` vs. `UNKNOWN`).
4. **Failure transparency** — broken parsers, timed-out scanners, or stale offline databases must surface explicit limitations rather than silent clean scans.
5. **No placeholder features** — ship complete, tested vertical slices.

## Local Development Setup

Prerequisites: Node.js `>= 20.18 LTS`, npm, and optionally Semgrep, Trivy, Gitleaks, and Docker.

```bash
git clone https://github.com/sarkarbikram90/indicative.git
cd indicative
npm install
npm run build
npm run typecheck
npm test
```

Run the standalone CI/CD & OIDC analyzer locally against any repository:

```bash
npm run scan:cicd -- . --format markdown
```

## Ways to Contribute

### 1. New CI/CD or OIDC Detection Rules
- Define stable rule metadata (`GHA-*`, CWE, OWASP CI/CD Top 10, false-positive notes, static limitations) in `packages/cicd-security/src/rules/registry.ts`.
- Implement AST-based detection in `packages/cicd-security/src/rules/engine.ts` or `packages/cicd-security/src/oidc/oidcAnalyzer.ts`.
- Add both **positive (vulnerable)** and **negative (hardened)** fixtures under `tests/fixtures/` and regression tests in `packages/cicd-security/src/cicd.test.ts` and `tests/regression/cicd-corpus-benchmark.test.ts`.
- Update `rules/cicd/github-actions/README.md`.

### 2. New Scanner Adapters
Implement the `ScannerAdapter` contract from `@indicative/contracts` (`packages/contracts/src/scanners.ts`) and register it in `services/scanner-runner/src/adapters/registry.ts`. All adapters must:
- Never invoke shell interpolation (`shell: false`, explicit binary allowlist)
- Redact secrets before returning `RawScannerFinding[]`
- Report `FAILED` / `TIMEOUT` / `PARTIAL` / `UNAVAILABLE` accurately on error
- Include unit and malformed-output parser tests.

### 3. Security Regression Fixtures & Bug Reports
Real-world anonymized vulnerable and hardened fixtures that improve precision/recall are among the highest-value contributions to Indicative. **Never commit real credentials** — use clearly synthetic dummy secrets only.

## Pull Request Checklist

- [ ] `npm run build` passes cleanly
- [ ] `npm run typecheck` passes with zero errors
- [ ] `npm test` passes (unit, integration, security, regression, E2E)
- [ ] New rules/features include both positive and negative test cases
- [ ] Documentation (`README.md`, `CHANGELOG.md`, rule/architecture docs) updated accurately
- [ ] No real credentials, tokens, or unredacted secrets committed

## Code of Conduct

All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).
