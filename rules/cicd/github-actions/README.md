# Indicative CI/CD Security Rules — GitHub Actions & OIDC (`indicative-cicd-gha-v1.0.0`)

Every rule in `@indicative/cicd-security` carries a stable identifier, version, CWE/OWASP CI/CD Top 10 mapping, documented false-positive considerations, explicit static-analysis limitations, and positive/negative regression fixtures.

## Rule Reference

| Rule ID | Category | Default Severity | CWE | OWASP CI/CD | Summary |
|---|---|---|---|---|---|
| `GHA-PERM-001` | Permissions | `MEDIUM` | CWE-250 | CICD-SEC-2 | Missing explicit top-level `permissions:` block |
| `GHA-PERM-002` | Permissions | `CRITICAL` | CWE-250 | CICD-SEC-2 | Unrestricted `permissions: write-all` |
| `GHA-PERM-003` | Permissions | `HIGH` | CWE-732 | CICD-SEC-2 | Sensitive write scopes granted broadly at root or on untrusted triggers |
| `GHA-PERM-004` | Permissions | `HIGH`/`CRITICAL` | CWE-269 | CICD-SEC-2 | Broad root-level or PR-triggered `id-token: write` OIDC token scope |
| `GHA-TRIG-001` | Triggers | `CRITICAL` | CWE-94 | CICD-SEC-4 | `pull_request_target` combined with checkout of untrusted PR head (pwn-request) |
| `GHA-TRIG-002` | Triggers | `HIGH` | CWE-829 | CICD-SEC-4 | Privileged `workflow_run` downloading potentially untrusted upstream artifacts |
| `GHA-INJ-001` | Injection | `HIGH`/`CRITICAL` | CWE-78 | CICD-SEC-4 | Untrusted GitHub context interpolated directly in `run:` or `actions/github-script` |
| `GHA-ACT-001` | Supply Chain | `MEDIUM`/`HIGH` | CWE-829 | CICD-SEC-8 | Third-party GitHub Action referenced by mutable tag/branch instead of 40-char commit SHA |
| `GHA-ACT-002` | Supply Chain | `HIGH` | CWE-829 | CICD-SEC-8 | External reusable workflow referenced by mutable tag/branch instead of commit SHA |
| `GHA-ACT-003` | Supply Chain | `MEDIUM` | CWE-522 | CICD-SEC-6 | `actions/checkout` persists `GITHUB_TOKEN` in `.git/config` on write/implicit/untrusted jobs |
| `GHA-SEC-001` | Secrets | `HIGH` | CWE-532 | CICD-SEC-6 | Secrets interpolated into shell output or forwarded via `secrets: inherit` to external reusable workflows |
| `GHA-SEC-002` | Secrets | `HIGH` | CWE-798 | CICD-SEC-6 | Long-lived static cloud credentials (`AWS_SECRET_ACCESS_KEY`, `AZURE_CREDENTIALS`, `GCP_SA_KEY`) instead of OIDC |
| `GHA-INT-001` | Build Integrity | `MEDIUM` | CWE-494 | CICD-SEC-9 | Unverified remote script piped directly to shell (`curl \| sh`) |
| `GHA-INT-002` | Build Integrity | `MEDIUM` | CWE-494 | CICD-SEC-3 | Floating `npm install` without lockfile integrity (`npm ci`) |
| `GHA-OIDC-001` | OIDC Federation | `CRITICAL` | CWE-285 | CICD-SEC-2 | Missing or wildcard GitHub OIDC `sub` restriction (`repo:org/*`, `repo:org/repo:*`) in AWS/Azure/GCP trust policy |
| `GHA-OIDC-002` | OIDC Federation | `HIGH` | CWE-345 | CICD-SEC-2 | Missing or wildcard OIDC `aud` validation in AWS/Azure trust policy |
| `GHA-OIDC-003` | OIDC Correlation | `CRITICAL` | CWE-269 | CICD-SEC-2 | Cross-file static correlation linking an OIDC-requesting workflow with a permissive cloud trust policy |

## Local CLI Usage

```bash
# Markdown PR summary (non-blocking warning mode by default)
npx tsx packages/cicd-security/src/cli.ts . --format markdown

# GitHub Actions annotations
npx tsx packages/cicd-security/src/cli.ts . --format annotations

# Fail CI explicitly on CRITICAL/HIGH findings
npx tsx packages/cicd-security/src/cli.ts . --format json --policy failure
```

## Contributing a New Rule

1. Define the rule metadata in `packages/cicd-security/src/rules/registry.ts` (stable `GHA-*` ID, CWE, OWASP mapping, false-positive notes, limitations).
2. Implement deterministic AST-based detection in `packages/cicd-security/src/rules/engine.ts`.
3. Add both a **positive (vulnerable)** and **negative (hardened)** fixture test in `packages/cicd-security/src/cicd.test.ts` and `tests/fixtures/`.
4. Verify zero regressions with `npm test`.
