# Indicative Project Governance

## Mission

Indicative is an Apache-2.0 licensed open-source application and cloud security intelligence platform. Core detection engines, canonical finding normalization, CI/CD & OIDC static analysis, reporting (JSON/SARIF/CSV), and self-hosted operation remain freely available as open source.

## Roles & Responsibilities

- **Contributors:** Anyone who submits pull requests, detection rules, regression fixtures, documentation improvements, or issue reports.
- **Maintainers:** Technical stewards with merge authority responsible for code review, security boundary preservation, release engineering, and community health.

## Decision-Making & Feature Proposals

1. **Minor changes** (bug fixes, rule precision improvements, docs, tests): Reviewed and approved via standard pull request.
2. **Major architectural or product changes** (new scanner categories, schema migrations, graph storage, cloud SDK integrations): Require a documented **Problem Statement & Architecture Decision Record (ADR)** in `docs/engineering/architecture-decisions.md` before implementation.
3. **Security-boundary changes** (auth, tenant isolation, sandbox runner, redaction, AI prompt fencing): Require threat-model review and explicit regression/security tests proving the control works.

## Release Policy

- Indicative follows Semantic Versioning (`MAJOR.MINOR.PATCH`).
- Every release updates `CHANGELOG.md` and passes the full automated test suite and regression precision/recall baseline.
- Security advisories follow [SECURITY.md](SECURITY.md).
