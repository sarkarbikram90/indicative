# Security Policy

## Supported Versions

Indicative is an active open-source security intelligence platform. Security patches are applied to the latest minor release on `main`.

| Version | Supported |
|---|---|
| `0.2.x` (`main`) | ✅ Supported |
| `0.1.x` | ⚠️ Security fixes only; upgrade recommended |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities in public GitHub issues, pull requests, or discussions.**

If you discover a security vulnerability in Indicative (such as tenant isolation bypass, secret redaction bypass, scanner sandbox escape, OAuth/CSRF flaw, YAML parser DoS, or prompt-injection bypass):

1. Use **GitHub Private Vulnerability Reporting** (`Security` → `Advisories` → `Report a vulnerability`) on the repository, or contact the maintainers privately.
2. Include:
   - Affected component/package and version or commit SHA
   - Clear reproduction steps or minimal proof-of-concept fixture
   - Expected vs. actual security boundary behavior
   - Impact assessment (e.g., cross-tenant data access, secret leakage, RCE)

### Response Targets

- **Acknowledgement:** within 72 hours
- **Initial triage & severity assessment:** within 7 days
- **Coordinated remediation & disclosure:** target 30–90 days depending on severity and complexity

## Security Architecture Boundaries

Indicative's threat models are maintained publicly and updated alongside code:
- [Core Platform Security Threat Model](docs/architecture/security-threat-model.md)
- [CI/CD & OIDC Security Analyzer Threat Model](docs/architecture/ci-cd-security-threat-model.md)
- [Production-Readiness Assessment](docs/engineering/production-readiness.md)

**Important deployment note:** Standard Docker containers share the host kernel and are intended for local development and single-tenant evaluation only. Multi-tenant production deployments scanning untrusted repositories require hardened microVM or user-space kernel isolation (gVisor `runsc`, Kata Containers, or AWS Firecracker) and PostgreSQL Row-Level Security (RLS).
