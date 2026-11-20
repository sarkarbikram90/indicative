# Indicative — MVP Scope & Acceptance Criteria

## 1. MVP objective

Build the smallest product that can connect to a GitHub repository, run real security scans, normalize findings, explain issues through AI (when configured), and provide evidence-backed remediation and verification workflows.

## 2. Capability inventory

| # | Capability | MVP requirement |
|---|------------|-----------------|
| 1 | GitHub repository integration | GitHub App installation and repository discovery |
| 2 | Repository security scanning | Manual scan initiation against an authorized repository |
| 3 | Static application security testing | Semgrep over JS/TS/Python with a pinned ruleset |
| 4 | Dependency vulnerability detection | Trivy filesystem scanning of manifests/lockfiles |
| 5 | Exposed secret detection | Gitleaks over current content and available Git history |
| 6 | Git history secret scanning | Full history where available; limitations reported explicitly |
| 7 | Finding normalization | Single canonical schema from all scanners |
| 8 | Finding deduplication | Deterministic, category-specific fingerprints (not title-only) |
| 9 | Evidence-backed severity/confidence | Original scanner severity preserved; normalized severity and confidence recorded |
| 10 | AI-assisted contextual analysis | Optional, sanitized-input, structured-output analysis |
| 11 | Security findings dashboard | Filters, lists, summaries, trends, recent activity |
| 12 | Scan history and comparison | New / recurring / no-longer-detected findings across scans |
| 13 | Remediation recommendations | Root cause, impact, recommended change, verification guidance |
| 14 | Scanner-based verification | Re-scan establishes presence in scanned scope |
| 15 | Exportable reports | JSON, SARIF (where mappable), CSV |

## 3. Explicitly out of scope

- Autonomous penetration testing, DAST, exploitation, arbitrary website scanning
- Cloud, Kubernetes, and runtime security posture management
- Automatic credential revocation/rotation, automatic code modification, autonomous PRs
- Multi-agent autonomous security systems
- Enterprise billing, subscription management, complex RBAC/administration
- Mobile applications

Future work may add these, but the scanner-adapter and findings-engine boundaries must make that possible without redesign.

## 4. Acceptance criteria (from Agent.md §23)

A criterion counts as complete only with evidence (tests, executed scans, or documented results).

1. **Repository integration** — A user authenticates and authorizes a GitHub repository through the GitHub App.
2. **Real scanning** — Semgrep, Trivy, and Gitleaks execute using real binaries or pinned container images.
3. **Full-history secret detection** — Gitleaks scans current content and available history; any limitation is reported.
4. **Normalized findings** — All three scanners' findings appear in one schema with provenance preserved.
5. **Secure secret handling** — No plaintext secret appears in frontend responses, application logs, the findings database, AI requests, or reports.
6. **Finding lifecycle** — Deduplication, history, and status transitions work across subsequent scans.
7. **AI contextual analysis** — When configured, AI explains selected findings using sanitized context; deterministic scanning still works with no provider configured.
8. **Evidence-backed reporting** — A user can see what was detected, by which tool, where, why it matters, supporting evidence, and the recommended action.
9. **Re-scanning and verification** — A later scan establishes whether a finding is still present in scanned scope.
10. **Security** — Authentication, authorization, tenant isolation, execution controls, sensitive-data handling, and audit logging are implemented.
11. **Automated tests** — Unit, integration, security, and end-to-end tests are provided.
12. **Reproducible local deployment** — A developer can follow the README and run the full development environment.

## 5. Definition of done for a feature

- Code is implemented behind a clear module boundary.
- Unit tests cover the core logic, including failure paths.
- Secrets and tokens never appear in logs, telemetry, AI requests, or persisted findings.
- Scanner failures are distinguishable from clean results.
- Relevant API endpoints are tenant-scoped and audited.
- Documentation reflects the actual implementation.

## 6. Non-goals and honesty constraints

- Do not claim a criterion is complete without evidence.
- Do not present mock scanner responses as successful real scanner execution.
- Do not describe a shallow, current-branch-only Gitleaks scan as a full-history scan.
- Do not claim production multi-tenant isolation solely because Docker containers are used.
- Clearly separate implemented functionality from planned functionality in all documentation.
