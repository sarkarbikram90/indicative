# Indicative — CI/CD Security Analyzer Threat Model

**Document Version:** 1.0  
**Last Updated:** 2026-11-23  
**Scope:** `packages/cicd-security` static workflow parser, OIDC federation analyzer, policy evaluator, and CI/CD reporters running inside Indicative's `scanner-runner` and API/UI pipeline.

---

## 1. Threat Assumptions

All `.github/workflows/*.{yml,yaml}`, Terraform (`.tf`), CloudFormation/IAM (`.json`, `.yaml`), Bicep, and repository configuration files are **untrusted, potentially adversarial inputs** controlled by external committers or pull-request authors.

---

## 2. Threat Matrix & Implemented Controls

| ID | Threat | Attack Vector | Implemented Mitigation | Verification Test |
|---|---|---|---|---|
| **CICD-T1** | **YAML Billion Laughs / Alias Expansion DoS** | Crafted workflow YAML with deeply nested anchors/aliases (`&a`, `*a`) exhausting memory/CPU during parsing. | Enforce `maxAliasCount: 32`, bounded file size (`MAX_WORKFLOW_FILE_BYTES = 512 KB`), bounded file count (`MAX_WORKFLOW_FILES = 500`), and safe YAML 1.2 core schema (no JS code/function tags). | `packages/cicd-security/src/cicd.test.ts` (alias bomb & oversized YAML tests) |
| **CICD-T2** | **ReDoS via Malicious Expressions or Shell Blocks** | Adversarial multi-kilobyte `run:` blocks or `${{ ... }}` expressions causing catastrophic regex backtracking. | Use bounded, linear-time regexes with no nested quantifiers; cap per-step script inspection length; reuse Indicative's linear-time `redactSecretsInText`. | `packages/cicd-security/src/cicd.test.ts` (adversarial long-line performance test) |
| **CICD-T3** | **Path Traversal & Symlink Escape during File Discovery** | Symlinks inside `.github/workflows/` pointing to `/etc/passwd` or outside workspace root. | Reuse `validateSafePathWithinRoot` and `lstat`-based walk that skips symlinks and rejects paths escaping `workspacePath`, plus pre-scan sanitization in worker/runner. | `packages/cicd-security/src/cicd.test.ts` + `tests/security/security-controls.test.ts` |
| **CICD-T4** | **Secret Leakage via Workflow Snippets** | Hardcoded credentials or tokens inside workflow YAML echoed verbatim into finding evidence, logs, or PR summaries. | Pass all extracted snippets, titles, descriptions, and remediation strings through `redactSecretsInText`, followed by `assertNoPlaintextSecretLeak` in the normalizer and export pipeline. | `packages/cicd-security/src/cicd.test.ts` + `tests/regression/corpus-benchmark.test.ts` |
| **CICD-T5** | **GitHub Actions Annotation Injection** | Malicious workflow filename or expression containing `\r`, `\n`, `%0A`, or `::set-output` / `::add-mask` breaking out of workflow commands. | Strictly escape `%`, `\r`, `\n`, `:`, `,` in GitHub Actions annotation formatter (`formatGitHubAnnotations`) per GitHub workflow command escaping specification. | `packages/cicd-security/src/cicd.test.ts` |
| **CICD-T6** | **False Assurance on Malformed Workflows** | Invalid YAML syntax silently skipped so broken or obfuscated workflows appear "clean." | Malformed workflow files emit an explicit `ScannerLimitation` (`WORKFLOW_YAML_PARSE_ERROR`) and mark the scanner run `PARTIAL` (never silent `SUCCESS` with zero limitations), triggering `VERIFICATION_INCONCLUSIVE` on missing prior findings. | `packages/cicd-security/src/cicd.test.ts` |
| **CICD-T7** | **Overclaiming Live Cloud Compromise from Static Config** | Claiming a workflow *has* AWS admin access solely because `id-token: write` or a `.tf` file exists. | Explicitly tag all OIDC findings with `evidenceBasis: "STATIC_CONFIG"` and state unknown runtime controls (live IAM role policies, permission boundaries, SCPs, GitHub branch/environment protection rules). | `packages/cicd-security/src/cicd.test.ts` |
| **CICD-T8** | **Unintended Pipeline Blocking** | Security analyzer unexpectedly failing developer builds by default. | Policy evaluator defaults to non-blocking `warn` / `info` mode; `fail` exit code is only triggered when explicitly configured by the user. | `packages/cicd-security/src/cicd.test.ts` |

---

## 3. Explicit Detection Scope & Known Limitations

1. **Static Analysis Only (No Live Cloud API Queries):** Static OIDC analysis inspects Terraform (`.tf`), CloudFormation/IAM JSON/YAML, Azure ARM/Bicep/Terraform, and GCP Terraform files present in the scanned repository. Trust policies defined in separate infrastructure repositories or modified manually in the cloud console are outside single-repository static scope.
2. **Composite & External Actions:** Static analysis inspects how workflows invoke third-party actions (pinning, inputs, permissions), but does not fetch external action source code from the internet (consistent with Indicative's zero-egress scanner invariant).
3. **Dynamic Shell Dataflow:** Expression injection detection identifies untrusted GitHub contexts interpolated directly into `run:` scripts and `actions/github-script` `script:` blocks, while recognizing safe `env:` indirection. Complex multi-step indirect dataflows across custom compiled binaries are out of scope for static YAML analysis.
4. **Repository-Level GitHub Settings:** Whether a repository's GitHub Settings default `GITHUB_TOKEN` to `read-only` or `read-write`, or whether GitHub Environments require manual reviewers, cannot be determined solely from repository files; findings explicitly note this unknown context.
