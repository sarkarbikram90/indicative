import type { CicdRuleDefinition } from "../types.js";

export const CICD_RULE_CATALOG: Record<string, CicdRuleDefinition> = {
  "GHA-PERM-001": {
    ruleId: "GHA-PERM-001",
    version: "1.0.0",
    category: "PERMISSIONS",
    title: "Workflow missing explicit top-level GITHUB_TOKEN permissions",
    defaultSeverity: "MEDIUM",
    defaultConfidence: "HIGH",
    cwe: "CWE-250",
    owaspCicd: "CICD-SEC-2",
    summary:
      "The workflow does not declare an explicit top-level `permissions:` block and therefore inherits repository or organization default GITHUB_TOKEN permissions.",
    impact:
      "If repository defaults are set to read-write (legacy default on older repositories), every job and third-party action in this workflow receives broad write access to repository contents, packages, and releases.",
    remediation:
      "Declare `permissions: {}` or `permissions: { contents: read }` at the workflow root, then grant minimal write scopes only to the specific jobs that require them.",
    falsePositiveNotes:
      "If repository or organization GitHub settings already enforce restricted read-only default GITHUB_TOKEN permissions, runtime exposure is reduced, though explicit least-privilege declarations remain best practice and protect against setting drift.",
    limitations:
      "Static analysis cannot inspect repository-level GitHub Settings (`default_workflow_permissions`).",
    references: [
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
      "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management"
    ]
  },

  "GHA-PERM-002": {
    ruleId: "GHA-PERM-002",
    version: "1.0.0",
    category: "PERMISSIONS",
    title: "Workflow or job grants unrestricted write-all GITHUB_TOKEN permissions",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-250",
    owaspCicd: "CICD-SEC-2",
    summary:
      "`permissions: write-all` grants write access across every available GITHUB_TOKEN scope (contents, packages, id-token, actions, security-events, pull-requests, issues, deployments).",
    impact:
      "Any compromised build step, dependency install script, or third-party action can push malicious commits, mint OIDC cloud tokens, publish poisoned packages, or alter security alerts.",
    remediation:
      "Replace `permissions: write-all` with explicit least-privilege scopes (for example `contents: read` at the root and targeted job-level scopes only where needed).",
    falsePositiveNotes: "Rarely false positive; `write-all` is almost never justified in production workflows.",
    limitations: "Static analysis reports the declared token scope; effective scopes also depend on fork PR token restrictions for standard `pull_request` triggers.",
    references: [
      "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token"
    ]
  },

  "GHA-PERM-003": {
    ruleId: "GHA-PERM-003",
    version: "1.0.0",
    category: "PERMISSIONS",
    title: "Excessive write permissions granted broadly or on untrusted trigger",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-732",
    owaspCicd: "CICD-SEC-2",
    summary:
      "High-impact write scopes (`contents: write`, `packages: write`, `actions: write`, `security-events: write`, `deployments: write`) are declared at the workflow root across multiple jobs or paired with untrusted PR triggers.",
    impact:
      "Over-scoped write permissions widen the blast radius of compromised dependencies, test runners, or pull-request workflows.",
    remediation:
      "Set top-level `permissions: { contents: read }` and move write scopes strictly to the minimal single release/deployment job.",
    falsePositiveNotes:
      "Single-job release workflows triggered solely by protected tag pushes or manual `workflow_dispatch` with an explicit release purpose may legitimately need `contents: write`.",
    limitations: "Cannot verify GitHub branch/tag protection rules statically.",
    references: [
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"
    ]
  },

  "GHA-PERM-004": {
    ruleId: "GHA-PERM-004",
    version: "1.0.0",
    category: "PERMISSIONS",
    title: "Overly broad or untrusted-trigger id-token: write OIDC permission",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-269",
    owaspCicd: "CICD-SEC-2",
    summary:
      "`id-token: write` allows requesting signed GitHub OIDC JWTs to exchange for cloud credentials. Granting it at workflow root across all jobs or on untrusted PR triggers increases cloud credential exposure.",
    impact:
      "If any build/test step or untrusted PR job can mint an OIDC token and the target cloud trust policy does not strictly constrain `sub` (branch/environment), attackers may assume cloud IAM roles.",
    remediation:
      "Scope `id-token: write` exclusively to the specific deployment job protected by a GitHub `environment:`, and restrict triggers to protected branches or manual approvals.",
    falsePositiveNotes:
      "`id-token: write` is a legitimate mechanism for keyless cloud authentication when scoped strictly to a dedicated deployment job with environment-bound cloud trust policies.",
    limitations:
      "Actual cloud compromise depends on external cloud IAM trust policy conditions and GitHub environment approval gates.",
    references: [
      "https://docs.github.com/en/actions/concepts/security/openid-connect"
    ]
  },

  "GHA-TRIG-001": {
    ruleId: "GHA-TRIG-001",
    version: "1.0.0",
    category: "TRIGGERS",
    title: "Dangerous pull_request_target checkout of untrusted pull request head",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-94",
    owaspCicd: "CICD-SEC-4",
    summary:
      "A workflow triggered by `pull_request_target` runs in the privileged context of the base repository (with access to secrets and write tokens) while explicitly checking out untrusted pull-request head code (`github.event.pull_request.head.sha` / `head.ref`).",
    impact:
      "Any external fork contributor can submit a PR that modifies build scripts, package manifests, or tests to execute arbitrary code inside the privileged runner, exfiltrating repository secrets and write tokens (pwn-request).",
    remediation:
      "Use standard `pull_request` for building/testing untrusted PR code. If `pull_request_target` is strictly required for metadata labeling, never check out `pull_request.head.*` or execute any PR-controlled files.",
    falsePositiveNotes:
      "Safe `pull_request_target` workflows that only inspect PR metadata without checking out PR head code are NOT flagged by this rule.",
    limitations:
      "Detects explicit `actions/checkout` ref overrides and `git checkout`/`gh pr checkout` patterns referencing PR head.",
    references: [
      "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
    ]
  },

  "GHA-TRIG-002": {
    ruleId: "GHA-TRIG-002",
    version: "1.0.0",
    category: "TRIGGERS",
    title: "Privileged workflow_run executes or consumes untrusted upstream PR artifacts",
    defaultSeverity: "HIGH",
    defaultConfidence: "MEDIUM",
    cwe: "CWE-829",
    owaspCicd: "CICD-SEC-4",
    summary:
      "A `workflow_run` workflow executes with base-repository privileges and downloads artifacts or checks out code from an upstream workflow without verifiable integrity isolation.",
    impact:
      "If the upstream workflow ran on an untrusted fork PR, downloaded artifacts (scripts, binaries, JSON/text interpolated into shell) can achieve code execution or privilege escalation in the privileged `workflow_run` context.",
    remediation:
      "Validate and treat downloaded artifacts strictly as untrusted data (never execute scripts or `eval` files from artifacts), verify `github.event.workflow_run.head_repository.full_name == github.repository`, and minimize `GITHUB_TOKEN` scopes.",
    falsePositiveNotes:
      "Safe when the downloaded artifact is strictly validated non-executable data (e.g., numeric coverage score) or the upstream workflow only triggers on trusted protected branches.",
    limitations: "Static analysis cannot confirm the trigger conditions of every upstream workflow if defined externally.",
    references: [
      "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
    ]
  },

  "GHA-INJ-001": {
    ruleId: "GHA-INJ-001",
    version: "1.0.0",
    category: "EXPRESSION_INJECTION",
    title: "Untrusted GitHub event context interpolated directly in script execution",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-78",
    owaspCicd: "CICD-SEC-4",
    summary:
      "Attacker-controlled GitHub context expressions (such as `github.event.pull_request.title`, `issue.body`, `comment.body`, `head_ref`, or `commits.*.message`) are interpolated directly into a `run:` shell block or `actions/github-script` script.",
    impact:
      "GitHub expands `${{ ... }}` expressions BEFORE passing the script to the shell or JavaScript interpreter. An attacker can craft a PR title, branch name, or issue comment containing shell metacharacters (`$(...)`, `` `...` ``, `;`, `\"`) to achieve arbitrary command execution in the runner.",
    remediation:
      "Pass untrusted values through an intermediate `env:` mapping (e.g., `env: { PR_TITLE: ${{ github.event.pull_request.title }} }`) and reference the quoted environment variable (`\"$PR_TITLE\"` in bash or `process.env.PR_TITLE` in JS).",
    falsePositiveNotes:
      "Safe `env:` indirection is recognized and NOT flagged. Expressions referencing non-attacker-controlled fields (`github.sha`, `github.run_id`, `runner.os`) are excluded.",
    limitations:
      "In private repositories with trusted internal contributors only, exploitability requires an authenticated committer/commenter, though it remains a code-injection defect.",
    references: [
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
    ]
  },

  "GHA-ACT-001": {
    ruleId: "GHA-ACT-001",
    version: "1.0.0",
    category: "SUPPLY_CHAIN",
    title: "Third-party GitHub Action referenced by mutable tag or branch instead of commit SHA",
    defaultSeverity: "MEDIUM",
    defaultConfidence: "HIGH",
    cwe: "CWE-829",
    owaspCicd: "CICD-SEC-8",
    summary:
      "A third-party action is referenced via a mutable Git tag or branch (e.g., `@v4` or `@main`) instead of an immutable 40-character commit SHA.",
    impact:
      "If the upstream action repository or maintainer account is compromised, an attacker can silently move the mutable tag to malicious code (as seen in real-world supply-chain incidents like `tj-actions/changed-files`), executing inside your CI runner with access to secrets and tokens.",
    remediation:
      "Pin external actions to a full 40-character commit SHA with an inline version comment (e.g., `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`) and automate updates with Dependabot or Renovate.",
    falsePositiveNotes:
      "Repository-local actions (`./.github/actions/...`) and digest-pinned Docker actions (`@sha256:...`) are already immutable and are NOT flagged.",
    limitations:
      "Pinning prevents silent tag mutation, but does not audit the underlying action source code itself.",
    references: [
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
    ]
  },

  "GHA-ACT-002": {
    ruleId: "GHA-ACT-002",
    version: "1.0.0",
    category: "SUPPLY_CHAIN",
    title: "External reusable workflow referenced by mutable tag or branch",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-829",
    owaspCicd: "CICD-SEC-8",
    summary:
      "A job invokes a remote reusable workflow (`uses: owner/repo/.github/workflows/...@ref`) without pinning to an immutable 40-character commit SHA.",
    impact:
      "Reusable workflows often receive repository secrets (`secrets: inherit`) and deployment permissions. A mutable ref allows upstream compromise to hijack entire release pipelines.",
    remediation:
      "Pin remote reusable workflows to a full 40-character commit SHA and pass only the explicit minimal secrets required.",
    falsePositiveNotes: "Local reusable workflows (`./.github/workflows/...`) are excluded.",
    limitations: "Cannot verify governance controls on the remote repository.",
    references: [
      "https://docs.github.com/en/actions/sharing-automations/reusing-workflows"
    ]
  },

  "GHA-ACT-003": {
    ruleId: "GHA-ACT-003",
    version: "1.0.0",
    category: "SUPPLY_CHAIN",
    title: "actions/checkout persists GITHUB_TOKEN credentials in .git/config during privileged or untrusted job",
    defaultSeverity: "MEDIUM",
    defaultConfidence: "HIGH",
    cwe: "CWE-522",
    owaspCicd: "CICD-SEC-6",
    summary:
      "`actions/checkout` defaults to `persist-credentials: true`, writing the `GITHUB_TOKEN` HTTP authorization header into `.git/config` on disk for the duration of the job.",
    impact:
      "Subsequent build scripts, third-party tools, or untrusted test code can read `.git/config` and abuse the persisted token to push commits or access private resources.",
    remediation:
      "Set `with: { persist-credentials: false }` on `actions/checkout` whenever subsequent steps do not need to run authenticated `git push` commands.",
    falsePositiveNotes:
      "Only flagged when the job has write permissions, omits explicit permissions, or runs on untrusted PR triggers. Read-only jobs with explicit `contents: read` and no write scope are excluded to reduce noise.",
    limitations: "Steps that legitimately push tags or commits back to GitHub require persisted credentials or an explicit token passed only to the push step.",
    references: [
      "https://github.com/actions/checkout#usage",
      "https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised"
    ]
  },

  "GHA-SEC-001": {
    ruleId: "GHA-SEC-001",
    version: "1.0.0",
    category: "SECRETS",
    title: "Secret value exposed in shell output, command line, or broad secrets: inherit delegation",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-532",
    owaspCicd: "CICD-SEC-6",
    summary:
      "Workflow secrets are directly interpolated into logging/shell output (`echo`, `printf`, `printenv`, `env`) or forwarded wholesale via `secrets: inherit` to an external reusable workflow.",
    impact:
      "Directly interpolating secrets into shell commands risks command-line exposure, encoding bypass of GitHub log masking, or unintended leakage of all repository/organization secrets to external reusable workflows.",
    remediation:
      "Pass secrets only via narrowly scoped step-level `env:` variables (never echo/print them), and replace `secrets: inherit` on external workflows with explicit per-secret mappings.",
    falsePositiveNotes:
      "GitHub masks exact raw secret values in logs, but encoded/transformed or partial outputs bypass masking; printing secrets is always unsafe.",
    limitations: "Detects direct YAML secret references; does not trace secrets loaded dynamically from external vaults inside scripts.",
    references: [
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions"
    ]
  },

  "GHA-SEC-002": {
    ruleId: "GHA-SEC-002",
    version: "1.0.0",
    category: "SECRETS",
    title: "Long-lived static cloud credentials used in workflow instead of short-lived OIDC federation",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-798",
    owaspCicd: "CICD-SEC-6",
    summary:
      "The workflow configures AWS, GCP, or Azure authentication using static long-lived credential secrets (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, `AZURE_CREDENTIALS`, `GCP_SA_KEY`) instead of short-lived OIDC workload identity federation.",
    impact:
      "Long-lived static cloud keys stored as CI secrets lack automatic expiration and branch/environment claim binding; if exfiltrated from any runner or log, attackers retain persistent cloud access until manual rotation.",
    remediation:
      "Migrate to GitHub Actions OIDC federation (`id-token: write` scoped to a dedicated deployment job + cloud IAM trust policy pinned to exact repository and branch/environment).",
    falsePositiveNotes:
      "Legacy cloud accounts or non-OIDC endpoints may temporarily require static credentials; evaluate compensating rotation controls.",
    limitations: "Detects common cloud credential secret names and cloud login action static-key inputs.",
    references: [
      "https://docs.github.com/en/actions/concepts/security/openid-connect"
    ]
  },

  "GHA-INT-001": {
    ruleId: "GHA-INT-001",
    version: "1.0.0",
    category: "BUILD_INTEGRITY",
    title: "Unverified remote script piped directly to shell interpreter",
    defaultSeverity: "MEDIUM",
    defaultConfidence: "HIGH",
    cwe: "CWE-494",
    owaspCicd: "CICD-SEC-9",
    summary:
      "A workflow step downloads a remote script via `curl` or `wget` and pipes it directly into `sh`/`bash`/`python` without cryptographic checksum or signature verification.",
    impact:
      "Compromise of the remote host, CDN, or redirect target injects arbitrary malicious code directly into the CI build environment with zero integrity verification.",
    remediation:
      "Download a pinned versioned release archive, verify its SHA-256 digest against a checked-in checksum (or use a SHA-pinned GitHub Action / container image digest), and then execute.",
    falsePositiveNotes: "None for direct `curl | sh` patterns; verify checksums before execution.",
    limitations: "Detects common shell pipe-to-interpreter patterns inside `run:` blocks.",
    references: [
      "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation"
    ]
  },

  "GHA-INT-002": {
    ruleId: "GHA-INT-002",
    version: "1.0.0",
    category: "BUILD_INTEGRITY",
    title: "Dependency installation without lockfile integrity enforcement in CI",
    defaultSeverity: "MEDIUM",
    defaultConfidence: "MEDIUM",
    cwe: "CWE-494",
    owaspCicd: "CICD-SEC-3",
    summary:
      "Workflow uses mutable dependency installation commands (`npm install` instead of `npm ci`, `yarn install` without `--frozen-lockfile`/`--immutable`, or `pip install` without hash/requirements lock) in CI/release jobs.",
    impact:
      "Allows floating transitive dependencies to resolve dynamically during CI/release builds, increasing exposure to dependency confusion and newly compromised upstream minor releases.",
    remediation:
      "Use `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`, or `pip install --require-hashes -r requirements.lock` in CI and release workflows.",
    falsePositiveNotes:
      "Global CLI tool installs (`npm install -g ...`) or intentional lockfile-update bot workflows may trigger if not excluded.",
    limitations: "Inspects shell commands in workflow `run:` blocks; does not inspect external Makefile/shell scripts.",
    references: [
      "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse"
    ]
  },

  "GHA-OIDC-001": {
    ruleId: "GHA-OIDC-001",
    version: "1.0.0",
    category: "OIDC_FEDERATION",
    title: "Overly broad GitHub Actions OIDC subject (sub) trust condition in cloud IAM configuration",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-285",
    owaspCicd: "CICD-SEC-2",
    summary:
      "A static AWS IAM, Azure Federated Identity, or GCP Workload Identity trust policy for `token.actions.githubusercontent.com` omits a `sub` restriction or uses an overly broad wildcard (such as `repo:org/*`, `repo:org/repo:*`, or `*`).",
    impact:
      "Any repository in the organization (or any branch/PR/tag in the repository — or literally any GitHub repository worldwide if `sub` is missing or `*`) can exchange a GitHub OIDC token for this cloud identity.",
    remediation:
      "Constrain the OIDC `sub` claim using exact `StringEquals` matching pinned to a protected branch or deployment environment (e.g., `repo:owner/repo:environment:production` or `repo:owner/repo:ref:refs/heads/main`).",
    falsePositiveNotes:
      "Multi-repo platform deployment roles occasionally scope to a specific repository prefix intentionally, though environment-bound per-repo trust is strongly preferred.",
    limitations:
      "Static configuration analysis (`STATIC_CONFIG`) only; live cloud IAM role permissions, permission boundaries, and SCPs are not verified without live cloud assessment.",
    references: [
      "https://docs.github.com/en/actions/concepts/security/openid-connect#configuring-the-oidc-trust-with-the-cloud",
      "https://aws.amazon.com/blogs/security/use-iam-roles-to-connect-github-actions-to-actions-in-aws/"
    ]
  },

  "GHA-OIDC-002": {
    ruleId: "GHA-OIDC-002",
    version: "1.0.0",
    category: "OIDC_FEDERATION",
    title: "Missing or wildcard OIDC audience (aud) validation in cloud trust policy",
    defaultSeverity: "HIGH",
    defaultConfidence: "HIGH",
    cwe: "CWE-345",
    owaspCicd: "CICD-SEC-2",
    summary:
      "A static cloud OIDC trust policy referencing `token.actions.githubusercontent.com` does not restrict the `aud` claim (e.g., `sts.amazonaws.com` for AWS or `api://AzureADTokenExchange` for Azure) or uses a wildcard.",
    impact:
      "Without strict audience validation, OIDC tokens minted for a different audience/service could be replayed against this cloud trust relationship.",
    remediation:
      "Explicitly enforce `StringEquals` on `token.actions.githubusercontent.com:aud` = `sts.amazonaws.com` (AWS) or `api://AzureADTokenExchange` (Azure).",
    falsePositiveNotes:
      "GCP Workload Identity Pool Providers validate the default pool audience automatically unless `allowed_audiences` is overridden.",
    limitations: "Static configuration analysis (`STATIC_CONFIG`) only.",
    references: [
      "https://docs.github.com/en/actions/concepts/security/openid-connect#configuring-the-oidc-trust-with-the-cloud"
    ]
  },

  "GHA-OIDC-003": {
    ruleId: "GHA-OIDC-003",
    version: "1.0.0",
    category: "OIDC_FEDERATION",
    title: "Correlated pipeline-to-cloud OIDC trust weakness (workflow token request + permissive trust policy)",
    defaultSeverity: "CRITICAL",
    defaultConfidence: "HIGH",
    cwe: "CWE-269",
    owaspCicd: "CICD-SEC-2",
    summary:
      "Cross-file static correlation found both a GitHub Actions workflow requesting OIDC tokens (`id-token: write` / cloud OIDC auth action) and a permissive static cloud OIDC trust policy in the same repository.",
    impact:
      "Combines an active CI/CD OIDC token minting path with an overly broad cloud trust boundary, increasing the likelihood that a workflow or branch compromise pivots into cloud infrastructure.",
    remediation:
      "1. Scope `id-token: write` to a dedicated deployment job protected by a GitHub `environment:`. 2. Restrict the cloud OIDC trust policy `sub` claim to `repo:owner/repo:environment:<env>` and enforce exact `aud` validation.",
    falsePositiveNotes:
      "Static correlation proves both artifacts exist in the repository; verify whether the Terraform/IaC role is deployed to production and inspect its live IAM permissions.",
    limitations:
      "Evidence basis is `STATIC_CONFIG` correlation; live AWS/Azure/GCP role authorization, SCPs, and GitHub environment reviewer gates are unknown statically.",
    references: [
      "https://docs.github.com/en/actions/concepts/security/openid-connect"
    ]
  }
};

export function getCicdRule(ruleId: string): CicdRuleDefinition {
  const rule = CICD_RULE_CATALOG[ruleId];
  if (!rule) {
    throw new Error(`Unknown CI/CD security rule: ${ruleId}`);
  }
  return rule;
}

export function listCicdRules(): CicdRuleDefinition[] {
  return Object.values(CICD_RULE_CATALOG);
}
