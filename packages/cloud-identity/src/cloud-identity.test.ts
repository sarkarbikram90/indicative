import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  analyzeWorkspaceCloudIdentity,
  CloudIdentityIamAdapter,
  extractAwsRoleNameFromArn,
  formatCloudIdentityMarkdownSummary,
  formatCloudIdentityReportAsSarif
} from "./index.js";

describe("@indicative/cloud-identity", () => {
  it("extracts AWS IAM role names from full ARNs and templated ARNs", () => {
    expect(
      extractAwsRoleNameFromArn("arn:aws:iam::123456789012:role/acme-ecommerce-deploy")
    ).toBe("acme-ecommerce-deploy");
    expect(
      extractAwsRoleNameFromArn("arn:aws:iam::${{ secrets.AWS_ACCOUNT }}:role/ci/prod-deploy")
    ).toBe("prod-deploy");
    expect(extractAwsRoleNameFromArn("not-an-arn")).toBeUndefined();
  });

  it("correlates GitHub Actions OIDC workflow -> broad trust -> over-privileged AWS IAM role and discloses unknown controls", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "indicative-cloud-id-"));
    try {
      await fs.mkdir(path.join(tmpDir, ".github", "workflows"), { recursive: true });
      await fs.mkdir(path.join(tmpDir, "infra"), { recursive: true });

      await fs.writeFile(
        path.join(tmpDir, ".github", "workflows", "deploy.yml"),
        [
          "name: Deploy E-Commerce",
          "on:",
          "  pull_request_target:",
          "    branches: [main]",
          "permissions:",
          "  id-token: write",
          "  contents: read",
          "jobs:",
          "  deploy:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d4db1c34928",
          "        with:",
          "          role-to-assume: arn:aws:iam::123456789012:role/ecommerce-deploy-role",
          "          aws-region: us-east-1"
        ].join("\n"),
        "utf8"
      );

      await fs.writeFile(
        path.join(tmpDir, "infra", "iam.tf"),
        [
          'resource "aws_iam_role" "ecommerce_deploy" {',
          '  name = "ecommerce-deploy-role"',
          "  assume_role_policy = jsonencode({",
          '    Version = "2012-10-17"',
          "    Statement = [{",
          '      Effect = "Allow"',
          '      Action = "sts:AssumeRoleWithWebIdentity"',
          '      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }',
          "      Condition = {",
          "        StringLike = {",
          '          "token.actions.githubusercontent.com:sub" = "repo:acme/*"',
          "        }",
          "      }",
          "    }]",
          "  })",
          "}",
          "",
          'resource "aws_iam_role_policy" "ecommerce_s3" {',
          '  name = "ecommerce-broad-s3"',
          "  role = aws_iam_role.ecommerce_deploy.id",
          "  policy = jsonencode({",
          '    Version = "2012-10-17"',
          "    Statement = [",
          "      {",
          '        Effect = "Allow"',
          '        Action = ["s3:*", "secretsmanager:GetSecretValue"]',
          '        Resource = "*"',
          "      },",
          "      {",
          '        Effect = "Allow"',
          '        Action = ["iam:PassRole", "lambda:CreateFunction"]',
          '        Resource = "*"',
          "      }",
          "    ]",
          "  })",
          "}"
        ].join("\n"),
        "utf8"
      );

      const report = await analyzeWorkspaceCloudIdentity(tmpDir, {
        mode: "failure",
        failOnSeverities: ["CRITICAL", "HIGH"]
      });

      expect(report.workflowIdentityRefs).toHaveLength(1);
      expect(report.workflowIdentityRefs[0]!.roleNameHint).toBe("ecommerce-deploy-role");
      expect(report.iamRoles).toHaveLength(1);
      expect(report.correlatedChains).toHaveLength(1);

      const chain = report.correlatedChains[0]!;
      expect(chain.linkConfidence).toBe("EXACT_ROLE_MATCH");
      expect(chain.capabilityTier).toBe("PRIVILEGE_ESCALATION");
      expect(chain.severity).toBe("CRITICAL");
      expect(chain.hops).toHaveLength(4);
      expect(chain.unknownControls).toContain("AWS_SCP_UNKNOWN");
      expect(chain.unknownControls).toContain("GITHUB_BRANCH_PROTECTION_UNKNOWN");

      const ruleIds = new Set(report.findings.map((f) => f.ruleId));
      expect(ruleIds.has("IAM-PERM-001")).toBe(true);
      expect(ruleIds.has("IAM-DATA-001")).toBe(true);
      expect(ruleIds.has("IAM-ESC-001")).toBe(true);
      expect(ruleIds.has("IAM-BOUND-001")).toBe(true);
      expect(ruleIds.has("IAM-CORR-001")).toBe(true);
      expect(report.policyEvaluation.passed).toBe(false);

      const md = formatCloudIdentityMarkdownSummary(report);
      expect(md).toContain("Evidence-Backed CI/CD → Cloud Identity Chains");
      expect(md).toContain("AWS_SCP_UNKNOWN");

      const sarif = JSON.parse(formatCloudIdentityReportAsSarif(report)) as {
        version: string;
        runs: Array<{ results: unknown[] }>;
      };
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs[0]!.results.length).toBe(report.findings.length);

      // Verify ScannerAdapter execution
      const adapter = new CloudIdentityIamAdapter();
      const health = await adapter.healthCheck();
      expect(health.available).toBe(true);
      const execResult = await adapter.execute({
        scanId: "scan-1",
        organizationId: "org-1",
        projectId: "proj-1",
        workspacePath: tmpDir,
        hasGitHistory: false,
        isShallowClone: false,
        maxGitHistoryCommits: 100,
        timeoutMs: 30_000,
        secretFingerprintKey: "test-key"
      });
      expect(execResult.status).toBe("SUCCESS");
      expect(execResult.findings.length).toBe(report.findings.length);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("does not flag Deny statements or least-privilege ARN-scoped roles", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "indicative-cloud-id-clean-"));
    try {
      await fs.mkdir(path.join(tmpDir, "infra"), { recursive: true });
      await fs.writeFile(
        path.join(tmpDir, "infra", "iam.tf"),
        [
          'resource "aws_iam_role" "scoped_deploy" {',
          '  name = "scoped-deploy-role"',
          '  permissions_boundary = "arn:aws:iam::123456789012:policy/deploy-boundary"',
          "}",
          "",
          'resource "aws_iam_role_policy" "scoped_s3" {',
          '  name = "scoped-s3-upload"',
          "  role = aws_iam_role.scoped_deploy.id",
          "  policy = jsonencode({",
          '    Version = "2012-10-17"',
          "    Statement = [",
          "      {",
          '        Effect = "Allow"',
          '        Action = ["s3:PutObject", "s3:GetObject"]',
          '        Resource = "arn:aws:s3:::acme-prod-artifacts/*"',
          "      },",
          "      {",
          '        Effect = "Deny"',
          '        NotAction = ["s3:PutObject", "s3:GetObject"]',
          '        Resource = "*"',
          "      }",
          "    ]",
          "  })",
          "}"
        ].join("\n"),
        "utf8"
      );

      const report = await analyzeWorkspaceCloudIdentity(tmpDir, {
        mode: "failure",
        failOnSeverities: ["CRITICAL", "HIGH"]
      });

      expect(report.findings).toHaveLength(0);
      expect(report.correlatedChains).toHaveLength(0);
      expect(report.policyEvaluation.passed).toBe(true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
