import type { ParsedWorkflow, WorkflowJob } from "@indicative/cicd-security";
import type { WorkflowCloudIdentityRef } from "../types.js";

const UNTRUSTED_TRIGGERS = new Set([
  "pull_request_target",
  "issue_comment",
  "issues",
  "discussion",
  "discussion_comment",
  "workflow_run"
]);

/**
 * Extracts a likely IAM role name from an ARN or expression such as:
 *   arn:aws:iam::123456789012:role/acme-deploy-role
 *   arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/prod-deploy
 */
export function extractAwsRoleNameFromArn(rawRef?: string): string | undefined {
  if (!rawRef) return undefined;
  const trimmed = rawRef.trim();
  const roleMatch = trimmed.match(/:role\/(?:[^/\s$}]+\/)*([A-Za-z0-9+=,.@_-]{1,128})/i);
  if (roleMatch?.[1]) return roleMatch[1];
  return undefined;
}

function jobHasIdTokenWrite(wf: ParsedWorkflow, job: WorkflowJob): boolean {
  const effective = job.permissions ?? wf.permissions;
  if (!effective) return false;
  if (effective.mode === "write-all") return true;
  return effective.scopes["id-token"] === "write";
}

/**
 * Extracts explicit cloud identity targets referenced inside GitHub Actions workflows
 * (`aws-actions/configure-aws-credentials`, `azure/login`, `google-github-actions/auth`).
 */
export function extractWorkflowCloudIdentityRefs(
  workflows: ParsedWorkflow[]
): WorkflowCloudIdentityRef[] {
  const refs: WorkflowCloudIdentityRef[] = [];

  for (const wf of workflows) {
    const triggers = wf.triggers.map((t) => t.event);
    const hasUntrustedTrigger = triggers.some((t) => UNTRUSTED_TRIGGERS.has(t));

    for (const job of wf.jobs) {
      const hasIdTokenWrite = jobHasIdTokenWrite(wf, job);

      for (const step of job.steps) {
        const usesLower = (step.uses ?? "").toLowerCase();
        if (!usesLower) continue;

        if (usesLower.startsWith("aws-actions/configure-aws-credentials")) {
          const roleToAssume = step.withInputs["role-to-assume"]?.trim();
          const audience = step.withInputs.audience?.trim();
          if (roleToAssume || hasIdTokenWrite) {
            refs.push({
              provider: "aws",
              workflowFilePath: wf.filePath,
              workflowName: wf.name,
              jobId: job.jobId,
              environment: job.environment,
              action: step.uses!,
              roleToAssume,
              roleNameHint: extractAwsRoleNameFromArn(roleToAssume),
              audience,
              hasIdTokenWrite,
              hasUntrustedTrigger,
              triggers,
              lineStart: step.lineStart,
              lineEnd: step.lineEnd
            });
          }
        } else if (usesLower.startsWith("azure/login")) {
          const clientId = step.withInputs["client-id"]?.trim();
          if (clientId || hasIdTokenWrite) {
            refs.push({
              provider: "azure",
              workflowFilePath: wf.filePath,
              workflowName: wf.name,
              jobId: job.jobId,
              environment: job.environment,
              action: step.uses!,
              clientId,
              hasIdTokenWrite,
              hasUntrustedTrigger,
              triggers,
              lineStart: step.lineStart,
              lineEnd: step.lineEnd
            });
          }
        } else if (usesLower.startsWith("google-github-actions/auth")) {
          const workloadIdentityProvider =
            step.withInputs.workload_identity_provider?.trim();
          const serviceAccount = step.withInputs.service_account?.trim();
          if (workloadIdentityProvider || serviceAccount || hasIdTokenWrite) {
            refs.push({
              provider: "gcp",
              workflowFilePath: wf.filePath,
              workflowName: wf.name,
              jobId: job.jobId,
              environment: job.environment,
              action: step.uses!,
              workloadIdentityProvider,
              serviceAccount,
              hasIdTokenWrite,
              hasUntrustedTrigger,
              triggers,
              lineStart: step.lineStart,
              lineEnd: step.lineEnd
            });
          }
        }
      }
    }
  }

  return refs;
}
