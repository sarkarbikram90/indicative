import crypto from "node:crypto";
import {
  containsPotentialPlaintextSecret,
  redactSecretsInText,
  validateAllowedOutboundUrl,
  validateGitHubRepositorySlug
} from "@indicative/security";

export interface GitHubAppCredentials {
  appId: string;
  privateKeyPem: string;
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
}

export interface GitHubCheckRunAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  title: string;
  message: string;
}

export interface GitHubCheckRunPayload {
  name: string;
  headSha: string;
  status: "queued" | "in_progress" | "completed";
  conclusion?: "success" | "neutral" | "failure" | "action_required";
  detailsUrl?: string;
  externalId?: string;
  title: string;
  summary: string;
  annotations?: GitHubCheckRunAnnotation[];
}

export interface DiscoveredGitHubRepo {
  externalRepoId: string;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
  htmlUrl: string;
  description: string | null;
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return buf.toString("base64url");
}

function normalizePrivateKeyPem(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.includes("-----BEGIN")) {
    return trimmed.replace(/\\n/g, "\n");
  }
  // Support base64-encoded PEM in env vars
  return Buffer.from(trimmed, "base64").toString("utf8");
}

/**
 * Signs a short-lived GitHub App RS256 JWT (valid 9 minutes, per GitHub specification).
 */
export function createGitHubAppJwt(appId: string, privateKeyPem: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64UrlEncode(
    JSON.stringify({
      iat: now - 60,
      exp: now + 540,
      iss: appId
    })
  );
  const signingInput = `${header}.${payload}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(signingInput);
  const signature = signer.sign(normalizePrivateKeyPem(privateKeyPem));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export class GitHubAppClient {
  private readonly appId: string;
  private readonly privateKeyPem: string;
  private readonly apiBaseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly allowedHosts: string[];
  private readonly allowHttpInTest: boolean;

  constructor(creds: GitHubAppCredentials) {
    this.appId = creds.appId;
    this.privateKeyPem = creds.privateKeyPem;
    this.apiBaseUrl = (creds.apiBaseUrl ?? "https://api.github.com").replace(/\/+$/, "");
    this.fetchFn = creds.fetchImpl ?? fetch;
    const parsedBase = new URL(this.apiBaseUrl);
    this.allowedHosts = [parsedBase.hostname];
    this.allowHttpInTest = parsedBase.protocol === "http:" && process.env.NODE_ENV === "test";
  }

  private assertUrl(url: string): string {
    return validateAllowedOutboundUrl(url, {
      allowedHosts: this.allowedHosts,
      allowHttpInTest: this.allowHttpInTest
    }).toString();
  }

  /**
   * Mints a short-lived installation access token scoped strictly to requested repositories.
   * Defaults strictly to read-only contents/metadata permissions for repository ingestion.
   * NEVER log or return this token to the frontend.
   */
  async createInstallationToken(
    installationId: number,
    repositoryNames?: string[],
    permissions: Record<string, "read" | "write"> = {
      contents: "read",
      metadata: "read"
    }
  ): Promise<{ token: string; expiresAt: string }> {
    const jwt = createGitHubAppJwt(this.appId, this.privateKeyPem);
    const url = this.assertUrl(
      `${this.apiBaseUrl}/app/installations/${installationId}/access_tokens`
    );

    const body: Record<string, unknown> = {
      permissions
    };
    if (repositoryNames && repositoryNames.length > 0) {
      body.repositories = repositoryNames.map((slug) => validateGitHubRepositorySlug(slug).repo);
    }

    const res = await this.fetchFn(url, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${jwt}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.1"
      },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      throw new Error(`GITHUB_APP_TOKEN_ERROR: GitHub returned HTTP ${res.status}.`);
    }

    const data = (await res.json()) as { token?: string; expires_at?: string };
    if (!data.token) {
      throw new Error("GITHUB_APP_TOKEN_ERROR: Missing installation token in GitHub response.");
    }

    return {
      token: data.token,
      expiresAt: data.expires_at ?? new Date(Date.now() + 3600_000).toISOString()
    };
  }

  async listInstallationRepositories(
    installationId: number
  ): Promise<DiscoveredGitHubRepo[]> {
    const { token } = await this.createInstallationToken(installationId);
    const url = this.assertUrl(`${this.apiBaseUrl}/installation/repositories?per_page=100`);

    const res = await this.fetchFn(url, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.1"
      }
    });

    if (!res.ok) {
      throw new Error(`GITHUB_REPO_DISCOVERY_ERROR: GitHub returned HTTP ${res.status}.`);
    }

    const data = (await res.json()) as {
      repositories?: Array<{
        id: number;
        full_name: string;
        default_branch?: string;
        private?: boolean;
        html_url?: string;
        description?: string | null;
      }>;
    };

    return (data.repositories ?? []).map((r) => ({
      externalRepoId: String(r.id),
      fullName: validateGitHubRepositorySlug(r.full_name).fullName,
      defaultBranch: r.default_branch ?? "main",
      isPrivate: Boolean(r.private),
      htmlUrl: r.html_url ?? `https://github.com/${r.full_name}`,
      description: r.description ?? null
    }));
  }

  private assertSafeOutboundText(serialized: string, context: string): void {
    if (containsPotentialPlaintextSecret(serialized)) {
      throw new Error(
        `SECURITY_VIOLATION: Refused to publish outbound GitHub ${context} containing potential plaintext secret.`
      );
    }
  }

  /**
   * Creates or updates a GitHub Check Run on a commit SHA.
   */
  async upsertCheckRun(params: {
    installationId: number;
    repositoryFullName: string;
    checkRunId?: number;
    payload: GitHubCheckRunPayload;
  }): Promise<{ checkRunId: number; htmlUrl?: string }> {
    const { owner, repo, fullName } = validateGitHubRepositorySlug(params.repositoryFullName);
    const { token } = await this.createInstallationToken(params.installationId, [fullName], {
      checks: "write",
      metadata: "read"
    });

    const isUpdate = typeof params.checkRunId === "number" && params.checkRunId > 0;
    const url = this.assertUrl(
      isUpdate
        ? `${this.apiBaseUrl}/repos/${owner}/${repo}/check-runs/${params.checkRunId}`
        : `${this.apiBaseUrl}/repos/${owner}/${repo}/check-runs`
    );

    const safeAnnotations = (params.payload.annotations ?? []).slice(0, 50).map((a) => ({
      ...a,
      title: redactSecretsInText(a.title).slice(0, 255),
      message: redactSecretsInText(a.message).slice(0, 1000)
    }));

    const bodyObj: Record<string, unknown> = {
      name: params.payload.name,
      head_sha: params.payload.headSha,
      status: params.payload.status,
      ...(params.payload.status === "completed" && params.payload.conclusion
        ? {
            conclusion: params.payload.conclusion,
            completed_at: new Date().toISOString()
          }
        : {}),
      ...(params.payload.detailsUrl ? { details_url: params.payload.detailsUrl } : {}),
      ...(params.payload.externalId ? { external_id: params.payload.externalId } : {}),
      output: {
        title: redactSecretsInText(params.payload.title).slice(0, 255),
        summary: redactSecretsInText(params.payload.summary).slice(0, 60000),
        ...(safeAnnotations.length > 0 ? { annotations: safeAnnotations } : {})
      }
    };

    const serialized = JSON.stringify(bodyObj);
    this.assertSafeOutboundText(serialized, "check-run");

    const res = await this.fetchFn(url, {
      method: isUpdate ? "PATCH" : "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.2"
      },
      body: serialized
    });

    if (!res.ok) {
      throw new Error(`GITHUB_CHECK_RUN_ERROR: GitHub returned HTTP ${res.status}.`);
    }

    const data = (await res.json()) as { id?: number; html_url?: string };
    return {
      checkRunId: data.id ?? params.checkRunId ?? 0,
      htmlUrl: data.html_url
    };
  }

  /**
   * Upserts a single sticky PR summary comment identified by marker (avoids comment spam).
   */
  async upsertPullRequestComment(params: {
    installationId: number;
    repositoryFullName: string;
    pullNumber: number;
    marker: string;
    bodyMarkdown: string;
  }): Promise<{ commentId: number; htmlUrl?: string; updated: boolean }> {
    const { owner, repo, fullName } = validateGitHubRepositorySlug(params.repositoryFullName);
    const { token } = await this.createInstallationToken(params.installationId, [fullName], {
      issues: "write",
      pull_requests: "write",
      metadata: "read"
    });

    const safeBody = `${params.marker}\n${redactSecretsInText(params.bodyMarkdown)}`.slice(0, 64000);
    this.assertSafeOutboundText(safeBody, "pull-request comment");

    const listUrl = this.assertUrl(
      `${this.apiBaseUrl}/repos/${owner}/${repo}/issues/${params.pullNumber}/comments?per_page=50`
    );
    const listRes = await this.fetchFn(listUrl, {
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.2"
      }
    });

    let existingCommentId: number | undefined;
    if (listRes.ok) {
      const comments = (await listRes.json()) as Array<{ id: number; body?: string }>;
      const match = comments.find((c) => typeof c.body === "string" && c.body.includes(params.marker));
      existingCommentId = match?.id;
    }

    const targetUrl = this.assertUrl(
      existingCommentId
        ? `${this.apiBaseUrl}/repos/${owner}/${repo}/issues/comments/${existingCommentId}`
        : `${this.apiBaseUrl}/repos/${owner}/${repo}/issues/${params.pullNumber}/comments`
    );

    const writeRes = await this.fetchFn(targetUrl, {
      method: existingCommentId ? "PATCH" : "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.2"
      },
      body: JSON.stringify({ body: safeBody })
    });

    if (!writeRes.ok) {
      throw new Error(`GITHUB_PR_COMMENT_ERROR: GitHub returned HTTP ${writeRes.status}.`);
    }

    const saved = (await writeRes.json()) as { id?: number; html_url?: string };
    return {
      commentId: saved.id ?? existingCommentId ?? 0,
      htmlUrl: saved.html_url,
      updated: Boolean(existingCommentId)
    };
  }

  /**
   * Creates a GitHub security issue using either a GitHub App installation token or an explicit token.
   */
  async createRepositoryIssue(params: {
    installationId?: number;
    token?: string;
    repositoryFullName: string;
    title: string;
    bodyMarkdown: string;
    labels?: string[];
  }): Promise<{ issueNumber: number; htmlUrl: string }> {
    const { owner, repo, fullName } = validateGitHubRepositorySlug(params.repositoryFullName);
    let authToken = params.token;
    if (!authToken && params.installationId) {
      const minted = await this.createInstallationToken(params.installationId, [fullName], {
        issues: "write",
        metadata: "read"
      });
      authToken = minted.token;
    }
    if (!authToken) {
      throw new Error("GITHUB_ISSUE_AUTH_MISSING: No GitHub installation or token available.");
    }

    const safeTitle = redactSecretsInText(params.title).slice(0, 240);
    const safeBody = redactSecretsInText(params.bodyMarkdown).slice(0, 64000);
    const serialized = JSON.stringify({
      title: safeTitle,
      body: safeBody,
      labels: params.labels ?? ["indicative-security"]
    });
    this.assertSafeOutboundText(serialized, "repository issue");

    const url = this.assertUrl(`${this.apiBaseUrl}/repos/${owner}/${repo}/issues`);
    const res = await this.fetchFn(url, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Indicative-Security-Platform/0.2"
      },
      body: serialized
    });

    if (!res.ok) {
      throw new Error(`GITHUB_ISSUE_CREATE_ERROR: GitHub returned HTTP ${res.status}.`);
    }

    const created = (await res.json()) as { number?: number; html_url?: string };
    return {
      issueNumber: created.number ?? 0,
      htmlUrl: created.html_url ?? `https://github.com/${fullName}/issues`
    };
  }
}
