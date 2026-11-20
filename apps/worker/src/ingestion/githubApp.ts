import crypto from "node:crypto";
import { validateAllowedOutboundUrl, validateGitHubRepositorySlug } from "@indicative/security";

export interface GitHubAppCredentials {
  appId: string;
  privateKeyPem: string;
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
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
   * Mints a short-lived, read-only installation access token scoped strictly to requested repositories.
   * NEVER log or return this token to the frontend.
   */
  async createInstallationToken(
    installationId: number,
    repositoryNames?: string[]
  ): Promise<{ token: string; expiresAt: string }> {
    const jwt = createGitHubAppJwt(this.appId, this.privateKeyPem);
    const url = this.assertUrl(
      `${this.apiBaseUrl}/app/installations/${installationId}/access_tokens`
    );

    const body: Record<string, unknown> = {
      permissions: {
        contents: "read",
        metadata: "read"
      }
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
}
