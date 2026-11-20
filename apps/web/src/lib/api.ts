"use client";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000";

let cachedCsrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  cachedCsrfToken = token;
}

export function getApiBaseUrl(): string {
  return API_BASE;
}

export class ApiClientError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (["POST", "PATCH", "PUT", "DELETE"].includes(method) && cachedCsrfToken) {
    headers.set("X-CSRF-Token", cachedCsrfToken);
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    method,
    headers,
    credentials: "include"
  });

  if (!res.ok) {
    let code = "HTTP_ERROR";
    let message = `Request failed (${res.status})`;
    try {
      const errJson = (await res.json()) as {
        error?: { code?: string; message?: string };
      };
      if (errJson?.error?.code) code = errJson.error.code;
      if (errJson?.error?.message) message = errJson.error.message;
    } catch {
      // ignore non-json error bodies
    }
    throw new ApiClientError(res.status, code, message);
  }

  return (await res.json()) as T;
}

export interface AuthMeResponse {
  user: {
    id: string;
    email: string;
    name: string;
    githubLogin: string | null;
    isDemoUser: boolean;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
    role: string;
  };
  csrfToken: string;
  capabilities: {
    demoMode: boolean;
    githubOAuthConfigured: boolean;
    githubAppConfigured: boolean;
    githubAppInstallUrl: string;
    aiConfigured: boolean;
  };
}

export async function fetchSession(): Promise<AuthMeResponse | null> {
  try {
    const me = await apiFetch<AuthMeResponse>("/api/v1/auth/me");
    setCsrfToken(me.csrfToken);
    return me;
  } catch {
    return null;
  }
}
