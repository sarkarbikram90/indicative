import type { FastifyInstance } from "fastify";
import { eq } from "drizzle-orm";
import {
  isAiConfigured,
  isGitHubAppConfigured,
  isGitHubOAuthConfigured,
  type AppConfig
} from "@indicative/config";
import {
  auditEvents,
  organizationMembers,
  organizations,
  securityPolicies,
  userSessions,
  users,
  type Database
} from "@indicative/database";
import {
  generateCsrfToken,
  generateSecureToken,
  hashSessionToken,
  signStateToken,
  verifyStateToken
} from "@indicative/security";
import { ForbiddenError, UnauthorizedError } from "@indicative/shared";
import { SESSION_COOKIE_NAME, type AuthContext } from "../middleware/auth.js";

const OAUTH_STATE_COOKIE = "indicative_oauth_state";

export interface AuthRouteDeps {
  db: Database;
  config: AppConfig;
  requireAuth: (req: any, reply: any) => Promise<void>;
  fetchImpl?: typeof fetch;
}

export async function createUserSession(params: {
  db: Database;
  config: AppConfig;
  userId: string;
  organizationId: string;
  ipAddress?: string;
  userAgent?: string;
}): Promise<{ rawToken: string; csrfToken: string; expiresAt: Date }> {
  const rawToken = generateSecureToken(32);
  const tokenHash = hashSessionToken(rawToken);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await params.db.insert(userSessions).values({
    userId: params.userId,
    organizationId: params.organizationId,
    tokenHash,
    expiresAt,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent?.slice(0, 250)
  });

  return {
    rawToken,
    csrfToken: generateCsrfToken(tokenHash, params.config.SESSION_SECRET),
    expiresAt
  };
}

export function registerAuthRoutes(app: FastifyInstance, deps: AuthRouteDeps) {
  const fetchFn = deps.fetchImpl ?? fetch;

  app.get("/api/v1/auth/me", { preHandler: [deps.requireAuth] }, async (request) => {
    const auth = request.auth as AuthContext;
    return {
      user: {
        id: auth.userId,
        email: auth.email,
        name: auth.name,
        githubLogin: auth.githubLogin,
        isDemoUser: auth.isDemoUser
      },
      organization: {
        id: auth.organizationId,
        name: auth.organizationName,
        slug: auth.organizationSlug,
        role: auth.role
      },
      csrfToken: auth.csrfToken,
      capabilities: {
        demoMode: deps.config.DEMO_MODE && deps.config.NODE_ENV !== "production",
        githubOAuthConfigured: isGitHubOAuthConfigured(deps.config),
        githubAppConfigured: isGitHubAppConfigured(deps.config),
        githubAppInstallUrl: `https://github.com/apps/${deps.config.GITHUB_APP_SLUG}/installations/new`,
        aiConfigured: isAiConfigured(deps.config)
      }
    };
  });

  app.get("/api/v1/auth/config", async () => {
    return {
      demoMode: deps.config.DEMO_MODE && deps.config.NODE_ENV !== "production",
      githubOAuthConfigured: isGitHubOAuthConfigured(deps.config),
      githubAppConfigured: isGitHubAppConfigured(deps.config),
      githubAppInstallUrl: `https://github.com/apps/${deps.config.GITHUB_APP_SLUG}/installations/new`,
      aiConfigured: isAiConfigured(deps.config)
    };
  });

  // Development-only demo login — strictly refuses to run in production
  app.post("/api/v1/auth/demo", async (request, reply) => {
    if (deps.config.NODE_ENV === "production" || !deps.config.DEMO_MODE) {
      throw new ForbiddenError("Demo authentication is disabled.");
    }

    const [demoUser] = await deps.db
      .select()
      .from(users)
      .where(eq(users.email, "demo@indicative.local"));
    const [demoOrg] = await deps.db
      .select()
      .from(organizations)
      .where(eq(organizations.slug, "indicative-demo-org"));

    if (!demoUser || !demoOrg) {
      throw new UnauthorizedError("Demo workspace has not been seeded yet.");
    }

    const session = await createUserSession({
      db: deps.db,
      config: deps.config,
      userId: demoUser.id,
      organizationId: demoOrg.id,
      ipAddress: request.ip,
      userAgent: request.headers["user-agent"]
    });

    await deps.db.insert(auditEvents).values({
      organizationId: demoOrg.id,
      actorUserId: demoUser.id,
      action: "AUTH_DEMO_LOGIN",
      resourceType: "SESSION",
      correlationId: request.correlationId,
      ipAddress: request.ip,
      metadata: { isDemo: true }
    });

    reply.setCookie(SESSION_COOKIE_NAME, session.rawToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      path: "/",
      expires: session.expiresAt
    });

    return {
      authenticated: true,
      isDemo: true,
      token: session.rawToken,
      csrfToken: session.csrfToken,
      user: {
        id: demoUser.id,
        email: demoUser.email,
        name: demoUser.name,
        isDemoUser: true
      },
      organization: {
        id: demoOrg.id,
        name: demoOrg.name,
        slug: demoOrg.slug
      }
    };
  });

  // GitHub OAuth start (with signed anti-CSRF state cookie)
  app.get("/api/v1/auth/github/start", async (_request, reply) => {
    if (!isGitHubOAuthConfigured(deps.config)) {
      return reply.status(503).send({
        error: {
          code: "GITHUB_OAUTH_UNCONFIGURED",
          message: "GitHub OAuth is not configured on this server."
        }
      });
    }

    const state = signStateToken({ purpose: "github_oauth" }, deps.config.SESSION_SECRET, 600);
    reply.setCookie(OAUTH_STATE_COOKIE, state, {
      httpOnly: true,
      sameSite: "lax",
      secure: deps.config.NODE_ENV === "production",
      path: "/api/v1/auth/github",
      maxAge: 600
    });

    const params = new URLSearchParams({
      client_id: deps.config.GITHUB_OAUTH_CLIENT_ID,
      redirect_uri: deps.config.GITHUB_OAUTH_CALLBACK_URL,
      scope: "read:user user:email",
      state
    });

    return reply.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });

  // GitHub OAuth callback
  app.get("/api/v1/auth/github/callback", async (request, reply) => {
    if (!isGitHubOAuthConfigured(deps.config)) {
      throw new ForbiddenError("GitHub OAuth is not configured.");
    }

    const query = request.query as { code?: string; state?: string };
    const stateCookie = request.cookies?.[OAUTH_STATE_COOKIE];
    reply.clearCookie(OAUTH_STATE_COOKIE, { path: "/api/v1/auth/github" });

    if (!query.code || !query.state || !stateCookie || query.state !== stateCookie) {
      throw new ForbiddenError("Invalid OAuth state parameter (CSRF check failed).");
    }

    const verifiedState = verifyStateToken(query.state, deps.config.SESSION_SECRET);
    if (!verifiedState || verifiedState.purpose !== "github_oauth") {
      throw new ForbiddenError("Expired or invalid OAuth state token.");
    }

    const tokenRes = await fetchFn("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: deps.config.GITHUB_OAUTH_CLIENT_ID,
        client_secret: deps.config.GITHUB_OAUTH_CLIENT_SECRET,
        code: query.code,
        redirect_uri: deps.config.GITHUB_OAUTH_CALLBACK_URL
      })
    });

    if (!tokenRes.ok) {
      throw new UnauthorizedError("GitHub OAuth token exchange failed.");
    }

    const tokenJson = (await tokenRes.json()) as { access_token?: string };
    if (!tokenJson.access_token) {
      throw new UnauthorizedError("GitHub OAuth returned no access token.");
    }

    // Fetch user identity only (never store OAuth token for repository access)
    const userRes = await fetchFn("https://api.github.com/user", {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${tokenJson.access_token}`,
        "User-Agent": "Indicative-Security-Platform/0.1"
      }
    });
    if (!userRes.ok) {
      throw new UnauthorizedError("Failed to fetch GitHub user profile.");
    }

    const ghUser = (await userRes.json()) as {
      id: number;
      login: string;
      name?: string | null;
      email?: string | null;
      avatar_url?: string | null;
    };

    const email = ghUser.email || `${ghUser.login}@users.noreply.github.com`;
    const ghIdStr = String(ghUser.id);

    let [userRow] = await deps.db
      .select()
      .from(users)
      .where(eq(users.githubUserId, ghIdStr));

    if (!userRow) {
      [userRow] = await deps.db
        .insert(users)
        .values({
          email,
          name: ghUser.name || ghUser.login,
          githubUserId: ghIdStr,
          githubLogin: ghUser.login,
          avatarUrl: ghUser.avatar_url ?? null,
          isDemoUser: false
        })
        .returning();
    }

    const memberships = await deps.db
      .select()
      .from(organizationMembers)
      .where(eq(organizationMembers.userId, userRow!.id));

    let orgId = memberships[0]?.organizationId;
    if (!orgId) {
      const slug = `${ghUser.login.toLowerCase().replace(/[^a-z0-9-]/g, "-")}-org`;
      const [createdOrg] = await deps.db
        .insert(organizations)
        .values({
          name: `${ghUser.login} Workspace`,
          slug,
          isDemo: false
        })
        .returning();
      orgId = createdOrg!.id;

      await deps.db.insert(organizationMembers).values({
        organizationId: orgId,
        userId: userRow!.id,
        role: "OWNER"
      });
      await deps.db.insert(securityPolicies).values({
        organizationId: orgId
      });
    }

    const session = await createUserSession({
      db: deps.db,
      config: deps.config,
      userId: userRow!.id,
      organizationId: orgId,
      ipAddress: request.ip,
      userAgent: request.headers["user-agent"]
    });

    await deps.db.insert(auditEvents).values({
      organizationId: orgId,
      actorUserId: userRow!.id,
      action: "AUTH_GITHUB_OAUTH_LOGIN",
      resourceType: "SESSION",
      correlationId: request.correlationId,
      ipAddress: request.ip,
      metadata: { githubLogin: ghUser.login }
    });

    reply.setCookie(SESSION_COOKIE_NAME, session.rawToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: deps.config.NODE_ENV === "production",
      path: "/",
      expires: session.expiresAt
    });

    return reply.redirect(`${deps.config.WEB_PUBLIC_URL}/dashboard`);
  });

  app.post("/api/v1/auth/logout", { preHandler: [deps.requireAuth] }, async (request, reply) => {
    const auth = request.auth as AuthContext;
    await deps.db
      .update(userSessions)
      .set({ revokedAt: new Date() })
      .where(eq(userSessions.id, auth.sessionId));

    reply.clearCookie(SESSION_COOKIE_NAME, { path: "/" });
    return { loggedOut: true };
  });
}
