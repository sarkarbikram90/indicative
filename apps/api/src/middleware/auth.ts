import type { FastifyRequest, FastifyReply } from "fastify";
import { and, eq, gt, isNull } from "drizzle-orm";
import type { AppConfig } from "@indicative/config";
import {
  organizationMembers,
  organizations,
  userSessions,
  users,
  type Database
} from "@indicative/database";
import {
  generateCsrfToken,
  hashSessionToken,
  verifyCsrfToken
} from "@indicative/security";
import { ForbiddenError, UnauthorizedError } from "@indicative/shared";

export const SESSION_COOKIE_NAME = "indicative_session";

export interface AuthContext {
  userId: string;
  email: string;
  name: string;
  githubLogin: string | null;
  isDemoUser: boolean;
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  role: string;
  sessionId: string;
  sessionTokenHash: string;
  csrfToken: string;
  authMethod: "cookie" | "bearer";
}

declare module "fastify" {
  interface FastifyRequest {
    correlationId: string;
    auth?: AuthContext;
  }
}

export function extractRawSessionToken(request: FastifyRequest): {
  token: string;
  method: "cookie" | "bearer";
} | null {
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    if (token.length >= 16) {
      return { token, method: "bearer" };
    }
  }
  const cookieToken = request.cookies?.[SESSION_COOKIE_NAME];
  if (cookieToken && cookieToken.length >= 16) {
    return { token: cookieToken, method: "cookie" };
  }
  return null;
}

export function createAuthMiddleware(db: Database, config: AppConfig) {
  return async function requireAuth(
    request: FastifyRequest,
    _reply: FastifyReply
  ): Promise<void> {
    const extracted = extractRawSessionToken(request);
    if (!extracted) {
      throw new UnauthorizedError("Authentication session missing.");
    }

    const tokenHash = hashSessionToken(extracted.token);
    const now = new Date();

    const rows = await db
      .select({
        sessionId: userSessions.id,
        userId: users.id,
        email: users.email,
        name: users.name,
        githubLogin: users.githubLogin,
        isDemoUser: users.isDemoUser,
        organizationId: organizations.id,
        organizationName: organizations.name,
        organizationSlug: organizations.slug,
        role: organizationMembers.role
      })
      .from(userSessions)
      .innerJoin(users, eq(userSessions.userId, users.id))
      .innerJoin(organizations, eq(userSessions.organizationId, organizations.id))
      .innerJoin(
        organizationMembers,
        and(
          eq(organizationMembers.organizationId, organizations.id),
          eq(organizationMembers.userId, users.id)
        )
      )
      .where(
        and(
          eq(userSessions.tokenHash, tokenHash),
          isNull(userSessions.revokedAt),
          gt(userSessions.expiresAt, now)
        )
      )
      .limit(1);

    const record = rows[0];
    if (!record) {
      throw new UnauthorizedError("Invalid or expired session.");
    }

    // Enforce CSRF token on cookie-authenticated state-changing requests
    const isMutating = ["POST", "PATCH", "PUT", "DELETE"].includes(request.method);
    if (extracted.method === "cookie" && isMutating) {
      const providedCsrf = request.headers["x-csrf-token"];
      const csrfStr = Array.isArray(providedCsrf) ? providedCsrf[0] : providedCsrf;
      if (!verifyCsrfToken(csrfStr, tokenHash, config.SESSION_SECRET)) {
        throw new ForbiddenError("Invalid or missing CSRF token.");
      }
    }

    request.auth = {
      userId: record.userId,
      email: record.email,
      name: record.name,
      githubLogin: record.githubLogin,
      isDemoUser: record.isDemoUser,
      organizationId: record.organizationId,
      organizationName: record.organizationName,
      organizationSlug: record.organizationSlug,
      role: record.role,
      sessionId: record.sessionId,
      sessionTokenHash: tokenHash,
      csrfToken: generateCsrfToken(tokenHash, config.SESSION_SECRET),
      authMethod: extracted.method
    };
  };
}
