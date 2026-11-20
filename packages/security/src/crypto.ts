import crypto from "node:crypto";

export function generateSecureToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function hashSessionToken(rawToken: string): string {
  return crypto.createHash("sha256").update(rawToken, "utf8").digest("hex");
}

export function signStateToken(
  payload: Record<string, string | number>,
  secret: string,
  ttlSeconds = 600
): string {
  const envelope = {
    ...payload,
    exp: Math.floor(Date.now() / 1000) + ttlSeconds,
    nonce: crypto.randomBytes(12).toString("hex")
  };
  const encoded = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
}

export function verifyStateToken<T extends Record<string, unknown>>(
  token: string,
  secret: string
): T | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [encoded, providedSig] = parts as [string, string];
  const expectedSig = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");

  const providedBuf = Buffer.from(providedSig, "utf8");
  const expectedBuf = Buffer.from(expectedSig, "utf8");
  if (
    providedBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(providedBuf, expectedBuf)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as T & {
      exp?: number;
    };
    if (typeof parsed.exp !== "number" || parsed.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function generateCsrfToken(sessionTokenHash: string, secret: string): string {
  return crypto
    .createHmac("sha256", secret)
    .update(`csrf:v1:${sessionTokenHash}`)
    .digest("base64url");
}

export function verifyCsrfToken(
  providedToken: string | undefined,
  sessionTokenHash: string,
  secret: string
): boolean {
  if (!providedToken) return false;
  const expected = generateCsrfToken(sessionTokenHash, secret);
  const a = Buffer.from(providedToken, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
