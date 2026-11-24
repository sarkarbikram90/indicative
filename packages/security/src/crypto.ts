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

/**
 * Computes GitHub-compatible X-Hub-Signature-256 HMAC header ("sha256=<hex>").
 */
export function computeGitHubWebhookSignature(
  rawBody: Buffer | string,
  secret: string
): string {
  const digest = crypto
    .createHmac("sha256", secret)
    .update(typeof rawBody === "string" ? Buffer.from(rawBody, "utf8") : rawBody)
    .digest("hex");
  return `sha256=${digest}`;
}

/**
 * Verifies GitHub webhook X-Hub-Signature-256 in constant time over the exact raw request body.
 */
export function verifyGitHubWebhookSignature(
  rawBody: Buffer | string,
  signatureHeader: string | undefined,
  secret: string
): boolean {
  if (!signatureHeader || !secret || secret.trim().length === 0) return false;
  if (!signatureHeader.startsWith("sha256=")) return false;
  const expected = computeGitHubWebhookSignature(rawBody, secret);
  const providedBuf = Buffer.from(signatureHeader.trim(), "utf8");
  const expectedBuf = Buffer.from(expected, "utf8");
  return providedBuf.length === expectedBuf.length && crypto.timingSafeEqual(providedBuf, expectedBuf);
}

function deriveTenantEncryptionKey(masterKey: string, organizationId: string): Buffer {
  if (!masterKey || masterKey.length < 32) {
    throw new Error("SECURITY_VIOLATION: Master key must be at least 32 characters.");
  }
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(masterKey, "utf8"),
      Buffer.from(organizationId, "utf8"),
      Buffer.from("indicative:tenant-credentials:v1", "utf8"),
      32
    )
  );
}

/**
 * Encrypts tenant integration credentials (e.g., Slack webhook URLs, Jira tokens)
 * at rest using tenant-derived HKDF-SHA256 + AES-256-GCM.
 */
export function encryptTenantSecret(
  plaintext: string,
  organizationId: string,
  masterKey: string
): string {
  const key = deriveTenantEncryptionKey(masterKey, organizationId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(organizationId, "utf8"));
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

/**
 * Decrypts a value produced by encryptTenantSecret for the matching organizationId.
 */
export function decryptTenantSecret(
  ciphertext: string,
  organizationId: string,
  masterKey: string
): string {
  if (!ciphertext.startsWith("enc:v1:")) {
    throw new Error("INVALID_ENCRYPTED_SECRET: Unsupported ciphertext format.");
  }
  const parts = ciphertext.slice("enc:v1:".length).split(".");
  if (parts.length !== 3) {
    throw new Error("INVALID_ENCRYPTED_SECRET: Malformed ciphertext envelope.");
  }
  const [ivB64, tagB64, dataB64] = parts as [string, string, string];
  const key = deriveTenantEncryptionKey(masterKey, organizationId);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64url"));
  decipher.setAAD(Buffer.from(organizationId, "utf8"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final()
  ]);
  return decrypted.toString("utf8");
}
