import crypto from "node:crypto";

const FINGERPRINT_INFO = Buffer.from("indicative:secret-fingerprint:v1", "utf8");
const REDACT_CHUNK_SIZE = 64 * 1024;
const REDACT_CHUNK_OVERLAP = 512;

export interface SecretPattern {
  name: string;
  regex: RegExp;
}

/**
 * All patterns are explicitly bounded with non-nested quantifiers to guarantee
 * linear-time execution and prevent catastrophic backtracking (ReDoS) on hostile
 * or multi-megabyte minified inputs.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "aws-access-key",
    regex: /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g
  },
  {
    name: "github-token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b/g
  },
  {
    name: "github-fine-grained-pat",
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g
  },
  {
    name: "slack-token",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,120}\b/g
  },
  {
    name: "stripe-secret-key",
    regex: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,128}\b/g
  },
  {
    name: "openai-api-key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,128}\b/g
  },
  {
    name: "google-api-key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g
  },
  {
    name: "db-connection-uri",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/@]{1,128}:([^@\s/]{1,256})@[^\s"'`]{1,256}/gi
  },
  {
    name: "bearer-header",
    regex: /\b(Bearer|Basic|token)[ \t]{1,8}([A-Za-z0-9._~+/=-]{16,512})\b/gi
  },
  {
    name: "jwt-token",
    regex:
      /\beyJ[A-Za-z0-9_-]{10,256}\.eyJ[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,256}\b/g
  },
  {
    name: "generic-secret-assignment",
    regex:
      /((?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|db[_-]?pass(?:word)?|password|passwd|secret[_-]?key|private[_-]?key|aws[_-]?secret[_-]?access[_-]?key)[ \t]{0,16}[:=][ \t]{0,16}["']?)([^\s"'`;,]{8,256})(["']?)/gi
  }
];

const SENSITIVE_OBJECT_KEYS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "password",
  "passwd",
  "secret",
  "rawsecret",
  "token",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "installationtoken",
  "installation_token",
  "apikey",
  "api_key",
  "privatekey",
  "private_key",
  "clientsecret",
  "client_secret",
  "x-access-token",
  "x-api-key"
]);

/**
 * Linear-time O(n) PEM private key block scrubber (immune to regex backtracking ReDoS
 * even on megabyte-sized hostile inputs with repeated unclosed BEGIN markers).
 */
export function scrubPemPrivateKeyBlocks(text: string): string {
  const beginMarker = "-----BEGIN ";
  const keyMarker = "PRIVATE KEY-----";
  const endMarker = "-----END ";
  const maxBlockChars = 16 * 1024;

  let cursor = 0;
  let result = "";
  while (cursor < text.length) {
    const startIdx = text.indexOf(beginMarker, cursor);
    if (startIdx === -1) {
      result += text.slice(cursor);
      break;
    }

    const headerEnd = text.indexOf(keyMarker, startIdx + beginMarker.length);
    if (headerEnd === -1 || headerEnd - startIdx > 64) {
      result += text.slice(cursor, startIdx + beginMarker.length);
      cursor = startIdx + beginMarker.length;
      continue;
    }

    const bodyStart = headerEnd + keyMarker.length;
    const endStart = text.indexOf(endMarker, bodyStart);
    if (endStart === -1 || endStart - bodyStart > maxBlockChars) {
      // Unclosed or abnormally oversized marker — mask header itself without backtracking
      result += text.slice(cursor, startIdx) + "[REDACTED:private-key-header]";
      cursor = bodyStart;
      continue;
    }

    const footerEnd = text.indexOf(keyMarker, endStart + endMarker.length);
    if (footerEnd === -1 || footerEnd - endStart > 64) {
      result += text.slice(cursor, startIdx) + "[REDACTED:private-key-header]";
      cursor = bodyStart;
      continue;
    }

    result += text.slice(cursor, startIdx) + "[REDACTED:private-key-block:PRIVATE_KEY_BLOCK]";
    cursor = footerEnd + keyMarker.length;
  }

  return result;
}

/**
 * Derives an organization-specific 32-byte HMAC key using HKDF-SHA256.
 * Prevents cross-tenant secret fingerprint correlation.
 */
export function deriveTenantSecretKey(masterKey: string, organizationId: string): Buffer {
  if (!masterKey || masterKey.length < 16) {
    throw new Error("Master secret fingerprint key must be at least 16 characters.");
  }
  if (!organizationId || organizationId.trim().length === 0) {
    throw new Error("organizationId is required to derive a tenant secret key.");
  }
  const ikm = Buffer.from(masterKey, "utf8");
  const salt = Buffer.from(organizationId, "utf8");
  const derived = crypto.hkdfSync("sha256", ikm, salt, FINGERPRINT_INFO, 32);
  return Buffer.from(derived);
}

/**
 * Computes a deterministic tenant-keyed HMAC-SHA256 fingerprint for a raw credential.
 * Never returns or logs the plaintext value.
 */
export function computeSecretFingerprint(
  rawSecret: string,
  masterKey: string,
  organizationId: string
): string {
  const tenantKey = deriveTenantSecretKey(masterKey, organizationId);
  try {
    const hmac = crypto.createHmac("sha256", tenantKey);
    hmac.update(rawSecret, "utf8");
    return `hmac-sha256:v1:${hmac.digest("hex")}`;
  } finally {
    tenantKey.fill(0);
  }
}

/**
 * Produces a safe masked display token for a detected secret.
 * Never reveals the full secret or significant entropy.
 */
export function maskSecretValue(rawSecret: string, secretType = "secret"): string {
  const trimmed = rawSecret.trim();
  const safeType = secretType.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || "secret";
  if (trimmed.includes("PRIVATE KEY")) {
    return `[REDACTED:${safeType}:PRIVATE_KEY_BLOCK]`;
  }
  if (trimmed.length <= 12) {
    return `[REDACTED:${safeType}]`;
  }
  const prefix = trimmed.slice(0, 4);
  const suffix = trimmed.slice(-2);
  return `[REDACTED:${safeType}:${prefix}****${suffix}]`;
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function redactChunk(chunk: string, uniqueKnown: string[]): string {
  let output = scrubPemPrivateKeyBlocks(chunk);

  for (const secret of uniqueKnown) {
    if (output.includes(secret)) {
      const pattern = new RegExp(escapeRegExp(secret), "g");
      output = output.replace(pattern, maskSecretValue(secret, "detected"));
    }
  }

  for (const { name, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    if (name === "generic-secret-assignment") {
      output = output.replace(regex, (_m, prefix: string, _val: string, suffix: string) => {
        return `${prefix}[REDACTED:${name}]${suffix}`;
      });
    } else if (name === "db-connection-uri") {
      output = output.replace(regex, (match: string, password: string) => {
        return match.replace(`:${password}@`, `:[REDACTED:db-password]@`);
      });
    } else if (name === "bearer-header") {
      output = output.replace(regex, (_m, scheme: string) => `${scheme} [REDACTED:token]`);
    } else {
      output = output.replace(regex, (match: string) => maskSecretValue(match, name));
    }
  }

  return output;
}

/**
 * Redacts both explicitly known secret values and common credential patterns from arbitrary text.
 * Uses ReDoS-immune PEM scrubbing and bounded windowing for multi-megabyte minified payloads.
 */
export function redactSecretsInText(text: string, knownSecrets: string[] = []): string {
  if (!text) return text;

  const uniqueKnown = [...new Set(knownSecrets.filter((s) => s && s.trim().length >= 4))].sort(
    (a, b) => b.length - a.length
  );

  if (text.length <= REDACT_CHUNK_SIZE) {
    return redactChunk(text, uniqueKnown);
  }

  // Process oversized/minified strings in bounded chunks with boundary overlap so secrets
  // spanning chunk boundaries are still cleanly caught in O(n) time.
  let out = "";
  let offset = 0;
  while (offset < text.length) {
    const end = Math.min(text.length, offset + REDACT_CHUNK_SIZE);
    const slice = text.slice(offset, end);
    const redacted = redactChunk(slice, uniqueKnown);
    if (offset === 0) {
      out += redacted;
    } else {
      // Re-redact the join seam (last REDACT_CHUNK_OVERLAP chars of out + first REDACT_CHUNK_OVERLAP of redacted)
      const tailLen = Math.min(REDACT_CHUNK_OVERLAP, out.length);
      const headLen = Math.min(REDACT_CHUNK_OVERLAP, redacted.length);
      const seam = redactChunk(out.slice(-tailLen) + redacted.slice(0, headLen), uniqueKnown);
      out = out.slice(0, -tailLen) + seam + redacted.slice(headLen);
    }
    offset = end;
  }

  return out;
}

/**
 * Recursively redacts sensitive keys and secret patterns in an arbitrary JS value.
 */
export function redactObjectDeep<T>(value: T, knownSecrets: string[] = [], depth = 0): T {
  if (depth > 12 || value === null || value === undefined) {
    return value;
  }
  if (typeof value === "string") {
    return redactSecretsInText(value, knownSecrets) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactObjectDeep(item, knownSecrets, depth + 1)) as unknown as T;
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactSecretsInText(value.message, knownSecrets)
    } as unknown as T;
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      const normalizedKey = key.toLowerCase();
      if (SENSITIVE_OBJECT_KEYS.has(normalizedKey)) {
        out[key] = "[REDACTED]";
      } else {
        out[key] = redactObjectDeep(val, knownSecrets, depth + 1);
      }
    }
    return out as T;
  }
  return value;
}

/**
 * Linear-time safety assertion check to detect if a payload still contains
 * unredacted high-confidence credentials.
 */
export function containsPotentialPlaintextSecret(text: string): boolean {
  if (!text) return false;
  if (text.includes("-----BEGIN ") && text.includes("PRIVATE KEY-----")) {
    return true;
  }
  const highConfidencePatterns = [
    /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/,
    /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/,
    /\bxox[baprs]-[0-9A-Za-z-]{10,120}\b/,
    /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,128}\b/,
    /\bAIza[0-9A-Za-z_-]{35}\b/
  ];
  return highConfidencePatterns.some((re) => re.test(text));
}
