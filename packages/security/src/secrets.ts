import crypto from "node:crypto";

const FINGERPRINT_INFO = Buffer.from("indicative:secret-fingerprint:v1", "utf8");

export interface SecretPattern {
  name: string;
  regex: RegExp;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "private-key-block",
    regex:
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g
  },
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
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/@]+:([^@\s/]+)@[^\s"'`]+/gi
  },
  {
    name: "bearer-header",
    regex: /\b(Bearer|Basic|token)\s+[A-Za-z0-9._~+/=-]{16,}\b/gi
  },
  {
    name: "jwt-token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g
  },
  {
    name: "generic-secret-assignment",
    regex:
      /((?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|db[_-]?pass(?:word)?|password|passwd|secret[_-]?key|private[_-]?key|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?)([^\s"'`;,]{8,})(["']?)/gi
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

/**
 * Redacts both explicitly known secret values and common credential patterns from arbitrary text.
 */
export function redactSecretsInText(text: string, knownSecrets: string[] = []): string {
  if (!text) return text;
  let output = text;

  // 1. Scrub explicit raw secret strings first (longest first to avoid partial remnants)
  const uniqueKnown = [...new Set(knownSecrets.filter((s) => s && s.trim().length >= 4))].sort(
    (a, b) => b.length - a.length
  );
  for (const secret of uniqueKnown) {
    const pattern = new RegExp(escapeRegExp(secret), "g");
    output = output.replace(pattern, maskSecretValue(secret, "detected"));
  }

  // 2. Scrub structural secret patterns
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
 * Safety assertion check to detect if a payload still contains unredacted high-confidence credentials.
 */
export function containsPotentialPlaintextSecret(text: string): boolean {
  if (!text) return false;
  const highConfidencePatterns = [
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+-----END [A-Z0-9 ]*PRIVATE KEY-----/,
    /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/,
    /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/,
    /\bxox[baprs]-[0-9A-Za-z-]{10,120}\b/,
    /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,128}\b/,
    /\bAIza[0-9A-Za-z_-]{35}\b/
  ];
  return highConfidencePatterns.some((re) => re.test(text));
}
