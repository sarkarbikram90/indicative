import net from "node:net";

const GITHUB_SLUG_REGEX = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function validateGitHubRepositorySlug(fullName: string): {
  owner: string;
  repo: string;
  fullName: string;
} {
  const trimmed = fullName.trim();
  if (!GITHUB_SLUG_REGEX.test(trimmed) || trimmed.includes("..")) {
    throw new Error(
      `INVALID_REPOSITORY_SLUG: Repository "${trimmed}" must match owner/repo without traversal.`
    );
  }
  const [owner, repo] = trimmed.split("/") as [string, string];
  if (!owner || !repo || owner === "." || repo === ".") {
    throw new Error(`INVALID_REPOSITORY_SLUG: Invalid owner/repo "${trimmed}".`);
  }
  return { owner, repo, fullName: `${owner}/${repo}` };
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) {
    const parts = ip.split(".").map((n) => Number(n));
    const [a = 0, b = 0] = parts;
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (kind === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA
    if (lower.startsWith("fe80")) return true; // link-local
    if (lower.startsWith("::ffff:")) {
      return isPrivateOrReservedIp(lower.replace("::ffff:", ""));
    }
    return false;
  }
  return false;
}

export interface OutboundUrlPolicy {
  allowedHosts: string[];
  allowHttpInTest?: boolean;
}

/**
 * Validates outbound URLs against SSRF, cloud metadata endpoints, embedded credentials,
 * non-HTTPS schemes, and host allowlists.
 */
export function validateAllowedOutboundUrl(
  rawUrl: string,
  policy: OutboundUrlPolicy
): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("SSRF_BLOCKED: Malformed URL.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("SSRF_BLOCKED: URL must not contain embedded credentials.");
  }

  const allowedProtocols = policy.allowHttpInTest ? ["https:", "http:"] : ["https:"];
  if (!allowedProtocols.includes(parsed.protocol)) {
    throw new Error(`SSRF_BLOCKED: Disallowed URL scheme "${parsed.protocol}".`);
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".internal") ||
    hostname === "metadata.google.internal"
  ) {
    if (!policy.allowedHosts.includes(hostname)) {
      throw new Error(`SSRF_BLOCKED: Internal hostname "${hostname}" is not allowed.`);
    }
  }

  if (net.isIP(hostname) && isPrivateOrReservedIp(hostname)) {
    if (!policy.allowedHosts.includes(hostname)) {
      throw new Error(`SSRF_BLOCKED: Private or reserved IP "${hostname}" is not allowed.`);
    }
  }

  if (
    policy.allowedHosts.length > 0 &&
    !policy.allowedHosts.some((h) => h.toLowerCase() === hostname)
  ) {
    throw new Error(`SSRF_BLOCKED: Host "${hostname}" is not in the allowlist.`);
  }

  return parsed;
}
