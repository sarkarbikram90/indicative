import { exec } from "node:child_process";
import crypto from "node:crypto";

// Intentionally vulnerable SAST fixture (JavaScript) for Indicative regression testing.
// Contains: SQL Injection, Command Injection, Hardcoded JWT secret, Weak Hash, Unsafe eval, Disabled TLS.

export function findUserUnsafe(db: { query: (sql: string) => Promise<unknown> }, userId: string) {
  // Expected: indicative.js.sql-injection.template-query
  return db.query(`SELECT id, email FROM users WHERE id = '${userId}'`);
}

export function pingHostUnsafe(host: string) {
  // Expected: indicative.js.command-injection.child-process-exec
  return exec("ping -c 1 " + host);
}

export function weakPasswordDigest(input: string): string {
  // Expected: indicative.js.insecure-crypto.weak-hash
  return crypto.createHash("md5").update(input).digest("hex");
}

export function evalConfigUnsafe(expr: string) {
  // Expected: indicative.js.unsafe-eval
  return eval(expr);
}

export const insecureTlsAgentConfig = {
  // Expected: indicative.js.insecure-auth.tls-disabled
  rejectUnauthorized: false
};

export function signDemoToken(jwt: { sign: (p: object, s: string) => string }, userId: string) {
  // Expected: indicative.js.hardcoded-jwt-secret
  return jwt.sign({ sub: userId }, "hardcoded-insecure-jwt-signing-secret-fixture");
}
