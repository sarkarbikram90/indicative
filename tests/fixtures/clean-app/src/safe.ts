import crypto from "node:crypto";

// Clean TypeScript fixture repository — should produce ZERO SAST findings.

export function findUserSafe(
  db: { query: (sql: string, params: unknown[]) => Promise<unknown> },
  userId: string
) {
  return db.query("SELECT id, email FROM users WHERE id = $1", [userId]);
}

export function strongDigest(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

// False-positive secret example: clearly benign placeholder values
export const EXAMPLE_CONFIG = {
  APP_ENV: "development",
  API_KEY_PLACEHOLDER: "replace-me-in-env",
  DOCS_URL: "https://example.com/docs"
};
