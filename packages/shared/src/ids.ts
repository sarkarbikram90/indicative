import crypto from "node:crypto";

export function generateCorrelationId(): string {
  return `cor_${crypto.randomBytes(12).toString("hex")}`;
}

export function generateId(): string {
  return crypto.randomUUID();
}
