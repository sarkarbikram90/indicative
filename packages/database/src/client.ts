import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { drizzle as drizzlePg, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { PGlite } from "@electric-sql/pglite";
import { drizzle as drizzlePglite, type PgliteDatabase } from "drizzle-orm/pglite";
import * as schema from "./schema.js";

export type Database = NodePgDatabase<typeof schema> | PgliteDatabase<typeof schema>;

export interface DatabaseConnection {
  db: Database;
  driver: "postgres" | "pglite";
  executeSql(sqlText: string): Promise<void>;
  healthCheck(): Promise<{ ok: boolean; driver: string; latencyMs: number; error?: string }>;
  close(): Promise<void>;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS_DIR = path.resolve(__dirname, "../migrations");

export async function createPostgresConnection(
  databaseUrl: string
): Promise<DatabaseConnection> {
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 15,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000
  });
  const db = drizzlePg(pool, { schema });

  return {
    db,
    driver: "postgres",
    async executeSql(sqlText: string) {
      await pool.query(sqlText);
    },
    async healthCheck() {
      const start = Date.now();
      try {
        await pool.query("SELECT 1");
        return { ok: true, driver: "postgres", latencyMs: Date.now() - start };
      } catch (err) {
        return {
          ok: false,
          driver: "postgres",
          latencyMs: Date.now() - start,
          error: (err as Error).message
        };
      }
    },
    async close() {
      await pool.end();
    }
  };
}

/**
 * Creates a real embedded PostgreSQL 16 instance via PGlite.
 * Ideal for self-contained automated tests (integration, security, E2E) and
 * zero-dependency local demo execution.
 */
export async function createEmbeddedPostgresConnection(
  dataDir?: string
): Promise<DatabaseConnection> {
  if (dataDir) {
    await fs.mkdir(path.resolve(dataDir), { recursive: true });
  }
  const client = dataDir ? new PGlite(dataDir) : new PGlite();
  await client.waitReady;
  const db = drizzlePglite(client, { schema });

  return {
    db,
    driver: "pglite",
    async executeSql(sqlText: string) {
      await client.exec(sqlText);
    },
    async healthCheck() {
      const start = Date.now();
      try {
        await client.query("SELECT 1");
        return { ok: true, driver: "pglite", latencyMs: Date.now() - start };
      } catch (err) {
        return {
          ok: false,
          driver: "pglite",
          latencyMs: Date.now() - start,
          error: (err as Error).message
        };
      }
    },
    async close() {
      await client.close();
    }
  };
}

export async function runMigrations(conn: DatabaseConnection): Promise<string[]> {
  const files = (await fs.readdir(MIGRATIONS_DIR))
    .filter((f) => f.endsWith(".sql"))
    .sort();

  const applied: string[] = [];
  for (const file of files) {
    const sqlText = await fs.readFile(path.join(MIGRATIONS_DIR, file), "utf8");
    // Strip pgcrypto extension line for pglite compatibility (pglite provides gen_random_uuid natively)
    const normalizedSql =
      conn.driver === "pglite"
        ? sqlText.replace(/CREATE EXTENSION IF NOT EXISTS "pgcrypto";/gi, "")
        : sqlText;
    await conn.executeSql(normalizedSql);
    await conn.executeSql(
      `INSERT INTO schema_migrations (version) VALUES ('${file.replace(/'/g, "''")}') ON CONFLICT (version) DO NOTHING;`
    );
    applied.push(file);
  }
  return applied;
}
