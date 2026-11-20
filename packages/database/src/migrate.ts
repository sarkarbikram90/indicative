import { loadConfig } from "@indicative/config";
import { createPostgresConnection, runMigrations } from "./client.js";

async function main() {
  const config = loadConfig();
  const conn = await createPostgresConnection(config.DATABASE_URL);
  try {
    const applied = await runMigrations(conn);
    console.log(`[indicative/database] Applied migrations: ${applied.join(", ")}`);
  } finally {
    await conn.close();
  }
}

main().catch((err) => {
  console.error("[indicative/database] Migration failed:", err);
  process.exit(1);
});
