import path from "node:path";
import { eq } from "drizzle-orm";
import { loadConfig } from "@indicative/config";
import {
  createPostgresConnection,
  runMigrations,
  type DatabaseConnection
} from "./client.js";
import {
  users,
  organizations,
  organizationMembers,
  projects,
  projectRepositories,
  securityPolicies,
  scannerMetadata
} from "./schema.js";

export interface SeedResult {
  demoUserId: string;
  demoOrgId: string;
  demoProjectId: string;
  demoRepoId: string;
}

export async function seedDatabase(
  conn: DatabaseConnection,
  fixtureRepoPath?: string
): Promise<SeedResult> {
  const db = conn.db;

  // 1. Seed canonical scanner metadata
  const defaultScanners = [
    {
      scanner: "semgrep",
      version: "1.186.0",
      rulesetVersion: "indicative-sast-v1.0.0",
      license: "LGPL-2.1",
      capabilities: ["sast"],
      healthy: true
    },
    {
      scanner: "trivy",
      version: "0.76.2",
      rulesetVersion: "trivy-offline-db-v2",
      license: "Apache-2.0",
      capabilities: ["sca", "misconfiguration"],
      healthy: true
    },
    {
      scanner: "gitleaks",
      version: "8.30.1",
      rulesetVersion: "gitleaks-v8-default",
      license: "MIT",
      capabilities: ["secrets"],
      healthy: true
    },
    {
      scanner: "cicd-github-actions",
      version: "1.0.0",
      rulesetVersion: "indicative-cicd-gha-v1.0.0",
      license: "Apache-2.0",
      capabilities: ["cicd"],
      healthy: true
    },
    {
      scanner: "cloud-identity-iam",
      version: "1.0.0",
      rulesetVersion: "indicative-cloud-iam-v1.0.0",
      license: "Apache-2.0",
      capabilities: ["cloud-identity"],
      healthy: true
    }
  ];

  for (const s of defaultScanners) {
    await db
      .insert(scannerMetadata)
      .values({
        scanner: s.scanner,
        version: s.version,
        rulesetVersion: s.rulesetVersion,
        license: s.license,
        capabilities: s.capabilities,
        healthy: s.healthy,
        lastHealthCheckAt: new Date()
      })
      .onConflictDoNothing();
  }

  // 2. Demo user (strictly tagged isDemoUser=true)
  const existingUsers = await db
    .select()
    .from(users)
    .where(eq(users.email, "demo@indicative.local"));

  let demoUserId = existingUsers[0]?.id;
  if (!demoUserId) {
    const [created] = await db
      .insert(users)
      .values({
        email: "demo@indicative.local",
        name: "Indicative Demo Developer",
        githubLogin: "indicative-demo",
        isDemoUser: true
      })
      .returning();
    demoUserId = created!.id;
  }

  // 3. Demo organization
  const existingOrgs = await db
    .select()
    .from(organizations)
    .where(eq(organizations.slug, "indicative-demo-org"));

  let demoOrgId = existingOrgs[0]?.id;
  if (!demoOrgId) {
    const [created] = await db
      .insert(organizations)
      .values({
        name: "Indicative Demo Workspace",
        slug: "indicative-demo-org",
        isDemo: true
      })
      .returning();
    demoOrgId = created!.id;
  }

  // 4. Org membership
  await db
    .insert(organizationMembers)
    .values({
      organizationId: demoOrgId,
      userId: demoUserId,
      role: "OWNER"
    })
    .onConflictDoNothing();

  // 5. Security policy
  await db
    .insert(securityPolicies)
    .values({
      organizationId: demoOrgId,
      maxRepoSizeMb: 250,
      maxConcurrentScans: 3,
      artifactRetentionDays: 30,
      allowAiAnalysis: true,
      requireVerificationOnRescan: true
    })
    .onConflictDoNothing();

  // 6. Demo project (clearly marked isDemo=true, uses controlled vulnerable fixture repo)
  const existingProjects = await db
    .select()
    .from(projects)
    .where(eq(projects.slug, "demo-vulnerable-app"));

  let demoProjectId = existingProjects[0]?.id;
  if (!demoProjectId) {
    const [created] = await db
      .insert(projects)
      .values({
        organizationId: demoOrgId,
        name: "Demo Vulnerable App (Fixture)",
        slug: "demo-vulnerable-app",
        description:
          "Controlled demonstration fixture repository containing dummy credentials and intentional SAST/SCA/IaC flaws for real scanner verification.",
        isDemo: true
      })
      .returning();
    demoProjectId = created!.id;
  }

  const existingRepos = await db
    .select()
    .from(projectRepositories)
    .where(eq(projectRepositories.projectId, demoProjectId));

  let demoRepoId = existingRepos[0]?.id;
  if (!demoRepoId) {
    const resolvedFixture =
      fixtureRepoPath ?? path.resolve(process.cwd(), "tests/fixtures/vulnerable-app");
    const [created] = await db
      .insert(projectRepositories)
      .values({
        organizationId: demoOrgId,
        projectId: demoProjectId,
        provider: "LOCAL_FIXTURE",
        fullName: "indicative-demo/vulnerable-app",
        defaultBranch: "main",
        isPrivate: false,
        localFixturePath: resolvedFixture
      })
      .returning();
    demoRepoId = created!.id;
  }

  return { demoUserId, demoOrgId, demoProjectId, demoRepoId };
}

// Run when invoked directly via tsx src/seed.ts
const isMain = process.argv[1]?.endsWith("seed.ts") || process.argv[1]?.endsWith("seed.js");
if (isMain) {
  const config = loadConfig();
  createPostgresConnection(config.DATABASE_URL)
    .then(async (conn) => {
      try {
        await runMigrations(conn);
        const result = await seedDatabase(conn);
        console.log("[indicative/database] Seed complete:", result);
      } finally {
        await conn.close();
      }
    })
    .catch((err) => {
      console.error("[indicative/database] Seed failed:", err);
      process.exit(1);
    });
}
