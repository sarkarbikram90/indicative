import {
  pgTable,
  uuid,
  text,
  boolean,
  integer,
  doublePrecision,
  timestamp,
  jsonb,
  uniqueIndex,
  index
} from "drizzle-orm/pg-core";

// ============================================================================
// 1. Identity & Organization
// ============================================================================

export const users = pgTable(
  "users",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    email: text("email").notNull(),
    name: text("name").notNull(),
    githubUserId: text("github_user_id"),
    githubLogin: text("github_login"),
    avatarUrl: text("avatar_url"),
    isDemoUser: boolean("is_demo_user").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("users_email_idx").on(table.email),
    uniqueIndex("users_github_user_id_idx").on(table.githubUserId)
  ]
);

export const organizations = pgTable(
  "organizations",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    name: text("name").notNull(),
    slug: text("slug").notNull(),
    isDemo: boolean("is_demo").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [uniqueIndex("organizations_slug_idx").on(table.slug)]
);

export const organizationMembers = pgTable(
  "organization_members",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    role: text("role").notNull().default("OWNER"), // OWNER | MEMBER
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("org_members_org_user_idx").on(table.organizationId, table.userId),
    index("org_members_user_idx").on(table.userId)
  ]
);

export const userSessions = pgTable(
  "user_sessions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("user_sessions_token_hash_idx").on(table.tokenHash),
    index("user_sessions_user_idx").on(table.userId)
  ]
);

// ============================================================================
// 2. Integrations & Projects
// ============================================================================

export const integrations = pgTable(
  "integrations",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(), // GITHUB_APP
    status: text("status").notNull().default("ACTIVE"), // ACTIVE | REVOKED | ERROR
    configMetadata: jsonb("config_metadata").$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [index("integrations_org_idx").on(table.organizationId)]
);

export const githubInstallations = pgTable(
  "github_installations",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    integrationId: uuid("integration_id").references(() => integrations.id, {
      onDelete: "set null"
    }),
    installationId: integer("installation_id").notNull(),
    accountLogin: text("account_login").notNull(),
    accountType: text("account_type").notNull().default("User"),
    permissions: jsonb("permissions").$type<Record<string, string>>().notNull().default({}),
    status: text("status").notNull().default("ACTIVE"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("gh_installations_org_install_idx").on(
      table.organizationId,
      table.installationId
    ),
    index("gh_installations_org_idx").on(table.organizationId)
  ]
);

export const projects = pgTable(
  "projects",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    slug: text("slug").notNull(),
    description: text("description"),
    isDemo: boolean("is_demo").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("projects_org_slug_idx").on(table.organizationId, table.slug),
    index("projects_org_idx").on(table.organizationId)
  ]
);

export const projectRepositories = pgTable(
  "project_repositories",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    githubInstallationId: uuid("github_installation_id").references(
      () => githubInstallations.id,
      { onDelete: "set null" }
    ),
    provider: text("provider").notNull().default("GITHUB"), // GITHUB | LOCAL_FIXTURE
    externalRepoId: text("external_repo_id"),
    fullName: text("full_name").notNull(), // owner/repo
    defaultBranch: text("default_branch").notNull().default("main"),
    isPrivate: boolean("is_private").notNull().default(true),
    localFixturePath: text("local_fixture_path"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("project_repos_project_idx").on(table.projectId),
    index("project_repos_org_idx").on(table.organizationId)
  ]
);

// ============================================================================
// 3. Scanning & Artifacts
// ============================================================================

export const scans = pgTable(
  "scans",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    repositoryId: uuid("repository_id")
      .notNull()
      .references(() => projectRepositories.id, { onDelete: "cascade" }),
    initiatedByUserId: uuid("initiated_by_user_id").references(() => users.id, {
      onDelete: "set null"
    }),
    idempotencyKey: text("idempotency_key"),
    triggerSource: text("trigger_source").notNull().default("MANUAL"),
    triggerMetadata: jsonb("trigger_metadata").$type<Record<string, unknown>>().notNull().default({}),
    branch: text("branch").notNull().default("main"),
    commitSha: text("commit_sha"),
    commitMessage: text("commit_message"),
    status: text("status").notNull().default("QUEUED"),
    requestedScanners: jsonb("requested_scanners")
      .$type<string[]>()
      .notNull()
      .default(["semgrep", "trivy", "gitleaks", "cicd-github-actions"]),
    runAiAnalysis: boolean("run_ai_analysis").notNull().default(false),
    isDemoScan: boolean("is_demo_scan").notNull().default(false),
    summaryCounts: jsonb("summary_counts").$type<Record<string, number>>().notNull().default({}),
    comparisonSummary: jsonb("comparison_summary").$type<Record<string, unknown>>(),
    limitations: jsonb("limitations").$type<Array<{ code: string; message: string; scopeAffected?: string }>>().notNull().default([]),
    failureReason: text("failure_reason"),
    correlationId: text("correlation_id"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    durationMs: integer("duration_ms"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("scans_org_project_created_idx").on(
      table.organizationId,
      table.projectId,
      table.createdAt
    ),
    index("scans_org_status_idx").on(table.organizationId, table.status),
    uniqueIndex("scans_project_idempotency_idx").on(table.projectId, table.idempotencyKey)
  ]
);

export const scannerRuns = pgTable(
  "scanner_runs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    scanId: uuid("scan_id")
      .notNull()
      .references(() => scans.id, { onDelete: "cascade" }),
    scanner: text("scanner").notNull(),
    scannerVersion: text("scanner_version").notNull(),
    rulesetVersion: text("ruleset_version"),
    status: text("status").notNull(), // SUCCESS | FAILED | TIMEOUT | CANCELLED | PARTIAL | UNAVAILABLE
    exitCode: integer("exit_code"),
    findingsCount: integer("findings_count").notNull().default(0),
    errorClass: text("error_class").notNull().default("NONE"),
    errorMessage: text("error_message"),
    limitations: jsonb("limitations").$type<Array<{ code: string; message: string; scopeAffected?: string }>>().notNull().default([]),
    resourceUsage: jsonb("resource_usage").$type<Record<string, number>>(),
    durationMs: integer("duration_ms").notNull().default(0),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("scanner_runs_scan_idx").on(table.scanId),
    index("scanner_runs_org_idx").on(table.organizationId)
  ]
);

export const scannerMetadata = pgTable(
  "scanner_metadata",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    scanner: text("scanner").notNull(),
    version: text("version").notNull(),
    rulesetVersion: text("ruleset_version"),
    license: text("license").notNull(),
    capabilities: jsonb("capabilities").$type<string[]>().notNull().default([]),
    lastHealthCheckAt: timestamp("last_health_check_at", { withTimezone: true }),
    healthy: boolean("healthy").notNull().default(false),
    details: jsonb("details").$type<Record<string, unknown>>().notNull().default({}),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [uniqueIndex("scanner_metadata_scanner_idx").on(table.scanner)]
);

export const scanArtifacts = pgTable(
  "scan_artifacts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    scanId: uuid("scan_id")
      .notNull()
      .references(() => scans.id, { onDelete: "cascade" }),
    artifactType: text("artifact_type").notNull(), // NORMALIZED_REPORT_JSON | SARIF | CSV
    storageKey: text("storage_key").notNull(),
    contentType: text("content_type").notNull(),
    sizeBytes: integer("size_bytes").notNull(),
    sha256: text("sha256").notNull(),
    redacted: boolean("redacted").notNull().default(true),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("scan_artifacts_scan_idx").on(table.scanId),
    index("scan_artifacts_expires_idx").on(table.expiresAt)
  ]
);

// ============================================================================
// 4. Findings & Lifecycle
// ============================================================================

export const findings = pgTable(
  "findings",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    fingerprint: text("fingerprint").notNull(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    latestScanId: uuid("latest_scan_id")
      .notNull()
      .references(() => scans.id, { onDelete: "cascade" }),
    scanner: text("scanner").notNull(),
    scannerVersion: text("scanner_version").notNull(),
    rulesetVersion: text("ruleset_version"),
    ruleId: text("rule_id").notNull(),
    category: text("category").notNull(), // SAST | SCA | SECRET | IAC
    title: text("title").notNull(),
    description: text("description").notNull(),
    severity: text("severity").notNull(), // CRITICAL | HIGH | MEDIUM | LOW | INFO | UNKNOWN
    originalSeverity: text("original_severity"),
    confidence: text("confidence").notNull(), // HIGH | MEDIUM | LOW | UNKNOWN
    riskPriority: text("risk_priority").notNull().default("MEDIUM"),
    riskRationale: jsonb("risk_rationale").$type<string[]>().notNull().default([]),
    filePath: text("file_path"),
    lineStart: integer("line_start"),
    lineEnd: integer("line_end"),
    packageName: text("package_name"),
    installedVersion: text("installed_version"),
    fixedVersion: text("fixed_version"),
    cve: text("cve"),
    cvssScore: doublePrecision("cvss_score"),
    secretType: text("secret_type"),
    secretFingerprint: text("secret_fingerprint"), // Tenant-keyed HMAC-SHA256 only; NEVER plaintext
    secretValidity: text("secret_validity"), // UNKNOWN | NOT_VERIFIED
    commitSha: text("commit_sha"),
    commitTimestamp: timestamp("commit_timestamp", { withTimezone: true }),
    exposureLocation: text("exposure_location"), // WORKING_TREE | GIT_HISTORY | BOTH
    remediation: text("remediation"),
    status: text("status").notNull().default("OPEN"),
    verificationState: text("verification_state").notNull().default("DETECTED"),
    occurrenceCount: integer("occurrence_count").notNull().default(1),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("findings_project_fingerprint_idx").on(table.projectId, table.fingerprint),
    index("findings_org_project_status_sev_idx").on(
      table.organizationId,
      table.projectId,
      table.status,
      table.severity
    ),
    index("findings_org_secret_fp_idx").on(table.organizationId, table.secretFingerprint),
    index("findings_latest_scan_idx").on(table.latestScanId)
  ]
);

export const findingOccurrences = pgTable(
  "finding_occurrences",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    findingId: uuid("finding_id")
      .notNull()
      .references(() => findings.id, { onDelete: "cascade" }),
    scanId: uuid("scan_id")
      .notNull()
      .references(() => scans.id, { onDelete: "cascade" }),
    filePath: text("file_path"),
    lineStart: integer("line_start"),
    lineEnd: integer("line_end"),
    commitSha: text("commit_sha"),
    commitTimestamp: timestamp("commit_timestamp", { withTimezone: true }),
    exposureLocation: text("exposure_location"),
    redactedSnippet: text("redacted_snippet"),
    detectedAt: timestamp("detected_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("finding_occurrences_finding_idx").on(table.findingId),
    index("finding_occurrences_scan_idx").on(table.scanId)
  ]
);

export const findingEvidence = pgTable(
  "finding_evidence",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    findingId: uuid("finding_id")
      .notNull()
      .references(() => findings.id, { onDelete: "cascade" }),
    scanId: uuid("scan_id")
      .notNull()
      .references(() => scans.id, { onDelete: "cascade" }),
    evidenceType: text("evidence_type").notNull(),
    label: text("label").notNull(),
    content: text("content").notNull(), // Always redacted
    filePath: text("file_path"),
    lineStart: integer("line_start"),
    lineEnd: integer("line_end"),
    commitSha: text("commit_sha"),
    referenceUrl: text("reference_url"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [index("finding_evidence_finding_idx").on(table.findingId)]
);

export const findingStatusHistory = pgTable(
  "finding_status_history",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    findingId: uuid("finding_id")
      .notNull()
      .references(() => findings.id, { onDelete: "cascade" }),
    fromStatus: text("from_status"),
    toStatus: text("to_status").notNull(),
    reason: text("reason").notNull(),
    changedByUserId: uuid("changed_by_user_id").references(() => users.id, {
      onDelete: "set null"
    }),
    changedBySystem: boolean("changed_by_system").notNull().default(false),
    scanId: uuid("scan_id").references(() => scans.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [index("finding_status_history_finding_idx").on(table.findingId)]
);

export const findingAiAnalyses = pgTable(
  "finding_ai_analyses",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    findingId: uuid("finding_id")
      .notNull()
      .references(() => findings.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    model: text("model").notNull(),
    promptVersion: text("prompt_version").notNull(),
    analysisJson: jsonb("analysis_json").$type<Record<string, unknown>>().notNull(),
    promptTokens: integer("prompt_tokens"),
    completionTokens: integer("completion_tokens"),
    totalTokens: integer("total_tokens"),
    latencyMs: integer("latency_ms").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [index("finding_ai_analyses_finding_idx").on(table.findingId)]
);

// ============================================================================
// 5. Governance & Audit
// ============================================================================

export const auditEvents = pgTable(
  "audit_events",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
    action: text("action").notNull(),
    resourceType: text("resource_type").notNull(),
    resourceId: text("resource_id"),
    correlationId: text("correlation_id"),
    ipAddress: text("ip_address"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("audit_events_org_created_idx").on(table.organizationId, table.createdAt)
  ]
);

export const securityPolicies = pgTable(
  "security_policies",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    maxRepoSizeMb: integer("max_repo_size_mb").notNull().default(250),
    maxConcurrentScans: integer("max_concurrent_scans").notNull().default(3),
    artifactRetentionDays: integer("artifact_retention_days").notNull().default(30),
    allowAiAnalysis: boolean("allow_ai_analysis").notNull().default(true),
    requireVerificationOnRescan: boolean("require_verification_on_rescan")
      .notNull()
      .default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [uniqueIndex("security_policies_org_idx").on(table.organizationId)]
);

// ============================================================================
// 6. Developer Workflow & Automation (Webhooks, Schedules, Notifications)
// ============================================================================

export const webhookDeliveries = pgTable(
  "webhook_deliveries",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    deliveryId: text("delivery_id").notNull(),
    provider: text("provider").notNull().default("GITHUB"),
    eventType: text("event_type").notNull(),
    action: text("action"),
    repositoryFullName: text("repository_full_name"),
    organizationId: uuid("organization_id").references(() => organizations.id, {
      onDelete: "set null"
    }),
    projectId: uuid("project_id").references(() => projects.id, { onDelete: "set null" }),
    scanId: uuid("scan_id").references(() => scans.id, { onDelete: "set null" }),
    signatureValid: boolean("signature_valid").notNull().default(false),
    status: text("status").notNull(), // ACCEPTED | IGNORED | REJECTED | DUPLICATE
    summary: text("summary"),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    uniqueIndex("webhook_deliveries_provider_delivery_idx").on(table.provider, table.deliveryId),
    index("webhook_deliveries_org_received_idx").on(table.organizationId, table.receivedAt)
  ]
);

export const scanSchedules = pgTable(
  "scan_schedules",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    cadence: text("cadence").notNull().default("DAILY"), // HOURLY | DAILY | WEEKLY | CUSTOM_CRON
    cronExpression: text("cron_expression").notNull(),
    branch: text("branch"),
    scanners: jsonb("scanners")
      .$type<string[]>()
      .notNull()
      .default(["semgrep", "trivy", "gitleaks", "cicd-github-actions"]),
    runAiAnalysis: boolean("run_ai_analysis").notNull().default(false),
    enabled: boolean("enabled").notNull().default(true),
    lastRunAt: timestamp("last_run_at", { withTimezone: true }),
    nextRunAt: timestamp("next_run_at", { withTimezone: true }).notNull(),
    lastScanId: uuid("last_scan_id").references(() => scans.id, { onDelete: "set null" }),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null"
    }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("scan_schedules_org_idx").on(table.organizationId),
    index("scan_schedules_enabled_next_run_idx").on(table.enabled, table.nextRunAt)
  ]
);

export const notificationChannels = pgTable(
  "notification_channels",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id").references(() => projects.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    channelType: text("channel_type").notNull(), // SLACK | JIRA | GITHUB_ISSUE
    enabled: boolean("enabled").notNull().default(true),
    events: jsonb("events")
      .$type<string[]>()
      .notNull()
      .default(["NEW_CRITICAL_OR_HIGH", "KEV_DETECTED", "SCAN_FAILED"]),
    minSeverity: text("min_severity").notNull().default("HIGH"),
    onlyOnNewFindings: boolean("only_on_new_findings").notNull().default(true),
    configJson: jsonb("config_json").$type<Record<string, unknown>>().notNull().default({}),
    encryptedCredentials: text("encrypted_credentials"),
    lastTriggeredAt: timestamp("last_triggered_at", { withTimezone: true }),
    lastError: text("last_error"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("notification_channels_org_idx").on(table.organizationId),
    index("notification_channels_project_idx").on(table.projectId)
  ]
);

export const notificationDeliveries = pgTable(
  "notification_deliveries",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    channelId: uuid("channel_id")
      .notNull()
      .references(() => notificationChannels.id, { onDelete: "cascade" }),
    scanId: uuid("scan_id").references(() => scans.id, { onDelete: "set null" }),
    eventType: text("event_type").notNull(),
    status: text("status").notNull(), // SENT | FAILED | SKIPPED
    httpStatus: integer("http_status"),
    externalRef: text("external_ref"),
    errorMessage: text("error_message"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [
    index("notification_deliveries_org_created_idx").on(table.organizationId, table.createdAt),
    index("notification_deliveries_channel_idx").on(table.channelId)
  ]
);
