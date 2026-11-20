-- Indicative MVP Initial PostgreSQL Schema (19 domain tables + schema_migrations)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 1. Identity & Organization
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  github_user_id TEXT,
  github_login TEXT,
  avatar_url TEXT,
  is_demo_user BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users(email);
CREATE UNIQUE INDEX IF NOT EXISTS users_github_user_id_idx ON users(github_user_id);

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS organizations_slug_idx ON organizations(slug);

CREATE TABLE IF NOT EXISTS organization_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'OWNER',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS org_members_org_user_idx ON organization_members(organization_id, user_id);
CREATE INDEX IF NOT EXISTS org_members_user_idx ON organization_members(user_id);

CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS user_sessions_token_hash_idx ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(user_id);

-- 2. Integrations & Projects
CREATE TABLE IF NOT EXISTS integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  config_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS integrations_org_idx ON integrations(organization_id);

CREATE TABLE IF NOT EXISTS github_installations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  integration_id UUID REFERENCES integrations(id) ON DELETE SET NULL,
  installation_id INTEGER NOT NULL,
  account_login TEXT NOT NULL,
  account_type TEXT NOT NULL DEFAULT 'User',
  permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS gh_installations_org_install_idx ON github_installations(organization_id, installation_id);
CREATE INDEX IF NOT EXISTS gh_installations_org_idx ON github_installations(organization_id);

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  description TEXT,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS projects_org_slug_idx ON projects(organization_id, slug);
CREATE INDEX IF NOT EXISTS projects_org_idx ON projects(organization_id);

CREATE TABLE IF NOT EXISTS project_repositories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  github_installation_id UUID REFERENCES github_installations(id) ON DELETE SET NULL,
  provider TEXT NOT NULL DEFAULT 'GITHUB',
  external_repo_id TEXT,
  full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  is_private BOOLEAN NOT NULL DEFAULT TRUE,
  local_fixture_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS project_repos_project_idx ON project_repositories(project_id);
CREATE INDEX IF NOT EXISTS project_repos_org_idx ON project_repositories(organization_id);

-- 3. Scanning & Artifacts
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES project_repositories(id) ON DELETE CASCADE,
  initiated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  idempotency_key TEXT,
  trigger_source TEXT NOT NULL DEFAULT 'MANUAL',
  branch TEXT NOT NULL DEFAULT 'main',
  commit_sha TEXT,
  commit_message TEXT,
  status TEXT NOT NULL DEFAULT 'QUEUED',
  requested_scanners JSONB NOT NULL DEFAULT '["semgrep","trivy","gitleaks"]'::jsonb,
  run_ai_analysis BOOLEAN NOT NULL DEFAULT FALSE,
  is_demo_scan BOOLEAN NOT NULL DEFAULT FALSE,
  summary_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
  comparison_summary JSONB,
  limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
  failure_reason TEXT,
  correlation_id TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS scans_org_project_created_idx ON scans(organization_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_org_status_idx ON scans(organization_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS scans_project_idempotency_idx ON scans(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS scanner_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  scanner_version TEXT NOT NULL,
  ruleset_version TEXT,
  status TEXT NOT NULL,
  exit_code INTEGER,
  findings_count INTEGER NOT NULL DEFAULT 0,
  error_class TEXT NOT NULL DEFAULT 'NONE',
  error_message TEXT,
  limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
  resource_usage JSONB,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS scanner_runs_scan_idx ON scanner_runs(scan_id);
CREATE INDEX IF NOT EXISTS scanner_runs_org_idx ON scanner_runs(organization_id);

CREATE TABLE IF NOT EXISTS scanner_metadata (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scanner TEXT NOT NULL,
  version TEXT NOT NULL,
  ruleset_version TEXT,
  license TEXT NOT NULL,
  capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_health_check_at TIMESTAMPTZ,
  healthy BOOLEAN NOT NULL DEFAULT FALSE,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS scanner_metadata_scanner_idx ON scanner_metadata(scanner);

CREATE TABLE IF NOT EXISTS scan_artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  artifact_type TEXT NOT NULL,
  storage_key TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  redacted BOOLEAN NOT NULL DEFAULT TRUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS scan_artifacts_scan_idx ON scan_artifacts(scan_id);
CREATE INDEX IF NOT EXISTS scan_artifacts_expires_idx ON scan_artifacts(expires_at);

-- 4. Findings & Lifecycle
CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  fingerprint TEXT NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  latest_scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  scanner_version TEXT NOT NULL,
  ruleset_version TEXT,
  rule_id TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL,
  original_severity TEXT,
  confidence TEXT NOT NULL,
  risk_priority TEXT NOT NULL DEFAULT 'MEDIUM',
  risk_rationale JSONB NOT NULL DEFAULT '[]'::jsonb,
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  package_name TEXT,
  installed_version TEXT,
  fixed_version TEXT,
  cve TEXT,
  cvss_score DOUBLE PRECISION,
  secret_type TEXT,
  secret_fingerprint TEXT,
  secret_validity TEXT,
  commit_sha TEXT,
  commit_timestamp TIMESTAMPTZ,
  exposure_location TEXT,
  remediation TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN',
  verification_state TEXT NOT NULL DEFAULT 'DETECTED',
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_project_fingerprint_idx ON findings(project_id, fingerprint);
CREATE INDEX IF NOT EXISTS findings_org_project_status_sev_idx ON findings(organization_id, project_id, status, severity);
CREATE INDEX IF NOT EXISTS findings_org_secret_fp_idx ON findings(organization_id, secret_fingerprint);
CREATE INDEX IF NOT EXISTS findings_latest_scan_idx ON findings(latest_scan_id);

CREATE TABLE IF NOT EXISTS finding_occurrences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  commit_sha TEXT,
  commit_timestamp TIMESTAMPTZ,
  exposure_location TEXT,
  redacted_snippet TEXT,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS finding_occurrences_finding_idx ON finding_occurrences(finding_id);
CREATE INDEX IF NOT EXISTS finding_occurrences_scan_idx ON finding_occurrences(scan_id);

CREATE TABLE IF NOT EXISTS finding_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  label TEXT NOT NULL,
  content TEXT NOT NULL,
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  commit_sha TEXT,
  reference_url TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS finding_evidence_finding_idx ON finding_evidence(finding_id);

CREATE TABLE IF NOT EXISTS finding_status_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  from_status TEXT,
  to_status TEXT NOT NULL,
  reason TEXT NOT NULL,
  changed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  changed_by_system BOOLEAN NOT NULL DEFAULT FALSE,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS finding_status_history_finding_idx ON finding_status_history(finding_id);

CREATE TABLE IF NOT EXISTS finding_ai_analyses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  analysis_json JSONB NOT NULL,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  total_tokens INTEGER,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS finding_ai_analyses_finding_idx ON finding_ai_analyses(finding_id);

-- 5. Governance & Audit
CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  correlation_id TEXT,
  ip_address TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_events_org_created_idx ON audit_events(organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS security_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  max_repo_size_mb INTEGER NOT NULL DEFAULT 250,
  max_concurrent_scans INTEGER NOT NULL DEFAULT 3,
  artifact_retention_days INTEGER NOT NULL DEFAULT 30,
  allow_ai_analysis BOOLEAN NOT NULL DEFAULT TRUE,
  require_verification_on_rescan BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS security_policies_org_idx ON security_policies(organization_id);
