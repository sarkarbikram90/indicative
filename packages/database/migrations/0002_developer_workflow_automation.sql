-- Indicative Developer Workflow & Automation Migration (v0.3.0-dev)
-- Adds GitHub webhook delivery replay tracking, scan trigger metadata,
-- scheduled/recurring scans, and encrypted notification channels (Slack, Jira, GitHub Issues).

ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS trigger_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delivery_id TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'GITHUB',
  event_type TEXT NOT NULL,
  action TEXT,
  repository_full_name TEXT,
  organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  signature_valid BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL,
  summary TEXT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS webhook_deliveries_provider_delivery_idx
  ON webhook_deliveries(provider, delivery_id);
CREATE INDEX IF NOT EXISTS webhook_deliveries_org_received_idx
  ON webhook_deliveries(organization_id, received_at);

CREATE TABLE IF NOT EXISTS scan_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  cadence TEXT NOT NULL DEFAULT 'DAILY',
  cron_expression TEXT NOT NULL,
  branch TEXT,
  scanners JSONB NOT NULL DEFAULT '["semgrep","trivy","gitleaks","cicd-github-actions"]'::jsonb,
  run_ai_analysis BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_run_at TIMESTAMPTZ,
  next_run_at TIMESTAMPTZ NOT NULL,
  last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS scan_schedules_org_idx
  ON scan_schedules(organization_id);
CREATE INDEX IF NOT EXISTS scan_schedules_enabled_next_run_idx
  ON scan_schedules(enabled, next_run_at);

CREATE TABLE IF NOT EXISTS notification_channels (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  channel_type TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  events JSONB NOT NULL DEFAULT '["NEW_CRITICAL_OR_HIGH","KEV_DETECTED","SCAN_FAILED"]'::jsonb,
  min_severity TEXT NOT NULL DEFAULT 'HIGH',
  only_on_new_findings BOOLEAN NOT NULL DEFAULT TRUE,
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  encrypted_credentials TEXT,
  last_triggered_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS notification_channels_org_idx
  ON notification_channels(organization_id);
CREATE INDEX IF NOT EXISTS notification_channels_project_idx
  ON notification_channels(project_id);

CREATE TABLE IF NOT EXISTS notification_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  external_ref TEXT,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS notification_deliveries_org_created_idx
  ON notification_deliveries(organization_id, created_at);
CREATE INDEX IF NOT EXISTS notification_deliveries_channel_idx
  ON notification_deliveries(channel_id);
