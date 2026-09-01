-- Controlled Execution Gateway Phase 3 Stage 1.
-- Additive SQLite schema for the Python/Railway execution gateway.
-- Does not target Cloudflare D1. Live external execution remains disabled.

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS execution_attempts(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  ticket_id TEXT NOT NULL,
  adapter_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  state TEXT NOT NULL,
  provider_ref TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS execution_receipts(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  classification TEXT NOT NULL,
  payload_hash TEXT,
  destination_hash TEXT,
  recorded_at TEXT NOT NULL,
  extra_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS execution_live_grants(
  tenant_id TEXT NOT NULL,
  adapter_id TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT '*',
  env TEXT NOT NULL DEFAULT 'prod',
  enabled INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, adapter_id, action, env)
);

CREATE TABLE IF NOT EXISTS execution_destination_allowlist(
  tenant_id TEXT NOT NULL,
  adapter_id TEXT NOT NULL,
  destination_hash TEXT NOT NULL,
  label TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, adapter_id, destination_hash)
);

CREATE TABLE IF NOT EXISTS execution_kill_switches(
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  tenant_id TEXT,
  adapter_id TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  reason TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_shadow_runs(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_confirmation_tokens(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  approval_hash TEXT,
  idempotency_key TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_phase3_audit(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  event TEXT NOT NULL,
  subject_id TEXT,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_execution_attempts_tenant ON execution_attempts(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_execution_receipts_attempt ON execution_receipts(tenant_id, attempt_id);
CREATE INDEX IF NOT EXISTS idx_execution_shadow_tenant ON execution_shadow_runs(tenant_id, plan_id);
