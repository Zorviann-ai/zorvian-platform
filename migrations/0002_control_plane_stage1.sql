-- Integration Stage 1 control plane.
-- Tamper-evident event chain (not append-only / not immutable).

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS control_tenant_profile (
  tenant_id TEXT PRIMARY KEY,
  home_jurisdiction TEXT NOT NULL DEFAULT '',
  org_type TEXT NOT NULL DEFAULT 'general',
  is_financial_entity INTEGER NOT NULL DEFAULT 0,
  is_essential_entity INTEGER NOT NULL DEFAULT 0,
  sectors TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS control_model_cards (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'unspecified',
  version TEXT NOT NULL DEFAULT 'unspecified',
  purpose TEXT NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 0,
  allowed_actions TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS control_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  workflow TEXT NOT NULL,
  action TEXT NOT NULL,
  purpose TEXT NOT NULL,
  data_classes TEXT NOT NULL,
  jurisdiction_rules TEXT NOT NULL,
  layer_results TEXT NOT NULL,
  document_id TEXT,
  document_hash TEXT,
  approved_hash TEXT,
  model_id TEXT,
  model_provider TEXT,
  model_version TEXT,
  produced_by TEXT,
  approval_ref TEXT,
  destination_hash TEXT,
  result TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(tenant_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_control_events_tenant ON control_events(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_control_events_document ON control_events(document_id);
