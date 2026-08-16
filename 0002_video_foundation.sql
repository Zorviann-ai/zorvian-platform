PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS video_projects (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  prompt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  aspect_ratio TEXT NOT NULL DEFAULT '16:9',
  target_duration_seconds INTEGER,
  settings_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS video_scenes (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  scene_index INTEGER NOT NULL,
  title TEXT,
  narration TEXT,
  visual_prompt TEXT NOT NULL,
  duration_seconds REAL NOT NULL DEFAULT 5,
  status TEXT NOT NULL DEFAULT 'planned',
  provider_key TEXT,
  provider_job_id TEXT,
  output_asset_id TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, scene_index),
  FOREIGN KEY(project_id) REFERENCES video_projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS video_assets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  scene_id TEXT,
  kind TEXT NOT NULL,
  storage_key TEXT,
  source_url TEXT,
  mime_type TEXT,
  width INTEGER,
  height INTEGER,
  duration_seconds REAL,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(project_id) REFERENCES video_projects(id) ON DELETE CASCADE,
  FOREIGN KEY(scene_id) REFERENCES video_scenes(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS video_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  scene_id TEXT,
  job_type TEXT NOT NULL,
  provider_key TEXT,
  provider_job_id TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  attempt INTEGER NOT NULL DEFAULT 1,
  estimated_cost_micros INTEGER NOT NULL DEFAULT 0,
  actual_cost_micros INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  error_message TEXT,
  request_json TEXT,
  response_json TEXT,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(project_id) REFERENCES video_projects(id) ON DELETE CASCADE,
  FOREIGN KEY(scene_id) REFERENCES video_scenes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS video_renders (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  output_asset_id TEXT,
  resolution TEXT NOT NULL DEFAULT '1080p',
  format TEXT NOT NULL DEFAULT 'mp4',
  duration_seconds REAL,
  actual_cost_micros INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  FOREIGN KEY(project_id) REFERENCES video_projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_video_projects_tenant ON video_projects(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_video_scenes_project ON video_scenes(project_id, scene_index);
CREATE INDEX IF NOT EXISTS idx_video_jobs_project_status ON video_jobs(project_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_video_jobs_scene ON video_jobs(scene_id, created_at);
CREATE INDEX IF NOT EXISTS idx_video_assets_project ON video_assets(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_video_renders_project ON video_renders(project_id, created_at);
