-- Thawguard initial SQLite schema scaffold.
-- Timestamps are stored as UTC RFC3339 strings unless noted otherwise.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'freezer', 'thaw_approver', 'viewer')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS repositories (
  id INTEGER PRIMARY KEY,
  forge TEXT NOT NULL,
  base_url TEXT NOT NULL,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  default_branch TEXT NOT NULL,
  token_ciphertext BLOB,
  webhook_secret_ciphertext BLOB,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (forge, base_url, owner, name)
);

CREATE TABLE IF NOT EXISTS repository_branches (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  protected INTEGER NOT NULL DEFAULT 0,
  setup_status TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  UNIQUE (repository_id, name)
);

CREATE TABLE IF NOT EXISTS branch_freezes (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  branch TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('scheduled', 'active', 'ended', 'cancelled')),
  reason TEXT NOT NULL,
  starts_at TEXT,
  ends_at TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_branch_freezes_active
  ON branch_freezes(repository_id, branch, status, starts_at, ends_at);

CREATE TABLE IF NOT EXISTS thaw_exceptions (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_index INTEGER NOT NULL,
  pull_request_url TEXT,
  head_sha TEXT NOT NULL,
  target_branch TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked', 'used')),
  reason TEXT NOT NULL,
  approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_thaw_exceptions_pr
  ON thaw_exceptions(repository_id, pull_request_index, head_sha, status);

CREATE TABLE IF NOT EXISTS pull_request_cache (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_index INTEGER NOT NULL,
  state TEXT NOT NULL,
  target_branch TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  updated_from_forge_at TEXT NOT NULL,
  UNIQUE (repository_id, pull_request_index)
);

CREATE INDEX IF NOT EXISTS idx_pull_request_cache_branch_head
  ON pull_request_cache(repository_id, target_branch, head_sha, state);

CREATE TABLE IF NOT EXISTS status_results (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_index INTEGER,
  head_sha TEXT NOT NULL,
  context TEXT NOT NULL,
  state TEXT NOT NULL,
  description TEXT NOT NULL,
  target_url TEXT,
  posted_at TEXT,
  error TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER REFERENCES repositories(id) ON DELETE SET NULL,
  delivery_id TEXT NOT NULL,
  event TEXT NOT NULL,
  action TEXT,
  received_at TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  processed_at TEXT,
  error TEXT,
  UNIQUE (delivery_id)
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  run_at TEXT NOT NULL,
  locked_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_due
  ON jobs(run_at, locked_at, attempts);

CREATE TABLE IF NOT EXISTS setup_checks (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  branch TEXT,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok', 'warning', 'failed')),
  description TEXT NOT NULL,
  remediation TEXT,
  checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
  ON audit_events(created_at);
