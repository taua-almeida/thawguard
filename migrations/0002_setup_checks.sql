-- Add persisted setup-health results for repositories.

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
