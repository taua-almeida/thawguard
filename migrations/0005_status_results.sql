-- Ensure local status-result persistence exists for databases created before the scaffold stabilized.

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

-- Store the branch that a local status decision was computed against.
ALTER TABLE status_results ADD COLUMN target_branch TEXT NOT NULL DEFAULT '';
