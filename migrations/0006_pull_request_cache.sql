-- Ensure pull-request cache persistence exists for databases created before webhook recomputation.

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
