-- Record local dry-run status publication attempts before live forge posting is wired.

CREATE TABLE IF NOT EXISTS status_publication_attempts (
  id INTEGER PRIMARY KEY,
  publication_id INTEGER NOT NULL REFERENCES status_publication_intents(id) ON DELETE CASCADE,
  status_result_id INTEGER NOT NULL REFERENCES status_results(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_index INTEGER NOT NULL,
  target_branch TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  context TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('success', 'failure', 'pending', 'error')),
  description TEXT NOT NULL,
  target_url TEXT,
  mode TEXT NOT NULL CHECK (mode IN ('dry_run')),
  result TEXT NOT NULL CHECK (result IN ('planned')),
  error TEXT,
  attempted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_status_publication_attempts_recent
  ON status_publication_attempts(attempted_at, id);

CREATE INDEX IF NOT EXISTS idx_status_publication_attempts_publication
  ON status_publication_attempts(publication_id, attempted_at);
