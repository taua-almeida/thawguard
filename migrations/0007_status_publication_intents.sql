-- Record local status-publication intents before live forge posting is wired.

CREATE TABLE IF NOT EXISTS status_publication_intents (
  id INTEGER PRIMARY KEY,
  status_result_id INTEGER NOT NULL REFERENCES status_results(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_index INTEGER NOT NULL,
  target_branch TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  context TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('success', 'failure', 'pending', 'error')),
  description TEXT NOT NULL,
  target_url TEXT,
  delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('local_record')),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_status_publication_intents_recent
  ON status_publication_intents(created_at, id);

CREATE INDEX IF NOT EXISTS idx_status_publication_intents_head
  ON status_publication_intents(repository_id, head_sha, created_at);
