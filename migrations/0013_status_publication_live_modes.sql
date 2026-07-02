-- Allow future live Forgejo/Codeberg status publication records while preserving dry-run rows.

CREATE TABLE status_publication_attempts_preserved AS
SELECT id, publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at
FROM status_publication_attempts;

DROP TABLE status_publication_attempts;

CREATE TABLE status_publication_intents_next (
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
  delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('local_record', 'forgejo_status')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT INTO status_publication_intents_next(id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at)
SELECT id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at
FROM status_publication_intents;

DROP TABLE status_publication_intents;

ALTER TABLE status_publication_intents_next RENAME TO status_publication_intents;

CREATE INDEX IF NOT EXISTS idx_status_publication_intents_recent
  ON status_publication_intents(created_at, id);

CREATE INDEX IF NOT EXISTS idx_status_publication_intents_head
  ON status_publication_intents(repository_id, head_sha, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_status_publication_intents_idempotency
  ON status_publication_intents(repository_id, head_sha, context, delivery_mode);

CREATE INDEX IF NOT EXISTS idx_status_publication_intents_updated
  ON status_publication_intents(updated_at, id);

CREATE TABLE status_publication_attempts (
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
  mode TEXT NOT NULL CHECK (mode IN ('dry_run', 'forgejo_status')),
  result TEXT NOT NULL CHECK (result IN ('planned', 'posted', 'failed')),
  error TEXT,
  attempted_at TEXT NOT NULL
);

INSERT INTO status_publication_attempts(id, publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at)
SELECT id, publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at
FROM status_publication_attempts_preserved;

DROP TABLE status_publication_attempts_preserved;

CREATE INDEX IF NOT EXISTS idx_status_publication_attempts_recent
  ON status_publication_attempts(attempted_at, id);

CREATE INDEX IF NOT EXISTS idx_status_publication_attempts_publication
  ON status_publication_attempts(publication_id, attempted_at);
