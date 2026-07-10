-- Persist per-session CSRF tokens for local user authentication.

ALTER TABLE sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT '';

DELETE FROM sessions WHERE csrf_token = '';

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
  ON sessions(expires_at);
