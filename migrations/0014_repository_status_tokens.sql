-- Store per-repository Forgejo/Codeberg status-posting tokens encrypted with THAWGUARD_SECRET_KEY.

CREATE TABLE IF NOT EXISTS repository_status_tokens (
  repository_id INTEGER PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
