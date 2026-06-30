CREATE TABLE IF NOT EXISTS repository_webhook_secrets (
  repository_id INTEGER PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
