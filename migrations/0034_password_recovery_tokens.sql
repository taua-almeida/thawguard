-- Keep only the current password-recovery credential for each local user.
-- The bearer value is never stored; token_digest is SHA-256 over its encoded form.
-- expires_at is UTC Unix nanoseconds for deterministic boundary comparisons.

CREATE TABLE IF NOT EXISTS password_recovery_tokens (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token_digest BLOB NOT NULL UNIQUE
    CHECK (typeof(token_digest) = 'blob' AND length(token_digest) = 32),
  expires_at INTEGER NOT NULL
    CHECK (typeof(expires_at) = 'integer' AND expires_at > 0)
);
