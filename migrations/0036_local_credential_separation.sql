-- Separate local password credentials from user accounts so an account can
-- exist without a local password. Every existing user's credential values and
-- timestamps are copied exactly; the CHECK constraints reject any
-- nonconforming legacy row, which fails the whole migration transaction
-- instead of silently normalizing stored data.

CREATE TABLE IF NOT EXISTS local_credentials (
  user_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES users(id) ON DELETE CASCADE
    CHECK (typeof(user_id) = 'integer' AND user_id > 0),
  password_hash TEXT NOT NULL
    CHECK (typeof(password_hash) = 'text' AND length(password_hash) > 0),
  must_change_password INTEGER NOT NULL
    CHECK (typeof(must_change_password) = 'integer' AND must_change_password IN (0, 1)),
  created_at TEXT NOT NULL
    CHECK (typeof(created_at) = 'text' AND length(created_at) > 0),
  updated_at TEXT NOT NULL
    CHECK (typeof(updated_at) = 'text' AND length(updated_at) > 0)
);

INSERT INTO local_credentials(user_id, password_hash, must_change_password, created_at, updated_at)
SELECT id, password_hash, must_change_password, created_at, updated_at
FROM users;

ALTER TABLE users DROP COLUMN password_hash;

ALTER TABLE users DROP COLUMN must_change_password;
