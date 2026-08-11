-- Forgejo identity linking.
--
-- Three isolated tables for the explicit user-initiated Forgejo identity
-- link ceremony: the Administrator-managed OAuth client configuration, the
-- short-lived session/browser/state-bound link transactions, and the linked
-- identities themselves. Linking proves identity only: nothing here grants
-- repository roles, routes operations, or changes repository-owned state.

-- One OAuth client configuration per saved Forge connection. Credentials
-- are present exactly while the client is enabled; disabling destroys them.
-- The revision is monotonic and fences every ceremony and admin command; it
-- never wraps, and the only permitted same-revision write is the terminal
-- disable at the maximum revision.
CREATE TABLE forgejo_identity_oauth_clients (
  connection_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  enabled INTEGER NOT NULL
    CHECK (typeof(enabled) = 'integer' AND enabled IN (0, 1)),
  client_id TEXT
    CHECK (
      client_id IS NULL
      OR (typeof(client_id) = 'text' AND length(CAST(client_id AS BLOB)) BETWEEN 1 AND 255)
    ),
  client_secret_ciphertext BLOB
    CHECK (
      client_secret_ciphertext IS NULL
      OR (
        typeof(client_secret_ciphertext) = 'blob'
        AND length(client_secret_ciphertext) BETWEEN 1 AND 8192
      )
    ),
  bound_base_url TEXT
    CHECK (
      bound_base_url IS NULL
      OR (typeof(bound_base_url) = 'text' AND length(CAST(bound_base_url AS BLOB)) BETWEEN 1 AND 2048)
    ),
  oauth_revision INTEGER NOT NULL
    CHECK (typeof(oauth_revision) = 'integer' AND oauth_revision > 0),
  CHECK (
    (enabled = 1
      AND client_id IS NOT NULL
      AND client_secret_ciphertext IS NOT NULL
      AND bound_base_url IS NOT NULL)
    OR
    (enabled = 0
      AND client_id IS NULL
      AND client_secret_ciphertext IS NULL
      AND bound_base_url IS NULL)
  )
);

-- One live link transaction per connection and user, bound to the exact
-- session, browser, state, redirect URI, base URL, and revisions observed
-- at start. Rows expire ten minutes after creation; the claim CAS moves
-- 'pending' to 'claimed' before any provider I/O.
CREATE TABLE forgejo_identity_link_transactions (
  state_digest BLOB PRIMARY KEY NOT NULL
    CHECK (typeof(state_digest) = 'blob' AND length(state_digest) = 32),
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  user_id INTEGER NOT NULL
    REFERENCES users(id) ON DELETE CASCADE
    CHECK (typeof(user_id) = 'integer' AND user_id > 0),
  status TEXT NOT NULL
    CHECK (typeof(status) = 'text' AND status IN ('pending', 'claimed')),
  session_binding_digest BLOB NOT NULL
    CHECK (typeof(session_binding_digest) = 'blob' AND length(session_binding_digest) = 32),
  browser_binding_digest BLOB NOT NULL
    CHECK (typeof(browser_binding_digest) = 'blob' AND length(browser_binding_digest) = 32),
  pkce_verifier_ciphertext BLOB NOT NULL
    CHECK (
      typeof(pkce_verifier_ciphertext) = 'blob'
      AND length(pkce_verifier_ciphertext) BETWEEN 1 AND 8192
    ),
  redirect_uri TEXT NOT NULL
    CHECK (
      typeof(redirect_uri) = 'text'
      AND length(CAST(redirect_uri AS BLOB)) BETWEEN 1 AND 2048
      AND redirect_uri GLOB '*/account/forgejo/callback'
    ),
  bound_base_url TEXT NOT NULL
    CHECK (typeof(bound_base_url) = 'text' AND length(CAST(bound_base_url AS BLOB)) BETWEEN 1 AND 2048),
  connection_revision INTEGER NOT NULL
    CHECK (typeof(connection_revision) = 'integer' AND connection_revision > 0),
  oauth_revision INTEGER NOT NULL
    CHECK (typeof(oauth_revision) = 'integer' AND oauth_revision > 0),
  created_at TEXT NOT NULL
    CHECK (
      typeof(created_at) = 'text'
      AND length(created_at) = 30
      AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  expires_at TEXT NOT NULL
    CHECK (
      typeof(expires_at) = 'text'
      AND length(expires_at) = 30
      AND expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  UNIQUE (connection_id, user_id),
  CHECK (expires_at > created_at)
);

CREATE INDEX idx_forgejo_identity_link_transactions_expires_at
  ON forgejo_identity_link_transactions(expires_at);

-- Linked Forgejo identities. AUTOINCREMENT keeps deleted identity row ids
-- from ever being reused, so a stale unlink or purge form can never target
-- a later identity. ON DELETE RESTRICT keeps an identity's connection and
-- user rows alive while the identity exists; unlink and purge must remove
-- the identity explicitly first. The remote id is canonical positive
-- signed-int64 decimal text and never enters web read models.
CREATE TABLE forgejo_identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT
    CHECK (typeof(id) = 'integer' AND id > 0),
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE RESTRICT
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  user_id INTEGER NOT NULL
    REFERENCES users(id) ON DELETE RESTRICT
    CHECK (typeof(user_id) = 'integer' AND user_id > 0),
  remote_user_id TEXT NOT NULL
    CHECK (
      typeof(remote_user_id) = 'text'
      AND length(remote_user_id) BETWEEN 1 AND 19
      AND remote_user_id GLOB '[1-9]*'
      AND remote_user_id NOT GLOB '*[^0-9]*'
      AND (length(remote_user_id) < 19 OR remote_user_id <= '9223372036854775807')
      -- length() and GLOB stop at an embedded NUL; requiring the byte
      -- length to match the character length rejects NUL-smuggled text
      -- that would otherwise pass as a distinct duplicate remote id.
      AND length(CAST(remote_user_id AS BLOB)) = length(remote_user_id)
    ),
  username_at_link TEXT NOT NULL
    CHECK (typeof(username_at_link) = 'text' AND length(CAST(username_at_link AS BLOB)) BETWEEN 1 AND 255),
  linked_at TEXT NOT NULL
    CHECK (
      typeof(linked_at) = 'text'
      AND length(linked_at) = 30
      AND linked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  UNIQUE (connection_id, user_id),
  UNIQUE (connection_id, remote_user_id)
);
