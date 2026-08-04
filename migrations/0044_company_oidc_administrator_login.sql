-- Administrator-only operational company OIDC login.
--
-- The singleton connection gains an enabled flag and an activation
-- generation counter. The generation is incremented by Enable, Disable,
-- real connection edits, link, and unlink; link and login transactions
-- capture the generation they started under and callbacks require an
-- exact match, so a callback that started before any of those actions
-- can never complete afterward.

ALTER TABLE company_oidc_connections ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0
  CHECK (typeof(enabled) = 'integer' AND enabled IN (0, 1));

ALTER TABLE company_oidc_connections ADD COLUMN activation_generation INTEGER NOT NULL DEFAULT 1
  CHECK (typeof(activation_generation) = 'integer' AND activation_generation > 0);

-- Exactly one linked Administrator identity for the singleton connection.
-- Stores only the exact issuer, exact client ID, bounded raw subject, and
-- the canonical verified provider email kept for display.
CREATE TABLE company_oidc_identities (
  connection_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  user_id INTEGER NOT NULL UNIQUE
    REFERENCES users(id) ON DELETE CASCADE
    CHECK (typeof(user_id) = 'integer' AND user_id > 0),
  issuer TEXT NOT NULL
    CHECK (typeof(issuer) = 'text' AND length(CAST(issuer AS BLOB)) BETWEEN 1 AND 2048),
  client_id TEXT NOT NULL
    CHECK (typeof(client_id) = 'text' AND length(CAST(client_id AS BLOB)) BETWEEN 1 AND 512),
  subject TEXT NOT NULL
    CHECK (typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) BETWEEN 1 AND 255),
  email TEXT NOT NULL
    CHECK (typeof(email) = 'text' AND length(CAST(email AS BLOB)) BETWEEN 3 AND 254),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  linked_at TEXT NOT NULL
    CHECK (
      typeof(linked_at) = 'text'
      AND length(linked_at) = 30
      AND linked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    )
);

-- One-time authenticated link transactions, bound to the exact
-- Administrator, exact persistent session, connection revision, and
-- activation generation observed at initiation.
CREATE TABLE company_oidc_link_transactions (
  state_digest BLOB PRIMARY KEY NOT NULL
    CHECK (typeof(state_digest) = 'blob' AND length(state_digest) = 32),
  connection_id INTEGER NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  activation_generation INTEGER NOT NULL
    CHECK (typeof(activation_generation) = 'integer' AND activation_generation > 0),
  actor_user_id INTEGER NOT NULL
    REFERENCES users(id) ON DELETE CASCADE
    CHECK (typeof(actor_user_id) = 'integer' AND actor_user_id > 0),
  session_binding_digest BLOB NOT NULL UNIQUE
    CHECK (typeof(session_binding_digest) = 'blob' AND length(session_binding_digest) = 32),
  nonce_digest BLOB NOT NULL
    CHECK (typeof(nonce_digest) = 'blob' AND length(nonce_digest) = 32),
  pkce_verifier_ciphertext BLOB NOT NULL
    CHECK (
      typeof(pkce_verifier_ciphertext) = 'blob'
      AND length(pkce_verifier_ciphertext) BETWEEN 1 AND 512
    ),
  token_endpoint TEXT NOT NULL
    CHECK (
      typeof(token_endpoint) = 'text'
      AND length(token_endpoint) BETWEEN 9 AND 2048
      AND lower(substr(token_endpoint, 1, 8)) = 'https://'
    ),
  jwks_uri TEXT NOT NULL
    CHECK (
      typeof(jwks_uri) = 'text'
      AND length(jwks_uri) BETWEEN 9 AND 2048
      AND lower(substr(jwks_uri, 1, 8)) = 'https://'
    ),
  redirect_uri TEXT NOT NULL
    CHECK (
      typeof(redirect_uri) = 'text'
      AND length(redirect_uri) BETWEEN 1 AND 2048
      AND (
        lower(substr(redirect_uri, 1, 8)) = 'https://'
        OR lower(substr(redirect_uri, 1, 7)) = 'http://'
      )
      AND redirect_uri GLOB '*/settings/authentication/oidc/callback'
    ),
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
  CHECK (expires_at > created_at)
);

CREATE INDEX idx_company_oidc_link_transactions_expires_at
  ON company_oidc_link_transactions(expires_at);

-- One-time anonymous login transactions. No Thawguard user or session is
-- bound at initiation; the browser is bound through the digest of an
-- independent random token stored in a dedicated cookie.
CREATE TABLE company_oidc_login_transactions (
  state_digest BLOB PRIMARY KEY NOT NULL
    CHECK (typeof(state_digest) = 'blob' AND length(state_digest) = 32),
  connection_id INTEGER NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  activation_generation INTEGER NOT NULL
    CHECK (typeof(activation_generation) = 'integer' AND activation_generation > 0),
  browser_binding_digest BLOB NOT NULL UNIQUE
    CHECK (typeof(browser_binding_digest) = 'blob' AND length(browser_binding_digest) = 32),
  nonce_digest BLOB NOT NULL
    CHECK (typeof(nonce_digest) = 'blob' AND length(nonce_digest) = 32),
  pkce_verifier_ciphertext BLOB NOT NULL
    CHECK (
      typeof(pkce_verifier_ciphertext) = 'blob'
      AND length(pkce_verifier_ciphertext) BETWEEN 1 AND 512
    ),
  token_endpoint TEXT NOT NULL
    CHECK (
      typeof(token_endpoint) = 'text'
      AND length(token_endpoint) BETWEEN 9 AND 2048
      AND lower(substr(token_endpoint, 1, 8)) = 'https://'
    ),
  jwks_uri TEXT NOT NULL
    CHECK (
      typeof(jwks_uri) = 'text'
      AND length(jwks_uri) BETWEEN 9 AND 2048
      AND lower(substr(jwks_uri, 1, 8)) = 'https://'
    ),
  redirect_uri TEXT NOT NULL
    CHECK (
      typeof(redirect_uri) = 'text'
      AND length(redirect_uri) BETWEEN 1 AND 2048
      AND (
        lower(substr(redirect_uri, 1, 8)) = 'https://'
        OR lower(substr(redirect_uri, 1, 7)) = 'http://'
      )
      AND redirect_uri GLOB '*/settings/authentication/oidc/callback'
    ),
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
  CHECK (expires_at > created_at)
);

CREATE INDEX idx_company_oidc_login_transactions_expires_at
  ON company_oidc_login_transactions(expires_at);

-- OIDC session provenance. A session created through company OIDC login
-- gets a companion row; deleting the sessions row (logout, expiry
-- cleanup, or the existing per-user session revocation on password
-- change, reset, recovery, and user disable) cascades here, while
-- Disable and unlink revoke only OIDC sessions through this table.
CREATE TABLE company_oidc_sessions (
  session_id TEXT PRIMARY KEY NOT NULL
    REFERENCES sessions(id) ON DELETE CASCADE
    CHECK (typeof(session_id) = 'text' AND length(CAST(session_id AS BLOB)) BETWEEN 1 AND 512),
  connection_id INTEGER NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  user_id INTEGER NOT NULL
    REFERENCES users(id) ON DELETE CASCADE
    CHECK (typeof(user_id) = 'integer' AND user_id > 0)
);

CREATE INDEX idx_company_oidc_sessions_user_id
  ON company_oidc_sessions(user_id);
