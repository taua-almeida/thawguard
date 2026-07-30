DROP INDEX IF EXISTS idx_company_oidc_test_transactions_expires_at;
DROP TABLE company_oidc_test_transactions;

CREATE TABLE company_oidc_test_transactions (
  state_digest BLOB PRIMARY KEY NOT NULL
    CHECK (typeof(state_digest) = 'blob' AND length(state_digest) = 32),
  connection_id INTEGER NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
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

CREATE INDEX idx_company_oidc_test_transactions_expires_at
  ON company_oidc_test_transactions(expires_at);
