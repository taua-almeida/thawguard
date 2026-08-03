CREATE TABLE IF NOT EXISTS company_oidc_test_sign_in_evidence (
  connection_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  verified_at TEXT NOT NULL
    CHECK (
      typeof(verified_at) = 'text'
      AND length(verified_at) = 30
      AND verified_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    )
);
