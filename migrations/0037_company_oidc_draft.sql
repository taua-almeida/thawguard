CREATE TABLE IF NOT EXISTS company_oidc_connections (
  id INTEGER PRIMARY KEY NOT NULL
    CHECK (typeof(id) = 'integer' AND id = 1),
  provider_label TEXT NOT NULL
    CHECK (typeof(provider_label) = 'text' AND length(provider_label) BETWEEN 1 AND 80),
  issuer TEXT NOT NULL
    CHECK (typeof(issuer) = 'text' AND length(CAST(issuer AS BLOB)) BETWEEN 1 AND 2048),
  client_id TEXT NOT NULL
    CHECK (typeof(client_id) = 'text' AND length(CAST(client_id AS BLOB)) BETWEEN 1 AND 512),
  client_secret_ciphertext BLOB NOT NULL
    CHECK (typeof(client_secret_ciphertext) = 'blob' AND length(client_secret_ciphertext) > 0),
  revision INTEGER NOT NULL
    CHECK (typeof(revision) = 'integer' AND revision > 0),
  created_at TEXT NOT NULL
    CHECK (
      typeof(created_at) = 'text'
      AND length(created_at) = 30
      AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  updated_at TEXT NOT NULL
    CHECK (
      typeof(updated_at) = 'text'
      AND length(updated_at) = 30
      AND updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    )
);

CREATE TABLE IF NOT EXISTS company_oidc_allowed_domains (
  connection_id INTEGER NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  domain TEXT NOT NULL
    CHECK (
      typeof(domain) = 'text'
      AND length(CAST(domain AS BLOB)) BETWEEN 1 AND 253
      AND domain = lower(domain)
    ),
  PRIMARY KEY (connection_id, domain)
);
