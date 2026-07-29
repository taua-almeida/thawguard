CREATE TABLE IF NOT EXISTS company_oidc_setup_checks (
  connection_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES company_oidc_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id = 1),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  result_code TEXT NOT NULL
    CHECK (
      typeof(result_code) = 'text'
      AND result_code IN (
        'verified',
        'discovery_unavailable',
        'discovery_invalid',
        'issuer_invalid',
        'issuer_mismatch',
        'metadata_incompatible',
        'jwks_unavailable',
        'jwks_invalid',
        'jwks_no_candidate'
      )
    ),
  observed_issuer TEXT
    CHECK (
      observed_issuer IS NULL
      OR (
        typeof(observed_issuer) = 'text'
        AND length(CAST(observed_issuer AS BLOB)) BETWEEN 1 AND 2048
      )
    ),
  public_key_candidate_count INTEGER
    CHECK (
      public_key_candidate_count IS NULL
      OR (
        typeof(public_key_candidate_count) = 'integer'
        AND public_key_candidate_count >= 0
      )
    ),
  checked_at TEXT NOT NULL
    CHECK (
      typeof(checked_at) = 'text'
      AND length(checked_at) = 30
      AND checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  CHECK (
    (result_code = 'verified'
      AND observed_issuer IS NULL
      AND public_key_candidate_count IS NOT NULL
      AND public_key_candidate_count >= 1)
    OR
    (result_code = 'issuer_mismatch'
      AND observed_issuer IS NOT NULL
      AND public_key_candidate_count IS NULL)
    OR
    (result_code = 'jwks_no_candidate'
      AND observed_issuer IS NULL
      AND public_key_candidate_count IS NOT NULL
      AND public_key_candidate_count = 0)
    OR
    (result_code IN (
        'discovery_unavailable',
        'discovery_invalid',
        'issuer_invalid',
        'metadata_incompatible',
        'jwks_unavailable',
        'jwks_invalid'
      )
      AND observed_issuer IS NULL
      AND public_key_candidate_count IS NULL)
  )
);
