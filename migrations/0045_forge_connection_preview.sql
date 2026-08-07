-- Forgejo Connection Preview.
--
-- Five isolated tables for the Administrator-only Forge access preview.
-- No existing table, index, trigger, or row changes. The preview only
-- records repositories visible to one Administrator-attested service
-- credential; nothing here binds local repositories, grants access, or
-- proves provider-side scopes.

-- One saved forge connection per provider. AUTOINCREMENT keeps deleted
-- connection ids from ever being reused, so a reset-then-recreate cannot
-- adopt evidence, previews, or audit identity from the deleted connection.
CREATE TABLE forge_connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT
    CHECK (typeof(id) = 'integer' AND id > 0),
  provider TEXT NOT NULL
    CHECK (
      typeof(provider) = 'text'
      AND length(provider) BETWEEN 1 AND 32
      AND provider GLOB '[a-z]*'
      AND provider NOT GLOB '*[^a-z0-9]*'
    ),
  display_name TEXT NOT NULL
    CHECK (typeof(display_name) = 'text' AND length(CAST(display_name AS BLOB)) BETWEEN 1 AND 80),
  base_url TEXT NOT NULL
    CHECK (typeof(base_url) = 'text' AND length(CAST(base_url AS BLOB)) BETWEEN 1 AND 2048),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  check_generation INTEGER NOT NULL
    CHECK (typeof(check_generation) = 'integer' AND check_generation >= 0),
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
    ),
  UNIQUE (provider, base_url)
);

-- The schema can hold one row per provider later; the shipped service
-- accepts only one Forgejo connection, enforced here as well.
CREATE UNIQUE INDEX idx_forge_connections_single_forgejo
  ON forge_connections(provider) WHERE provider = 'forgejo';

-- Forgejo-specific configuration for a connection. The service PAT is
-- write-only ciphertext; the attestation is the Administrator's statement,
-- never a provider-verified fact.
CREATE TABLE forgejo_connection_config (
  connection_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  organization_slug TEXT NOT NULL
    CHECK (typeof(organization_slug) = 'text' AND length(CAST(organization_slug AS BLOB)) BETWEEN 1 AND 255),
  service_pat_ciphertext BLOB NOT NULL
    CHECK (typeof(service_pat_ciphertext) = 'blob' AND length(service_pat_ciphertext) > 0),
  service_user_remote_id TEXT
    CHECK (
      service_user_remote_id IS NULL
      OR (
        typeof(service_user_remote_id) = 'text'
        AND length(CAST(service_user_remote_id AS BLOB)) BETWEEN 1 AND 128
      )
    ),
  pat_attested_at TEXT NOT NULL
    CHECK (
      typeof(pat_attested_at) = 'text'
      AND length(pat_attested_at) = 30
      AND pat_attested_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  attested_by_user_id INTEGER
    REFERENCES users(id) ON DELETE SET NULL
    CHECK (
      attested_by_user_id IS NULL
      OR (typeof(attested_by_user_id) = 'integer' AND attested_by_user_id > 0)
    )
);

-- Organizations observed through the attested credential. The remote id is
-- immutable once bound; slug and display name may refresh on later checks.
-- UNIQUE (connection_id) is the current one-organization contract, and
-- UNIQUE (id, connection_id) supports the composite preview foreign key.
CREATE TABLE forge_organizations (
  id INTEGER PRIMARY KEY NOT NULL
    CHECK (typeof(id) = 'integer' AND id > 0),
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  remote_organization_id TEXT NOT NULL
    CHECK (
      typeof(remote_organization_id) = 'text'
      AND length(CAST(remote_organization_id AS BLOB)) BETWEEN 1 AND 128
    ),
  slug TEXT NOT NULL
    CHECK (typeof(slug) = 'text' AND length(CAST(slug AS BLOB)) BETWEEN 1 AND 255),
  display_name TEXT NOT NULL
    CHECK (typeof(display_name) = 'text' AND length(CAST(display_name AS BLOB)) BETWEEN 1 AND 255),
  observed_at TEXT NOT NULL
    CHECK (
      typeof(observed_at) = 'text'
      AND length(observed_at) = 30
      AND observed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  UNIQUE (connection_id, remote_organization_id),
  UNIQUE (connection_id),
  UNIQUE (id, connection_id)
);

-- Repositories visible to the attested credential at its latest successful
-- check. Preview rows are evidence of visibility at one check generation
-- only; disappearance is never remote-absence or access evidence, and no
-- local repository table references this preview.
CREATE TABLE forge_visible_repositories (
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  organization_id INTEGER NOT NULL
    CHECK (typeof(organization_id) = 'integer' AND organization_id > 0),
  remote_repository_id TEXT NOT NULL
    CHECK (
      typeof(remote_repository_id) = 'text'
      AND length(CAST(remote_repository_id AS BLOB)) BETWEEN 1 AND 128
    ),
  owner TEXT NOT NULL
    CHECK (typeof(owner) = 'text' AND length(CAST(owner AS BLOB)) BETWEEN 1 AND 255),
  name TEXT NOT NULL
    CHECK (typeof(name) = 'text' AND length(CAST(name AS BLOB)) BETWEEN 1 AND 255),
  default_branch TEXT NOT NULL
    CHECK (typeof(default_branch) = 'text' AND length(CAST(default_branch AS BLOB)) BETWEEN 1 AND 255),
  private INTEGER NOT NULL
    CHECK (typeof(private) = 'integer' AND private IN (0, 1)),
  observed_check_generation INTEGER NOT NULL
    CHECK (typeof(observed_check_generation) = 'integer' AND observed_check_generation > 0),
  observed_at TEXT NOT NULL
    CHECK (
      typeof(observed_at) = 'text'
      AND length(observed_at) = 30
      AND observed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  PRIMARY KEY (connection_id, remote_repository_id),
  FOREIGN KEY (organization_id, connection_id)
    REFERENCES forge_organizations(id, connection_id) ON DELETE CASCADE
);

-- One current check result per connection. Evidence is current only while
-- config_revision and check_generation match the connection row. Visible
-- counts exist only for successful snapshots: observed private read proof
-- requires at least one visible private repository, and the unproven code
-- records that none was visible.
CREATE TABLE forge_connection_setup_checks (
  connection_id INTEGER PRIMARY KEY NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  check_generation INTEGER NOT NULL
    CHECK (typeof(check_generation) = 'integer' AND check_generation > 0),
  result_code TEXT NOT NULL
    CHECK (
      typeof(result_code) = 'text'
      AND result_code IN (
        'visible_inventory_observed',
        'visible_inventory_observed_private_read_unproven',
        'unavailable',
        'invalid_response',
        'authentication_failed',
        'authorization_failed',
        'service_user_is_admin',
        'service_user_changed',
        'organization_unavailable',
        'organization_changed',
        'pagination_incomplete',
        'inventory_limit_exceeded'
      )
    ),
  observed_version TEXT
    CHECK (
      observed_version IS NULL
      OR (
        typeof(observed_version) = 'text'
        AND length(CAST(observed_version AS BLOB)) BETWEEN 1 AND 64
      )
    ),
  visible_repository_count INTEGER
    CHECK (
      visible_repository_count IS NULL
      OR (typeof(visible_repository_count) = 'integer' AND visible_repository_count >= 0)
    ),
  visible_private_repository_count INTEGER
    CHECK (
      visible_private_repository_count IS NULL
      OR (
        typeof(visible_private_repository_count) = 'integer'
        AND visible_private_repository_count >= 0
      )
    ),
  checked_at TEXT NOT NULL
    CHECK (
      typeof(checked_at) = 'text'
      AND length(checked_at) = 30
      AND checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  CHECK (
    (result_code = 'visible_inventory_observed'
      AND visible_repository_count IS NOT NULL
      AND visible_private_repository_count IS NOT NULL
      AND visible_private_repository_count >= 1
      AND visible_private_repository_count <= visible_repository_count)
    OR
    (result_code = 'visible_inventory_observed_private_read_unproven'
      AND visible_repository_count IS NOT NULL
      AND visible_private_repository_count IS NOT NULL
      AND visible_private_repository_count = 0)
    OR
    (result_code NOT IN (
        'visible_inventory_observed',
        'visible_inventory_observed_private_read_unproven'
      )
      AND visible_repository_count IS NULL
      AND visible_private_repository_count IS NULL)
  )
);
