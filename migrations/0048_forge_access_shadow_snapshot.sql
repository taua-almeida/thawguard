-- Manual Forgejo shadow-access snapshots.
--
-- One Administrator-triggered, bounded, connection-wide observation of every
-- current linked-identity x bound-repository pair. Everything here is
-- evidence only: no table below is read by enforcement, none references
-- repository_grants, and no row grants, predicts, or changes authority.

-- access_identity_revision fences shadow snapshots against identity churn.
-- It advances atomically on every identity link, unlink, and purge and never
-- wraps; at the maximum revision new links are blocked while unlink and
-- purge remain allowed as a terminal same-revision reduction.
ALTER TABLE forge_connections
ADD COLUMN access_identity_revision INTEGER NOT NULL DEFAULT 0
  CHECK (typeof(access_identity_revision) = 'integer' AND access_identity_revision >= 0);

-- Connections upgraded with identities linked before this migration start at
-- the revision each link would have produced, so an existing linked
-- connection can run a snapshot immediately and the invariant "identities
-- exist implies a positive revision" holds from the first moment the column
-- exists. Connections without identities stay at zero.
UPDATE forge_connections
SET access_identity_revision = (
  SELECT COUNT(*) FROM forgejo_identities
  WHERE forgejo_identities.connection_id = forge_connections.id
);

-- Composite-FK support: observations pin each pair to the exact identity and
-- binding row of one connection, so a row from another connection can never
-- satisfy the pair foreign keys below.
CREATE UNIQUE INDEX idx_forgejo_identities_id_connection
  ON forgejo_identities(id, connection_id);
CREATE UNIQUE INDEX idx_forge_repository_bindings_repository_connection
  ON forge_repository_bindings(repository_id, connection_id);

-- One row per snapshot attempt. AUTOINCREMENT keeps run ids from ever being
-- reused, so the id serves as the form CAS token, the ordering token, the
-- observation version, and the latest-attempt key. A NULL result_code means
-- the run is still executing; every terminal result requires a finish time.
CREATE TABLE forge_access_shadow_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT
    CHECK (typeof(id) = 'integer' AND id > 0),
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  requested_by_user_id INTEGER
    REFERENCES users(id) ON DELETE SET NULL
    CHECK (
      requested_by_user_id IS NULL
      OR (typeof(requested_by_user_id) = 'integer' AND requested_by_user_id > 0)
    ),
  config_revision INTEGER NOT NULL
    CHECK (typeof(config_revision) = 'integer' AND config_revision > 0),
  check_generation INTEGER NOT NULL
    CHECK (typeof(check_generation) = 'integer' AND check_generation > 0),
  binding_revision INTEGER NOT NULL
    CHECK (typeof(binding_revision) = 'integer' AND binding_revision > 0),
  access_identity_revision INTEGER NOT NULL
    CHECK (typeof(access_identity_revision) = 'integer' AND access_identity_revision > 0),
  identity_count INTEGER NOT NULL
    CHECK (typeof(identity_count) = 'integer' AND identity_count BETWEEN 1 AND 10),
  repository_count INTEGER NOT NULL
    CHECK (typeof(repository_count) = 'integer' AND repository_count BETWEEN 1 AND 10),
  result_code TEXT
    CHECK (
      result_code IS NULL
      OR (
        typeof(result_code) = 'text'
        AND result_code IN (
          'complete',
          'unavailable',
          'authentication_failed',
          'authorization_failed',
          'service_user_is_admin',
          'service_user_changed',
          'organization_changed',
          'credential_unavailable',
          'invalid_response',
          'pagination_incomplete',
          'work_limit_exceeded',
          'scope_changed',
          'interrupted'
        )
      )
    ),
  present_count INTEGER
    CHECK (
      present_count IS NULL
      OR (typeof(present_count) = 'integer' AND present_count >= 0)
    ),
  unknown_count INTEGER
    CHECK (
      unknown_count IS NULL
      OR (typeof(unknown_count) = 'integer' AND unknown_count >= 0)
    ),
  started_at TEXT NOT NULL
    CHECK (
      typeof(started_at) = 'text'
      AND length(started_at) = 30
      AND started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  finished_at TEXT
    CHECK (
      finished_at IS NULL
      OR (
        typeof(finished_at) = 'text'
        AND length(finished_at) = 30
        AND finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
      )
    ),
  -- The pair scope never exceeds the small-alpha ceiling.
  CHECK (identity_count * repository_count <= 25),
  -- Truth constraints: running rows carry no result evidence, a complete
  -- result carries pair counts bounded by the pair product (the absent count
  -- derives as product minus present minus unknown), and every other
  -- terminal result carries none. CASE keeps the constraint NULL-safe: a
  -- NULL result_code must select the running branch outright, never turn a
  -- comparison NULL that would let a complete-shaped row slip through.
  CHECK (
    CASE
      WHEN result_code IS NULL THEN
        finished_at IS NULL
        AND present_count IS NULL
        AND unknown_count IS NULL
      WHEN result_code = 'complete' THEN
        finished_at IS NOT NULL
        AND present_count IS NOT NULL
        AND unknown_count IS NOT NULL
        AND present_count + unknown_count <= identity_count * repository_count
      ELSE
        finished_at IS NOT NULL
        AND present_count IS NULL
        AND unknown_count IS NULL
    END
  ),
  CHECK (finished_at IS NULL OR finished_at >= started_at)
);

-- At most one running attempt may exist per connection; a second concurrent
-- reservation fails here even if two writers ever raced past the service.
CREATE UNIQUE INDEX idx_forge_access_shadow_runs_single_running
  ON forge_access_shadow_runs(connection_id) WHERE result_code IS NULL;

-- The latest observation per exact identity x binding pair. Composite
-- foreign keys cascade the row away with its identity (unlink/purge) or its
-- binding (unbind); the connection cascade covers reset defense in depth.
-- Run ids are ordering tokens into the never-reused runs sequence, not
-- foreign keys: retention may delete an old completed run while a preserved
-- confirmation still names it.
CREATE TABLE forge_access_shadow_observations (
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  identity_id INTEGER NOT NULL
    CHECK (typeof(identity_id) = 'integer' AND identity_id > 0),
  repository_id INTEGER NOT NULL
    CHECK (typeof(repository_id) = 'integer' AND repository_id > 0),
  latest_reason TEXT NOT NULL
    CHECK (
      typeof(latest_reason) = 'text'
      AND latest_reason IN (
        'direct_collaborator',
        'team_access',
        'no_explicit_access_none',
        'identity_unresolved',
        'repository_unavailable',
        'visibility_source_unproven',
        'permission_unavailable',
        'permission_unrecognized',
        'evidence_inconsistent'
      )
    ),
  latest_run_id INTEGER NOT NULL
    CHECK (typeof(latest_run_id) = 'integer' AND latest_run_id > 0),
  latest_observed_at TEXT NOT NULL
    CHECK (
      typeof(latest_observed_at) = 'text'
      AND length(latest_observed_at) = 30
      AND latest_observed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    ),
  last_confirmed_reason TEXT
    CHECK (
      last_confirmed_reason IS NULL
      OR (
        typeof(last_confirmed_reason) = 'text'
        AND last_confirmed_reason IN (
          'direct_collaborator',
          'team_access',
          'no_explicit_access_none'
        )
      )
    ),
  last_confirmed_run_id INTEGER
    CHECK (
      last_confirmed_run_id IS NULL
      OR (typeof(last_confirmed_run_id) = 'integer' AND last_confirmed_run_id > 0)
    ),
  last_confirmed_at TEXT
    CHECK (
      last_confirmed_at IS NULL
      OR (
        typeof(last_confirmed_at) = 'text'
        AND length(last_confirmed_at) = 30
        AND last_confirmed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
      )
    ),
  PRIMARY KEY (connection_id, identity_id, repository_id),
  FOREIGN KEY (identity_id, connection_id)
    REFERENCES forgejo_identities(id, connection_id) ON DELETE CASCADE,
  FOREIGN KEY (repository_id, connection_id)
    REFERENCES forge_repository_bindings(repository_id, connection_id) ON DELETE CASCADE,
  -- A confirmed latest reason is its own confirmation and the fields must
  -- match exactly; an unknown latest reason either preserves one complete
  -- earlier confirmation or has none. CASE keeps the constraint NULL-safe:
  -- a NULL comparison must fail the branch, not pass the whole CHECK.
  CHECK (
    CASE WHEN latest_reason IN ('direct_collaborator', 'team_access', 'no_explicit_access_none') THEN
      last_confirmed_reason IS NOT NULL AND last_confirmed_reason = latest_reason
      AND last_confirmed_run_id IS NOT NULL AND last_confirmed_run_id = latest_run_id
      AND last_confirmed_at IS NOT NULL AND last_confirmed_at = latest_observed_at
    ELSE
      (last_confirmed_reason IS NULL
        AND last_confirmed_run_id IS NULL
        AND last_confirmed_at IS NULL)
      OR
      (last_confirmed_reason IS NOT NULL
        AND last_confirmed_run_id IS NOT NULL
        AND last_confirmed_at IS NOT NULL)
    END
  ),
  -- The latest observation may never precede its preserved confirmation.
  CHECK (
    last_confirmed_run_id IS NULL
    OR (latest_run_id >= last_confirmed_run_id AND latest_observed_at >= last_confirmed_at)
  )
);
