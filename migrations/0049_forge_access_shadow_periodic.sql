-- Explicitly enabled periodic execution of the shipped Forgejo shadow-access
-- snapshot. This migration is forward-only once periodic configuration or
-- periodic runs exist. Rolling back to an older binary, and mixed-version
-- writers against one database, are unsupported: older code does not know
-- the periodic cadence or trigger attribution even though existing manual
-- insert statements continue to receive the additive manual default.

-- One configuration row may exist for the one Forgejo connection. Absence
-- and a NULL due time both mean disabled. The positive revision is the form
-- CAS token and advances on every real enable or disable mutation.
CREATE TABLE forge_access_shadow_periodic_config (
  connection_id INTEGER PRIMARY KEY
    REFERENCES forge_connections(id) ON DELETE CASCADE
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  revision INTEGER NOT NULL
    CHECK (typeof(revision) = 'integer' AND revision > 0),
  next_due_at TEXT
    CHECK (
      next_due_at IS NULL
      OR (
        typeof(next_due_at) = 'text'
        AND length(next_due_at) = 30
        AND next_due_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
      )
    )
);

-- Additive semantics preserve every 0048 row as manual without rebuilding
-- the run table or its AUTOINCREMENT sequence. A manual requester may later
-- become NULL through the shipped ON DELETE SET NULL relationship. Periodic
-- work, by contrast, may never carry a human requester.
ALTER TABLE forge_access_shadow_runs
ADD COLUMN run_trigger TEXT NOT NULL DEFAULT 'manual'
  CHECK (
    typeof(run_trigger) = 'text'
    AND run_trigger IN ('manual', 'periodic')
    AND (run_trigger = 'manual' OR requested_by_user_id IS NULL)
  );
