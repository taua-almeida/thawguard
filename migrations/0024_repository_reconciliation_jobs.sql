-- Add durable, repository-scoped enforcement convergence work to the existing
-- jobs table. Existing generic jobs remain intact and have NULL repository IDs.

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  run_at TEXT NOT NULL,
  locked_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL
);

ALTER TABLE jobs ADD COLUMN repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE;
ALTER TABLE jobs ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX idx_jobs_one_repository_reconciliation
  ON jobs(repository_id)
  WHERE type = 'reconcile_repository_enforcement' AND repository_id IS NOT NULL;

CREATE INDEX idx_jobs_repository_reconciliation_due
  ON jobs(type, run_at, locked_at, id)
  WHERE type = 'reconcile_repository_enforcement' AND repository_id IS NOT NULL;

-- Move unfinished work from the former in-memory/branch retry paths into the
-- durable repository queue. INSERT OR IGNORE preserves any job already queued.
INSERT OR IGNORE INTO jobs(
  type,
  payload_json,
  run_at,
  repository_id,
  generation,
  created_at
)
SELECT
  'reconcile_repository_enforcement',
  '{}',
  strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'),
  repositories.id,
  1,
  strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')
FROM repositories
WHERE enforcement_state = 'unhealthy'
   OR EXISTS (
     SELECT 1
     FROM branch_freezes
     WHERE branch_freezes.repository_id = repositories.id
       AND branch_freezes.needs_recompute = 1
   );
