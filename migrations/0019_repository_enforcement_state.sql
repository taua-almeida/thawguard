-- One enforcement mode: each repository carries an explicit enforcement
-- lifecycle state instead of a runtime dry-run/live publisher switch.
-- Existing and new repositories start setup-incomplete; activation only
-- happens once readiness checks land in a later migration/feature.

ALTER TABLE repositories ADD COLUMN enforcement_state TEXT NOT NULL DEFAULT 'setup_incomplete'
  CHECK (enforcement_state IN ('setup_incomplete', 'ready', 'active', 'unhealthy'));
