-- Add one-time scheduled freeze window metadata to the existing branch_freezes table.

ALTER TABLE branch_freezes ADD COLUMN scheduled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE branch_freezes ADD COLUMN planned_ends_at TEXT;
ALTER TABLE branch_freezes ADD COLUMN needs_recompute INTEGER NOT NULL DEFAULT 0;

UPDATE branch_freezes
SET scheduled = 1
WHERE status = 'scheduled';

CREATE INDEX IF NOT EXISTS idx_branch_freezes_scheduled_due
  ON branch_freezes(status, starts_at, id)
  WHERE scheduled = 1 AND status = 'scheduled';

CREATE INDEX IF NOT EXISTS idx_branch_freezes_planned_unfreeze_due
  ON branch_freezes(status, planned_ends_at, id)
  WHERE scheduled = 1 AND status = 'active' AND planned_ends_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_branch_freezes_scheduled_recompute
  ON branch_freezes(needs_recompute, updated_at, id)
  WHERE scheduled = 1 AND needs_recompute = 1;
