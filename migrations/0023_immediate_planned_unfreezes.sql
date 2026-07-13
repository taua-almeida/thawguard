-- Generalize planned-unfreeze and recompute lookups to all branch freezes.
-- Existing scheduled rows and immediate rows are preserved unchanged.

DROP INDEX IF EXISTS idx_branch_freezes_planned_unfreeze_due;
CREATE INDEX idx_branch_freezes_planned_unfreeze_due
  ON branch_freezes(status, planned_ends_at, id)
  WHERE status = 'active' AND planned_ends_at IS NOT NULL;

DROP INDEX IF EXISTS idx_branch_freezes_scheduled_recompute;
CREATE INDEX idx_branch_freezes_recompute
  ON branch_freezes(needs_recompute, updated_at, id)
  WHERE needs_recompute = 1;
