-- Ensure only one active freeze exists for a repository branch.

CREATE UNIQUE INDEX IF NOT EXISTS idx_branch_freezes_one_active
  ON branch_freezes(repository_id, branch)
  WHERE status = 'active';
