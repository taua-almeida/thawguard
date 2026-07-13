-- repository_branches becomes the managed-branch source of truth: freezes and
-- scheduled freezes are only accepted for exact managed branch names. Backfill
-- every repository default branch plus every branch that already appears in
-- branch_freezes so existing freeze and schedule rows stay valid. INSERT OR
-- IGNORE preserves existing branch rows and their recorded setup evidence.

INSERT OR IGNORE INTO repository_branches (repository_id, name)
SELECT id, default_branch
FROM repositories
WHERE default_branch <> '';

INSERT OR IGNORE INTO repository_branches (repository_id, name)
SELECT DISTINCT repository_id, branch
FROM branch_freezes
WHERE branch <> '';
