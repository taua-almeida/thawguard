-- Repository-scoped role grants. Additive expand step: no data is moved from
-- user_roles or users.role; cutover and cleanup happen in later migrations.
-- granted_by_user_id is live attribution ("Added by ..."), so a deleted
-- granter clears it instead of deleting the grant.

CREATE TABLE IF NOT EXISTS repository_grants (
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('viewer', 'freezer', 'thaw_approver')),
  granted_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (repository_id, user_id, role)
);

CREATE INDEX IF NOT EXISTS idx_repository_grants_user_id
  ON repository_grants(user_id);
