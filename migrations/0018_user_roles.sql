-- Allow local users to hold multiple narrow roles.

CREATE TABLE IF NOT EXISTS user_roles (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'freezer', 'thaw_approver', 'viewer')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, role)
);

INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
SELECT id, role, created_at
FROM users
WHERE role IN ('admin', 'freezer', 'thaw_approver', 'viewer');

-- Existing admin rows predate explicit multi-role flags and previously carried
-- all operator capabilities. Preserve that bootstrap behavior for upgraded DBs;
-- newly-created admin-only users remain admin-only because the app writes
-- user_roles directly.
INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
SELECT id, 'freezer', created_at
FROM users
WHERE role = 'admin';

INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
SELECT id, 'thaw_approver', created_at
FROM users
WHERE role = 'admin';

INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
SELECT id, 'viewer', created_at
FROM users
WHERE role = 'admin';
