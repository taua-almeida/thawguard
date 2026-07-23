-- Contract authorization storage around one global Admin flag and
-- repository-scoped grants. The preceding cutover migration is the final
-- compatibility read of users.role and scoped user_roles rows.

CREATE TABLE user_roles_next (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role = 'admin'),
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, role)
);

INSERT INTO user_roles_next(user_id, role, created_at)
SELECT user_id, role, created_at
FROM user_roles
WHERE role = 'admin';

DROP TABLE user_roles;
ALTER TABLE user_roles_next RENAME TO user_roles;

ALTER TABLE users DROP COLUMN role;
