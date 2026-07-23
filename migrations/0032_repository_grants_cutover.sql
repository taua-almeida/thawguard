-- Cut live authorization over from legacy global scoped roles to repository
-- grants. Legacy columns and rows remain for the later contract migration, but
-- this snapshot is the final compatibility read of them.

CREATE TEMP TABLE repository_grants_cutover_meta (
  cutover_at TEXT NOT NULL
);

INSERT INTO repository_grants_cutover_meta(cutover_at)
VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- user_roles is authoritative whenever a user has at least one explicit row.
-- users.role is consulted only for users with no explicit rows at all.
CREATE TEMP TABLE repository_grants_cutover_effective (
  user_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (user_id, role)
);

INSERT INTO repository_grants_cutover_effective(user_id, role)
SELECT ur.user_id, ur.role
FROM user_roles ur
WHERE ur.role IN ('admin', 'viewer', 'freezer', 'thaw_approver');

INSERT OR IGNORE INTO repository_grants_cutover_effective(user_id, role)
SELECT u.id, u.role
FROM users u
WHERE u.role IN ('admin', 'viewer', 'freezer', 'thaw_approver')
  AND NOT EXISTS (
    SELECT 1
    FROM user_roles ur
    WHERE ur.user_id = u.id
  );

-- Normalize every effective legacy Admin into explicit storage before runtime
-- stops consulting users.role. Existing explicit rows retain their metadata.
INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
SELECT effective.user_id, 'admin', meta.cutover_at
FROM repository_grants_cutover_effective effective
CROSS JOIN repository_grants_cutover_meta meta
WHERE effective.role = 'admin';

-- Stage only rows that do not already exist. This both preserves manual grant
-- attribution/timestamps and gives the audit insert the exact newly-added set.
CREATE TEMP TABLE repository_grants_cutover_new (
  repository_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (repository_id, user_id, role)
);

INSERT INTO repository_grants_cutover_new(repository_id, user_id, role, granted_at)
SELECT repositories.id, effective.user_id, effective.role, meta.cutover_at
FROM repository_grants_cutover_effective effective
CROSS JOIN repositories
CROSS JOIN repository_grants_cutover_meta meta
LEFT JOIN repository_grants existing
  ON existing.repository_id = repositories.id
 AND existing.user_id = effective.user_id
 AND existing.role = effective.role
WHERE effective.role IN ('viewer', 'freezer', 'thaw_approver')
  AND existing.repository_id IS NULL;

INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
SELECT repository_id, user_id, role, NULL, granted_at
FROM repository_grants_cutover_new;

-- Migration provenance is deliberately system-owned and allowlisted. There is
-- no fabricated human actor, and every newly inserted grant gets one durable
-- audit event so a later revocation cannot erase its origin.
INSERT INTO audit_events(actor_user_id, action, subject_type, subject_id, details_json, created_at)
SELECT
  NULL,
  'repository_grant.added',
  'repository',
  CAST(repository_id AS TEXT),
  json_object(
    'actor_kind', 'system',
    'actor_role', 'migration',
    'provenance', 'legacy_authorization_cutover',
    'user_id', CAST(user_id AS TEXT),
    'role', role
  ),
  granted_at
FROM repository_grants_cutover_new;

DROP TABLE repository_grants_cutover_new;
DROP TABLE repository_grants_cutover_effective;
DROP TABLE repository_grants_cutover_meta;
