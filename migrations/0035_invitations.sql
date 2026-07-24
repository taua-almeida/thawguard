-- Managed invitations stage installation and repository authority without
-- granting it. Bearers are stored only as SHA-256 digests, and expiry uses
-- UTC Unix nanoseconds for an exact boundary comparison in the acceptance
-- slice.

CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY NOT NULL
    CHECK (
      typeof(id) = 'text'
      AND length(id) = 26
      AND substr(id, 1, 4) = 'inv_'
      AND substr(id, 5, 22) NOT GLOB '*[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]*'
      AND substr(id, 26, 1) IN ('A', 'Q', 'g', 'w')
    ),
  status TEXT NOT NULL
    CHECK (typeof(status) = 'text' AND status IN ('pending', 'needs_reissue', 'accepted', 'cancelled')),
  canonical_email TEXT,
  display_name TEXT,
  token_digest BLOB,
  expires_at INTEGER,
  is_admin INTEGER,
  authorized_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  expected_repository_grant_count INTEGER,
  created_at TEXT NOT NULL
    CHECK (typeof(created_at) = 'text' AND length(created_at) > 0),
  updated_at TEXT NOT NULL
    CHECK (typeof(updated_at) = 'text' AND length(updated_at) > 0),
  CHECK (
    CASE
      WHEN status = 'pending' THEN
        canonical_email IS NOT NULL
        AND typeof(canonical_email) = 'text'
        AND display_name IS NOT NULL
        AND typeof(display_name) = 'text'
        AND token_digest IS NOT NULL
        AND typeof(token_digest) = 'blob'
        AND length(token_digest) = 32
        AND expires_at IS NOT NULL
        AND typeof(expires_at) = 'integer'
        AND expires_at > 0
        AND is_admin IS NOT NULL
        AND typeof(is_admin) = 'integer'
        AND is_admin IN (0, 1)
        AND (authorized_by_user_id IS NULL OR (
          typeof(authorized_by_user_id) = 'integer'
          AND authorized_by_user_id > 0
        ))
        AND expected_repository_grant_count IS NOT NULL
        AND typeof(expected_repository_grant_count) = 'integer'
        AND expected_repository_grant_count >= 0
      WHEN status = 'needs_reissue' THEN
        canonical_email IS NOT NULL
        AND typeof(canonical_email) = 'text'
        AND display_name IS NOT NULL
        AND typeof(display_name) = 'text'
        AND token_digest IS NULL
        AND expires_at IS NULL
        AND is_admin IS NOT NULL
        AND typeof(is_admin) = 'integer'
        AND is_admin IN (0, 1)
        AND authorized_by_user_id IS NULL
        AND expected_repository_grant_count IS NOT NULL
        AND typeof(expected_repository_grant_count) = 'integer'
        AND expected_repository_grant_count >= 0
      WHEN status IN ('accepted', 'cancelled') THEN
        canonical_email IS NULL
        AND display_name IS NULL
        AND token_digest IS NULL
        AND expires_at IS NULL
        AND is_admin IS NULL
        AND authorized_by_user_id IS NULL
        AND expected_repository_grant_count IS NULL
      ELSE 0
    END
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token_digest
  ON invitations(token_digest)
  WHERE token_digest IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_active_canonical_email
  ON invitations(canonical_email)
  WHERE canonical_email IS NOT NULL
    AND status IN ('pending', 'needs_reissue');

CREATE TABLE IF NOT EXISTS invitation_repository_grants (
  invitation_id TEXT NOT NULL
    REFERENCES invitations(id) ON DELETE CASCADE
    CHECK (typeof(invitation_id) = 'text'),
  repository_id INTEGER NOT NULL
    REFERENCES repositories(id) ON DELETE CASCADE
    CHECK (typeof(repository_id) = 'integer' AND repository_id > 0),
  role TEXT NOT NULL
    CHECK (typeof(role) = 'text' AND role IN ('viewer', 'freezer', 'thaw_approver')),
  PRIMARY KEY (invitation_id, repository_id, role)
);
