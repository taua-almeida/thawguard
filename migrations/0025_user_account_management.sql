-- Track local account disable state and admin-forced password changes.
-- Existing users stay enabled with no forced password change; existing
-- sessions and explicit roles are untouched.

ALTER TABLE users ADD COLUMN disabled_at TEXT;
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
