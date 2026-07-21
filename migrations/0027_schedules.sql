-- Recurring freeze schedules. This table is only the schedule shell: an
-- operator-facing name, one exact managed branch, an explicit IANA timezone,
-- and an immutable kind. Weekly rules and dated windows live in their own
-- tables (not defined here), so a schedule row on its own never freezes
-- anything; active stays 0 until activation exists and is requested.
--
-- The timezone is stored as an IANA zone name (e.g. "America/Sao_Paulo"),
-- never as a bare UTC offset: offsets change with DST, zone rules do not.
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  branch TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('weekly', 'dated')),
  timezone TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_by_kind TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  -- The schedule name appears in forge status descriptions, so two schedules
  -- with the same name on the same branch would be indistinguishable there.
  UNIQUE (repository_id, branch, name)
);
