-- Dated schedule windows: named one-off calendar windows for schedules of
-- kind 'dated'. starts_at and ends_at are local wall-clock timestamps in the
-- parent schedule's timezone ("2006-01-02T15:04"), not UTC instants: the
-- window means "these local dates and times", and the expander resolves them
-- to instants with the zone's DST rules at materialization time.
--
-- Rows are kept after the window passes only so re-adding an identical window
-- stays idempotent for occurrence bookkeeping; the UI never shows past
-- windows. Deleting the schedule cascades, which is safe because live freeze
-- rows snapshot the schedule name (below).
CREATE TABLE IF NOT EXISTS schedule_dated_windows (
  id INTEGER PRIMARY KEY,
  schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  -- Window names appear on the timeline and in forge status descriptions, so
  -- two same-named windows on one schedule would be indistinguishable there.
  UNIQUE (schedule_id, name)
);

-- Snapshot of the winning schedule's name at the moment the materializer
-- created (or last relabeled) the freeze row. The forge status description is
-- built from this snapshot, so hard-deleting a schedule mid-window cannot
-- silently relabel an already-posted status. Empty for manual freezes.
ALTER TABLE branch_freezes ADD COLUMN schedule_name TEXT NOT NULL DEFAULT '';
