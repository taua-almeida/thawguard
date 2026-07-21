-- Schedule materialization: link branch_freezes rows created by a recurring
-- schedule back to that schedule, and record per-schedule suppression when an
-- operator manually ends a materialized occurrence ("thaw until next window").
--
-- schedule_id is SET NULL on schedule deletion so a historical freeze row
-- outlives its schedule; the freeze's own reason and audit trail keep the
-- human-readable context.
ALTER TABLE branch_freezes ADD COLUMN schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL;

-- suppressed_until is a UTC instant (same text format as the other timestamp
-- columns). NULL means the schedule is not suppressed. While now <
-- suppressed_until the materializer ignores this schedule's coverage; the
-- schedule stays active and resumes at its next window.
ALTER TABLE schedules ADD COLUMN suppressed_until TEXT;

-- The materializer looks up the live freeze row for a schedule on every tick.
CREATE INDEX idx_branch_freezes_schedule
ON branch_freezes(schedule_id, status)
WHERE schedule_id IS NOT NULL;
