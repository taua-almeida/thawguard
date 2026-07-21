-- Weekly recurrence rules for weekly-kind schedules. A rule is a pure "shape
-- of a week": a start weekday+time and an end weekday+time, with no date,
-- month, or year — the schedule's IANA timezone is applied only at expansion
-- time, which is what makes DST handling possible at all.
--
-- Weekdays follow Go's time.Weekday: 0 = Sunday .. 6 = Saturday.
-- Times are minutes-precision wall clocks stored as "HH:MM".
--
-- Wrap encoding: comparing week-minutes (weekday*1440 + minutes), an end at
-- or before its start means the rule wraps into the following week. That one
-- convention encodes "Friday 16:00 -> Monday 08:00" without a flag column.
CREATE TABLE IF NOT EXISTS schedule_weekly_rules (
  id INTEGER PRIMARY KEY,
  schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
  start_weekday INTEGER NOT NULL CHECK (start_weekday BETWEEN 0 AND 6),
  start_time TEXT NOT NULL,
  end_weekday INTEGER NOT NULL CHECK (end_weekday BETWEEN 0 AND 6),
  end_time TEXT NOT NULL,
  created_at TEXT NOT NULL,
  -- An exact duplicate rule adds no coverage and would double-render on the
  -- rules card, so it is rejected rather than silently kept.
  UNIQUE (schedule_id, start_weekday, start_time, end_weekday, end_time)
);

-- ListRules filters by schedule_id on every detail render, and the FK's
-- ON DELETE CASCADE walks the same column when a schedule is deleted.
CREATE INDEX IF NOT EXISTS idx_schedule_weekly_rules_schedule
  ON schedule_weekly_rules(schedule_id);
