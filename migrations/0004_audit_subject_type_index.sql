-- Speed up scoped audit history panels.

CREATE INDEX IF NOT EXISTS idx_audit_events_subject_type_id
  ON audit_events(subject_type, id DESC);
