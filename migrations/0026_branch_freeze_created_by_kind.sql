-- Record what kind of actor started each freeze. branch_freezes.created_by
-- uses ON DELETE SET NULL, so once a user is removed a NULL is ambiguous
-- between "removed user" and "bootstrap admin"; the kind column keeps them
-- distinguishable in the UI.
ALTER TABLE branch_freezes ADD COLUMN created_by_kind TEXT NOT NULL DEFAULT '';

-- Backfill from the creation audit events, which already carry actor_kind
-- in their details JSON. Rows without a matching event keep '' and the UI
-- omits the attribution.
UPDATE branch_freezes
SET created_by_kind = COALESCE(
    (
        SELECT json_extract(audit_events.details_json, '$.actor_kind')
        FROM audit_events
        WHERE audit_events.subject_type = 'branch_freeze'
          AND audit_events.subject_id = CAST(branch_freezes.id AS TEXT)
          AND audit_events.action IN ('branch_freeze.created', 'freeze_schedule.created')
        ORDER BY audit_events.id
        LIMIT 1
    ),
    ''
)
WHERE created_by_kind = '';
