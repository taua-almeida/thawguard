-- Keep local status-publication intents idempotent per commit-status key.
-- status_results remains append-only history; this table stores the latest desired publication state.

ALTER TABLE status_publication_intents ADD COLUMN updated_at TEXT;

UPDATE status_publication_intents
SET updated_at = created_at
WHERE updated_at IS NULL OR updated_at = '';

DELETE FROM status_publication_intents
WHERE EXISTS (
  SELECT 1
  FROM status_publication_intents AS newer
  WHERE newer.repository_id = status_publication_intents.repository_id
    AND newer.head_sha = status_publication_intents.head_sha
    AND newer.context = status_publication_intents.context
    AND newer.delivery_mode = status_publication_intents.delivery_mode
    AND newer.id > status_publication_intents.id
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_status_publication_intents_idempotency
  ON status_publication_intents(repository_id, head_sha, context, delivery_mode);

CREATE INDEX IF NOT EXISTS idx_status_publication_intents_updated
  ON status_publication_intents(updated_at, id);
