CREATE TABLE webhook_deliveries_next (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER REFERENCES repositories(id) ON DELETE SET NULL,
  delivery_id TEXT NOT NULL,
  event TEXT NOT NULL,
  action TEXT,
  received_at TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  processing_started_at TEXT,
  processed_at TEXT,
  error TEXT,
  UNIQUE (repository_id, delivery_id)
);

INSERT INTO webhook_deliveries_next(id, repository_id, delivery_id, event, action, received_at, verified, processing_started_at, processed_at, error)
SELECT id, repository_id, delivery_id, event, action, received_at, verified, NULL,
  CASE WHEN error = 'webhook processing failed' THEN NULL ELSE processed_at END,
  error
FROM webhook_deliveries;

DROP TABLE webhook_deliveries;

ALTER TABLE webhook_deliveries_next RENAME TO webhook_deliveries;
