-- Latest successful controlled thawguard/setup status-post verification.
-- Readiness and activation happen in separate requests, so the timestamp is
-- the durable evidence that the stored status token proved it can post
-- statuses. It is cleared when the status token is replaced; historical
-- details live in audit events.

ALTER TABLE repositories ADD COLUMN status_post_verified_at TEXT;
