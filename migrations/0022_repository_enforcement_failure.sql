-- Latest sanitized enforcement failure shown on the repository page. Only a
-- stable bounded reason category and its timestamp are stored; raw forge
-- response bodies, tokens, webhook secrets, and payloads never reach
-- repository state. Both fields are set together when enforcement becomes
-- unhealthy and cleared together only after a fully successful activation,
-- recovery, or reconciliation. Existing repositories keep a null failure
-- state; historical details live in audit events.

ALTER TABLE repositories ADD COLUMN enforcement_failure_reason TEXT;
ALTER TABLE repositories ADD COLUMN enforcement_failed_at TEXT;
