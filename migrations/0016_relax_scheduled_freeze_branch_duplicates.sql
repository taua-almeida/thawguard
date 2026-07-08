-- Scheduled freezes are plans. A repository branch may have multiple future
-- windows, and a scheduled window may become active while another freeze is
-- already active. Store-level validation still prevents duplicate manual
-- "freeze now" submissions in normal app flows.

DROP INDEX IF EXISTS idx_branch_freezes_one_open;
DROP INDEX IF EXISTS idx_branch_freezes_one_active;
