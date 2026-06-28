package jobs

import "time"

type Type string

const (
	RecomputePRStatus       Type = "recompute_pr_status"
	RecomputeBranchStatuses Type = "recompute_branch_statuses"
	ActivateScheduledFreeze Type = "activate_scheduled_freeze"
	ExecutePlannedUnfreeze  Type = "execute_planned_unfreeze"
	ExpireThawException     Type = "expire_thaw_exception"
	RetryStatusPost         Type = "retry_status_post"
	RunSetupCheck           Type = "run_setup_check"
	ReconcileOpenPRs        Type = "reconcile_open_prs"
)

type Job struct {
	ID        int64
	Type      Type
	Payload   string
	RunAt     time.Time
	Attempts  int
	CreatedAt time.Time
}
