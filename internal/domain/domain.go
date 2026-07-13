package domain

import (
	"errors"
	"time"
)

const RequiredStatusContext = "thawguard/freeze"

type CommitStatusState string

const (
	CommitStatusSuccess CommitStatusState = "success"
	CommitStatusFailure CommitStatusState = "failure"
	CommitStatusPending CommitStatusState = "pending"
	CommitStatusError   CommitStatusState = "error"
)

// EnforcementState is the persisted repository enforcement lifecycle. It is
// independent from Repository.Active, which controls whether the repository
// and its encrypted credentials can be loaded at all.
type EnforcementState string

const (
	EnforcementSetupIncomplete EnforcementState = "setup_incomplete"
	EnforcementReady           EnforcementState = "ready"
	EnforcementActive          EnforcementState = "active"
	EnforcementUnhealthy       EnforcementState = "unhealthy"
)

func (s EnforcementState) Valid() bool {
	switch s {
	case EnforcementSetupIncomplete, EnforcementReady, EnforcementActive, EnforcementUnhealthy:
		return true
	default:
		return false
	}
}

// EnforcementNotActiveMessage is the single operator-facing message for
// mutations that require active repository enforcement.
const EnforcementNotActiveMessage = "Repository enforcement is not active. Complete setup and activate enforcement before performing this action."

// ErrEnforcementNotActive guards non-form boundaries (publisher, forge sync)
// against posting for repositories whose enforcement is not active.
var ErrEnforcementNotActive = errors.New(EnforcementNotActiveMessage)

type Repository struct {
	ID               int64
	Forge            string
	BaseURL          string
	Owner            string
	Name             string
	DefaultBranch    string
	HasWebhookSecret bool
	HasStatusToken   bool
	Active           bool
	EnforcementState EnforcementState
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (r Repository) EnforcementActive() bool {
	return r.EnforcementState == EnforcementActive
}

// BranchNotManagedMessage is the single operator-facing message for freeze and
// scheduled-freeze creation against a branch outside the repository's managed
// branch scope.
const BranchNotManagedMessage = "Branch is not managed for this repository. Add it in repository setup before creating a freeze."

// RepositoryBranch is one exact managed branch name for a repository. Managed
// branches are the only branches freezes and scheduled freezes may target.
// SetupStatus stays "unknown" until real readiness checks verify the branch.
type RepositoryBranch struct {
	ID            int64
	RepositoryID  int64
	Name          string
	Protected     bool
	SetupStatus   string
	LastCheckedAt *time.Time
}

type Actor struct {
	UserID *int64
	Kind   string
	Role   string
}

const ActorKindBootstrapAdmin = "bootstrap_admin"
const ActorKindUser = "user"
const ActorKindSystem = "system"

func (r Repository) FullName() string {
	if r.Owner == "" {
		return r.Name
	}
	return r.Owner + "/" + r.Name
}

type PullRequest struct {
	ID           int64
	RepositoryID int64
	Index        int
	Title        string
	State        string
	TargetBranch string
	HeadSHA      string
	URL          string
}

func (pr PullRequest) IsOpen() bool {
	return pr.State == "open" || pr.State == ""
}

type BranchFreezeStatus string

const (
	BranchFreezeStatusScheduled BranchFreezeStatus = "scheduled"
	BranchFreezeStatusActive    BranchFreezeStatus = "active"
	BranchFreezeStatusEnded     BranchFreezeStatus = "ended"
	BranchFreezeStatusCancelled BranchFreezeStatus = "cancelled"
)

type BranchFreeze struct {
	ID             int64
	RepositoryID   int64
	Branch         string
	Status         BranchFreezeStatus
	Active         bool
	Scheduled      bool
	NeedsRecompute bool
	Reason         string
	StartsAt       *time.Time
	EndsAt         *time.Time
	PlannedEndsAt  *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ThawException struct {
	ID               int64
	RepositoryID     int64
	PullRequestID    int64
	PullRequestIndex int
	PullRequestURL   string
	HeadSHA          string
	TargetBranch     string
	Status           string
	Active           bool
	Reason           string
	ExpiresAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (t ThawException) IsActive(now time.Time) bool {
	if !t.Active {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}
