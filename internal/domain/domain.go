package domain

import (
	"errors"
	"time"
)

const RequiredStatusContext = "thawguard/freeze"

// SetupStatusContext is the harmless status context used only for the
// controlled status-post verification. It is never the required merge-gating
// context, so posting it before activation cannot affect merges.
const SetupStatusContext = "thawguard/setup"

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

// EnforcementFailureReason values are the only persisted enforcement failure
// categories. They are stable, sanitized, and bounded by construction; raw
// wrapped errors, forge response bodies, and credentials never reach
// repository state.
const (
	EnforcementFailureReadinessChecks = "readiness checks failed"
	EnforcementFailureSetupStatusPost = "controlled setup status post failed"
	EnforcementFailureOpenPRSync      = "open pull request synchronization failed"
	EnforcementFailureEvaluation      = "status decision evaluation failed"
	EnforcementFailurePublication     = "status publication failed"
	EnforcementFailureRuntime         = "runtime enforcement convergence failed"
)

func ValidEnforcementFailureReason(reason string) bool {
	switch reason {
	case EnforcementFailureReadinessChecks, EnforcementFailureSetupStatusPost,
		EnforcementFailureOpenPRSync, EnforcementFailureEvaluation, EnforcementFailurePublication,
		EnforcementFailureRuntime:
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
	// StatusPostVerifiedAt is the latest successful controlled
	// thawguard/setup status post. It is cleared when the status token
	// changes.
	StatusPostVerifiedAt *time.Time
	// EnforcementFailureReason and EnforcementFailedAt describe the latest
	// sanitized enforcement failure. Both are set together when the
	// repository becomes unhealthy and cleared together only after a fully
	// successful activation, recovery, or reconciliation.
	EnforcementFailureReason string
	EnforcementFailedAt      *time.Time
	CreatedAt                time.Time
	UpdatedAt                time.Time
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
	// ScheduleID links a freeze materialized by a recurring schedule back to
	// that schedule; NULL for manual and one-time scheduled freezes, and
	// survives schedule deletion (ON DELETE SET NULL).
	ScheduleID *int64
	// CreatedByUserID references the user who started or scheduled the
	// freeze; NULL survives user deletion (ON DELETE SET NULL), so
	// CreatedByKind keeps removed users distinguishable from actors that
	// never had a user row.
	CreatedByUserID *int64
	CreatedByKind   string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ScheduleKind is immutable after creation: changing it would silently
// reinterpret every rule or window the schedule carries.
type ScheduleKind string

const (
	ScheduleKindWeekly ScheduleKind = "weekly"
	ScheduleKindDated  ScheduleKind = "dated"
)

func (k ScheduleKind) Valid() bool {
	return k == ScheduleKindWeekly || k == ScheduleKindDated
}

// Schedule is a named recurring freeze schedule for one exact managed branch.
// Timezone is a persisted IANA zone name — never a bare UTC offset — because
// offsets change with DST while zone rules do not. A schedule with
// Active == false never freezes anything.
type Schedule struct {
	ID           int64
	RepositoryID int64
	Branch       string
	Name         string
	Kind         ScheduleKind
	Timezone     string
	Reason       string
	Active       bool
	// SuppressedUntil is set when an operator manually ends this schedule's
	// materialized freeze: the schedule stays active but does not re-freeze
	// the branch until this UTC instant (its next scheduled window).
	SuppressedUntil *time.Time
	// CreatedByUserID survives user deletion as NULL (ON DELETE SET NULL);
	// CreatedByKind keeps removed users distinguishable from actors that
	// never had a user row, mirroring BranchFreeze.
	CreatedByUserID *int64
	CreatedByKind   string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ScheduleWeeklyRule is one weekly recurrence rule: a start weekday+time and
// an end weekday+time, minutes precision, no date component. Weekdays use Go's
// time.Weekday numbering (Sunday = 0). Comparing week-minutes
// (weekday*1440 + minutes), an end at or before its start wraps into the
// following week — that single convention encodes "Friday 16:00 → Monday
// 08:00". The schedule's timezone is applied only at expansion time.
type ScheduleWeeklyRule struct {
	ID           int64
	ScheduleID   int64
	StartWeekday time.Weekday
	StartTime    string
	EndWeekday   time.Weekday
	EndTime      string
	CreatedAt    time.Time
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
