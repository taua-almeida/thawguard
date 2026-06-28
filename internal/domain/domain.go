package domain

import "time"

const RequiredStatusContext = "thawguard/freeze"

type CommitStatusState string

const (
	CommitStatusSuccess CommitStatusState = "success"
	CommitStatusFailure CommitStatusState = "failure"
	CommitStatusPending CommitStatusState = "pending"
	CommitStatusError   CommitStatusState = "error"
)

type Repository struct {
	ID          int64
	Forge       string
	Owner       string
	Name        string
	DefaultBase string
	Active      bool
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

type BranchFreeze struct {
	ID           int64
	RepositoryID int64
	Branch       string
	Active       bool
	Reason       string
	StartsAt     *time.Time
	EndsAt       *time.Time
}

type ThawException struct {
	ID            int64
	PullRequestID int64
	HeadSHA       string
	Active        bool
	Reason        string
	ExpiresAt     *time.Time
}

func (t ThawException) IsActive(now time.Time) bool {
	if !t.Active {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}
