package policy

import (
	"time"

	"github.com/calitaz/thawguard/internal/domain"
)

type Input struct {
	PullRequest      domain.PullRequest
	ActiveFreeze     *domain.BranchFreeze
	ThawException    *domain.ThawException
	OpenPullRequests []domain.PullRequest
	Now              time.Time
}

type Decision struct {
	State       domain.CommitStatusState
	Context     string
	Description string
	Reason      string
}

func Evaluate(input Input) Decision {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	pr := input.PullRequest
	if pr.HeadSHA == "" {
		return failure("PR head SHA is missing", "missing_head_sha")
	}

	freeze := input.ActiveFreeze
	if freeze == nil || !freeze.Active || freeze.Branch != pr.TargetBranch {
		return success("No active freeze applies to this PR", "not_frozen")
	}

	if thaw := input.ThawException; thaw != nil && thaw.PullRequestID == pr.ID && thaw.HeadSHA == pr.HeadSHA && thaw.IsActive(now) {
		if duplicate := duplicateOpenHead(pr, input.OpenPullRequests); duplicate != nil {
			return failure("Thaw blocked because another open PR shares this head SHA", "duplicate_head_sha")
		}
		return success("PR is explicitly thawed during an active freeze", "thawed_exception")
	}

	return failure("Branch is frozen; merge is blocked by Thawguard", "active_freeze")
}

func duplicateOpenHead(pr domain.PullRequest, openPRs []domain.PullRequest) *domain.PullRequest {
	for i := range openPRs {
		other := openPRs[i]
		if other.ID == pr.ID {
			continue
		}
		if !other.IsOpen() {
			continue
		}
		if other.RepositoryID == pr.RepositoryID && other.TargetBranch == pr.TargetBranch && other.HeadSHA == pr.HeadSHA {
			return &other
		}
	}
	return nil
}

func success(description, reason string) Decision {
	return Decision{State: domain.CommitStatusSuccess, Context: domain.RequiredStatusContext, Description: description, Reason: reason}
}

func failure(description, reason string) Decision {
	return Decision{State: domain.CommitStatusFailure, Context: domain.RequiredStatusContext, Description: description, Reason: reason}
}
