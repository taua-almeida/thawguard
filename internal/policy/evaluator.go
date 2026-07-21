package policy

import (
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

type Input struct {
	PullRequest        domain.PullRequest
	ActiveFreeze       *domain.BranchFreeze
	ThawException      *domain.ThawException
	OpenPullRequests   []domain.PullRequest
	SharedHeadApproved bool
	Now                time.Time
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

	if thaw := input.ThawException; thaw != nil && thawMatchesPullRequest(*thaw, pr) && thaw.IsActive(now) {
		if duplicate := duplicateOpenHead(pr, input.OpenPullRequests); duplicate != nil && !input.SharedHeadApproved {
			return failure("Thaw blocked because another open PR shares this head SHA", "duplicate_head_sha")
		}
		return success("PR is explicitly thawed during an active freeze", "thawed_exception")
	}

	return failure(BuildFreezeDescription(FreezeDescriptionInput{
		ScheduleName: freeze.ScheduleName,
		Reason:       freeze.Reason,
	}), "active_freeze")
}

func thawMatchesPullRequest(thaw domain.ThawException, pr domain.PullRequest) bool {
	if thaw.HeadSHA != pr.HeadSHA {
		return false
	}
	if thaw.PullRequestID > 0 && pr.ID > 0 {
		return thaw.PullRequestID == pr.ID
	}
	return thaw.RepositoryID == pr.RepositoryID && thaw.PullRequestIndex == pr.Index && thaw.TargetBranch == pr.TargetBranch
}

func duplicateOpenHead(pr domain.PullRequest, openPRs []domain.PullRequest) *domain.PullRequest {
	for i := range openPRs {
		other := openPRs[i]
		if other.RepositoryID == pr.RepositoryID && other.Index == pr.Index {
			continue
		}
		if !other.IsOpen() {
			continue
		}
		if other.RepositoryID == pr.RepositoryID && other.HeadSHA == pr.HeadSHA {
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
