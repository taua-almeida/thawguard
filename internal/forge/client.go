package forge

import (
	"context"

	"github.com/taua-almeida/thawguard/internal/domain"
)

type CommitStatus struct {
	SHA         string
	State       domain.CommitStatusState
	Context     string
	Description string
	TargetURL   string
}

type BranchProtection struct {
	Branch              string
	RequiredContexts    []string
	Protected           bool
	RequiresStatusCheck bool
}

type CapabilityReport struct {
	CanReadPullRequests      bool
	CanPostStatuses          bool
	CanReadBranchProtection  bool
	CanWriteBranchProtection bool
	Warnings                 []string
}

type Client interface {
	GetPullRequest(ctx context.Context, owner, repo string, index int) (domain.PullRequest, error)
	ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error)
	PostCommitStatus(ctx context.Context, owner, repo string, status CommitStatus) error
	ReadBranchProtection(ctx context.Context, owner, repo, branch string) (BranchProtection, error)
	UpsertRequiredStatusContext(ctx context.Context, owner, repo, branch, contextName string) error
	VerifyCapabilities(ctx context.Context, owner, repo string) (CapabilityReport, error)
}
