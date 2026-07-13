package forge

import (
	"context"
	"errors"
	"fmt"

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

// BranchHead is the current commit of one exact branch, fetched read-only for
// the controlled status-post verification and activation flow.
type BranchHead struct {
	Branch string
	SHA    string
}

var ErrBranchProtectionNotFound = errors.New("branch protection not found")

type ResponseError struct {
	Operation  string
	StatusCode int
	Status     string
	Snippet    string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("%s: forge returned %s: %s", e.Operation, e.Status, e.Snippet)
}

type Client interface {
	GetPullRequest(ctx context.Context, owner, repo string, index int) (domain.PullRequest, error)
	ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error)
	PostCommitStatus(ctx context.Context, owner, repo string, status CommitStatus) error
	ReadBranchProtection(ctx context.Context, owner, repo, branch string) (BranchProtection, error)
	GetBranchHead(ctx context.Context, owner, repo, branch string) (BranchHead, error)
}
