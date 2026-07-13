package forgejo

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type Client interface {
	ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error)
	ReadBranchProtection(ctx context.Context, owner, repo, branch string) (forge.BranchProtection, error)
}

type Adapter struct {
	Client Client
}

func (a Adapter) InspectPullRequestRead(ctx context.Context, repo domain.Repository, branch string) (setupcheck.Result, error) {
	if a.Client == nil {
		return setupcheck.Result{}, errors.New("forgejo setup inspector has no client")
	}
	_, err := a.Client.ListOpenPullRequests(ctx, repo.Owner, repo.Name, branch)
	if err != nil {
		var responseErr *forge.ResponseError
		if errors.As(err, &responseErr) {
			switch responseErr.StatusCode {
			case 401, 403:
				return setupcheck.Result{
					Name:        setupcheck.CheckPullRequestReadAccess,
					Status:      setupcheck.StatusFailed,
					Description: "The forge denied the authenticated pull request list request.",
					Remediation: "Grant the stored token read access to pull requests for this repository.",
				}, nil
			case 404:
				return setupcheck.Result{
					Name:        setupcheck.CheckPullRequestReadAccess,
					Status:      setupcheck.StatusWarning,
					Description: "The forge did not expose the pull request list endpoint for this repository.",
					Remediation: "Confirm the repository URL and Forgejo/Codeberg API compatibility.",
				}, nil
			}
		}
		return setupcheck.Result{}, fmt.Errorf("read open pull requests: %w", err)
	}
	return setupcheck.Result{
		Name:        setupcheck.CheckPullRequestReadAccess,
		Status:      setupcheck.StatusOK,
		Description: "The authenticated forge request successfully read the open pull request list.",
		Remediation: "",
	}, nil
}

func (a Adapter) InspectBranch(ctx context.Context, repo domain.Repository, branch string) (setupcheck.BranchInspection, error) {
	if a.Client == nil {
		return setupcheck.BranchInspection{}, errors.New("forgejo setup inspector has no client")
	}
	protection, err := a.Client.ReadBranchProtection(ctx, repo.Owner, repo.Name, branch)
	if errors.Is(err, forge.ErrBranchProtectionNotFound) {
		return branchInspection(branch, false, false, nil), nil
	}
	if err != nil {
		return setupcheck.BranchInspection{}, fmt.Errorf("read branch protection for %q: %w", branch, err)
	}
	if strings.TrimSpace(protection.Branch) != branch {
		return setupcheck.BranchInspection{}, fmt.Errorf("read branch protection for %q: response branch mismatch", branch)
	}
	return branchInspection(branch, protection.Protected, protection.RequiresStatusCheck, protection.RequiredContexts), nil
}

func branchInspection(branch string, protected, statusChecks bool, contexts []string) setupcheck.BranchInspection {
	protectionDescription := "The forge returned branch protection configuration for this exact managed branch."
	if !protected {
		protectionDescription = "The forge confirmed that this exact managed branch has no branch protection configuration."
	}
	return setupcheck.BranchInspection{
		Protected: protected,
		Results: []setupcheck.Result{
			{Name: setupcheck.CheckBranchProtectionReadable, Status: setupcheck.StatusOK, Description: protectionDescription},
			{Name: setupcheck.CheckBranchProtectionEnabled, Status: setupcheck.StatusFromBool(protected), Description: "The exact managed branch must be protected.", Remediation: "Enable branch protection for " + branch + "."},
			{Name: setupcheck.CheckRequiredStatusChecksEnabled, Status: setupcheck.StatusFromBool(protected && statusChecks), Description: "Branch protection must enable required status checks.", Remediation: "Enable required status checks for " + branch + "."},
			{Name: setupcheck.CheckRequiredThawguardFreezeContextConfigured, Status: setupcheck.StatusFromBool(protected && statusChecks && slices.Contains(contexts, domain.RequiredStatusContext)), Description: "Required status checks must contain the exact context " + domain.RequiredStatusContext + ".", Remediation: "Add the exact context " + domain.RequiredStatusContext + " to branch protection for " + branch + "."},
		},
	}
}

var _ setupcheck.Inspector = Adapter{}
