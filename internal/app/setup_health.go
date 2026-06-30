package app

import (
	"context"
	"fmt"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type setupCheckRecorder interface {
	Record(ctx context.Context, repositoryID int64, branch string, results []setupcheck.Result) error
}

type localSetupHealthRunner struct {
	recorder setupCheckRecorder
}

func (r localSetupHealthRunner) Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error) {
	if r.recorder == nil {
		return nil, fmt.Errorf("local setup health runner has no recorder")
	}
	results := localSetupHealthResults()
	if err := r.recorder.Record(ctx, repo.ID, repo.DefaultBranch, results); err != nil {
		return nil, err
	}
	return results, nil
}

func localSetupHealthResults() []setupcheck.Result {
	return []setupcheck.Result{
		{
			Name:        "Bot status permission not verified locally",
			Status:      setupcheck.StatusWarning,
			Description: "This local placeholder does not contact Forgejo/Codeberg, so it cannot verify token status permissions.",
			Remediation: "Configure a bot token that can write repository commit statuses before relying on freezes.",
		},
		{
			Name:        "Required status context not verified locally",
			Status:      setupcheck.StatusWarning,
			Description: "This local placeholder does not read branch protection, so it cannot verify the required context " + domain.RequiredStatusContext + ".",
			Remediation: "Configure branch protection to require the exact context " + domain.RequiredStatusContext + ".",
		},
		{
			Name:        "Pull request webhook not verified locally",
			Status:      setupcheck.StatusWarning,
			Description: "This local placeholder does not inspect webhook delivery health.",
			Remediation: "Configure a pull_request webhook pointing at /webhooks/forgejo with a shared secret and verify deliveries before relying on automation.",
		},
	}
}
