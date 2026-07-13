package setupcheck

import (
	"context"

	"github.com/taua-almeida/thawguard/internal/domain"
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusWarning Status = "warning"
	StatusFailed  Status = "failed"

	CheckStatusTokenConfigured                    = "Status token configured"
	CheckPullRequestReadAccess                    = "Pull request read access"
	CheckRecentVerifiedPullRequestWebhook         = "Recent verified pull request webhook"
	CheckStatusPostingUntested                    = "Status posting has not been tested yet"
	CheckBranchProtectionReadable                 = "Branch protection readable"
	CheckBranchProtectionEnabled                  = "Branch protection enabled"
	CheckRequiredStatusChecksEnabled              = "Required status checks enabled"
	CheckRequiredThawguardFreezeContextConfigured = "Required thawguard/freeze context configured"
)

type Result struct {
	Name        string
	Status      Status
	Description string
	Remediation string
}

type BranchInspection struct {
	Results   []Result
	Protected bool
}

type Inspector interface {
	InspectPullRequestRead(ctx context.Context, repo domain.Repository, branch string) (Result, error)
	InspectBranch(ctx context.Context, repo domain.Repository, branch string) (BranchInspection, error)
}

func StatusFromBool(ok bool) Status {
	if ok {
		return StatusOK
	}
	return StatusFailed
}

func ManualSetupSteps() []string {
	return []string{
		"Store an encrypted Forgejo/Codeberg token so Thawguard can run read-only readiness checks.",
		"Add a pull_request webhook pointing at /webhooks/forgejo with the repository webhook secret.",
		"Configure branch protection to require the exact status context " + domain.RequiredStatusContext + ".",
		"Run readiness checks, then use the later controlled activation test to verify status posting.",
	}
}
