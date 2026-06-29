package forgejo

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type Client interface {
	ReadBranchProtection(ctx context.Context, owner, repo, branch string) (forge.BranchProtection, error)
	VerifyCapabilities(ctx context.Context, owner, repo string) (forge.CapabilityReport, error)
}

type Adapter struct {
	Client            Client
	WebhookConfigured bool
}

func (a Adapter) Inspect(ctx context.Context, repo domain.Repository) (setupcheck.Report, error) {
	if a.Client == nil {
		return setupcheck.Report{}, errors.New("forgejo setup inspector has no client")
	}
	capabilities, err := a.Client.VerifyCapabilities(ctx, repo.Owner, repo.Name)
	if err != nil {
		return setupcheck.Report{}, fmt.Errorf("verify forge capabilities: %w", err)
	}
	protection, err := a.Client.ReadBranchProtection(ctx, repo.Owner, repo.Name, repo.DefaultBranch)
	if err != nil {
		return setupcheck.Report{}, fmt.Errorf("read branch protection: %w", err)
	}
	branchMatches := protection.Branch == "" || protection.Branch == repo.DefaultBranch

	return setupcheck.Report{
		CanPostStatuses:        capabilities.CanPostStatuses,
		RequiredContextPresent: branchMatches && protection.Protected && protection.RequiresStatusCheck && slices.Contains(protection.RequiredContexts, domain.RequiredStatusContext),
		WebhookConfigured:      a.WebhookConfigured,
	}, nil
}

var _ setupcheck.Inspector = (*Adapter)(nil)
