package forgejo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
)

func TestAdapterInspectsHealthyForgejoSetup(t *testing.T) {
	adapter := Adapter{
		Client: fakeClient{
			CapabilityReport: forge.CapabilityReport{CanPostStatuses: true},
			BranchProtection: forge.BranchProtection{
				Branch:              "main",
				Protected:           true,
				RequiresStatusCheck: true,
				RequiredContexts:    []string{domain.RequiredStatusContext},
			},
		},
		WebhookConfigured: true,
	}

	report, err := adapter.Inspect(context.Background(), domain.Repository{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.CanPostStatuses || !report.RequiredContextPresent || !report.WebhookConfigured {
		t.Fatalf("expected healthy report, got %+v", report)
	}
}

func TestAdapterReportsMissingRequiredContext(t *testing.T) {
	adapter := Adapter{
		Client: fakeClient{
			CapabilityReport: forge.CapabilityReport{CanPostStatuses: true},
			BranchProtection: forge.BranchProtection{
				Branch:              "main",
				Protected:           true,
				RequiresStatusCheck: true,
				RequiredContexts:    []string{"ci/test"},
			},
		},
		WebhookConfigured: true,
	}

	report, err := adapter.Inspect(context.Background(), domain.Repository{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if report.RequiredContextPresent {
		t.Fatalf("expected missing required context, got %+v", report)
	}
}

func TestAdapterFailsClosedOnBranchMismatch(t *testing.T) {
	adapter := Adapter{
		Client: fakeClient{
			CapabilityReport: forge.CapabilityReport{CanPostStatuses: true},
			BranchProtection: forge.BranchProtection{
				Branch:              "dev",
				Protected:           true,
				RequiresStatusCheck: true,
				RequiredContexts:    []string{domain.RequiredStatusContext},
			},
		},
		WebhookConfigured: true,
	}

	report, err := adapter.Inspect(context.Background(), domain.Repository{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if report.RequiredContextPresent {
		t.Fatalf("expected branch mismatch to fail closed, got %+v", report)
	}
}

func TestAdapterReturnsClientError(t *testing.T) {
	adapter := Adapter{Client: fakeClient{CapabilitiesErr: errors.New("forge unavailable")}}
	_, err := adapter.Inspect(context.Background(), domain.Repository{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err == nil {
		t.Fatal("expected client error")
	}
	if !strings.Contains(err.Error(), "verify forge capabilities") {
		t.Fatalf("expected capabilities context, got %v", err)
	}
}

func TestAdapterReturnsBranchProtectionError(t *testing.T) {
	adapter := Adapter{Client: fakeClient{BranchProtectionErr: errors.New("branch protection unavailable")}}
	_, err := adapter.Inspect(context.Background(), domain.Repository{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err == nil {
		t.Fatal("expected client error")
	}
	if !strings.Contains(err.Error(), "read branch protection") {
		t.Fatalf("expected branch-protection context, got %v", err)
	}
}

type fakeClient struct {
	CapabilityReport    forge.CapabilityReport
	BranchProtection    forge.BranchProtection
	CapabilitiesErr     error
	BranchProtectionErr error
}

func (c fakeClient) VerifyCapabilities(ctx context.Context, owner, repo string) (forge.CapabilityReport, error) {
	if c.CapabilitiesErr != nil {
		return forge.CapabilityReport{}, c.CapabilitiesErr
	}
	return c.CapabilityReport, nil
}

func (c fakeClient) ReadBranchProtection(ctx context.Context, owner, repo, branch string) (forge.BranchProtection, error) {
	if c.BranchProtectionErr != nil {
		return forge.BranchProtection{}, c.BranchProtectionErr
	}
	return c.BranchProtection, nil
}
