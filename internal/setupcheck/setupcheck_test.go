package setupcheck

import (
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestStableReadinessCheckNames(t *testing.T) {
	names := []string{
		CheckStatusTokenConfigured,
		CheckPullRequestReadAccess,
		CheckRecentVerifiedPullRequestWebhook,
		CheckStatusPostingUntested,
		CheckBranchProtectionReadable,
		CheckBranchProtectionEnabled,
		CheckRequiredStatusChecksEnabled,
		CheckRequiredThawguardFreezeContextConfigured,
	}
	if len(names) != 8 {
		t.Fatalf("expected eight stable check names, got %d", len(names))
	}
	if !strings.Contains(CheckRequiredThawguardFreezeContextConfigured, domain.RequiredStatusContext) {
		t.Fatalf("expected branch context check name to include %s", domain.RequiredStatusContext)
	}
}

func TestManualSetupStepsMentionRequiredContext(t *testing.T) {
	steps := strings.Join(ManualSetupSteps(), "\n")
	if !strings.Contains(steps, domain.RequiredStatusContext) {
		t.Fatalf("expected manual setup steps to mention %s", domain.RequiredStatusContext)
	}
}
