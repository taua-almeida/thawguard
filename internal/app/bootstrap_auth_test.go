package app

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
)

func TestValidateBootstrapLocalBindAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		if err := validateBootstrapLocalBind(addr); err != nil {
			t.Fatalf("expected %q to be accepted: %v", addr, err)
		}
	}
}

func TestValidateInitialSetupBindAllowsNetworkBindAfterUsersExist(t *testing.T) {
	checker := fakeUserPresenceChecker{hasUsers: true}
	if err := validateInitialSetupBind(context.Background(), "0.0.0.0:8080", checker); err != nil {
		t.Fatalf("expected network bind after local users exist: %v", err)
	}
}

func TestValidateInitialSetupBindRejectsNetworkBindBeforeUsersExist(t *testing.T) {
	checker := fakeUserPresenceChecker{}
	if err := validateInitialSetupBind(context.Background(), "0.0.0.0:8080", checker); err == nil {
		t.Fatal("expected network bind to be rejected before first admin setup")
	}
}

func TestValidateInitialSetupBindReturnsUserCheckErrors(t *testing.T) {
	checker := fakeUserPresenceChecker{err: errors.New("database unavailable")}
	if err := validateInitialSetupBind(context.Background(), "127.0.0.1:8080", checker); err == nil {
		t.Fatal("expected user check error")
	}
}

func TestValidateBootstrapLocalBindRejectsNetworkBinds(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "192.0.2.1:8080"} {
		if err := validateBootstrapLocalBind(addr); err == nil {
			t.Fatalf("expected %q to be rejected", addr)
		}
	}
}

func TestStatusPublisherMode(t *testing.T) {
	for _, raw := range []string{"", "dry_run", " DRY_RUN "} {
		mode, err := statusPublisherMode(raw)
		if err != nil {
			t.Fatalf("expected %q to be accepted: %v", raw, err)
		}
		if mode != statuspublication.AttemptModeDryRun {
			t.Fatalf("expected dry_run mode for %q, got %q", raw, mode)
		}
	}
	mode, err := statusPublisherMode("forgejo_status")
	if err != nil {
		t.Fatal(err)
	}
	if mode != statuspublication.DeliveryModeForgejoStatus {
		t.Fatalf("expected forgejo status mode, got %q", mode)
	}
	if _, err := statusPublisherMode("live"); err == nil {
		t.Fatal("expected invalid publisher mode error")
	}
}

type fakeUserPresenceChecker struct {
	hasUsers bool
	err      error
}

func (f fakeUserPresenceChecker) HasUsers(context.Context) (bool, error) {
	return f.hasUsers, f.err
}

func TestValidateStatusPublisherConfigRequiresLiveOptIn(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode}, mode, true); err == nil {
		t.Fatal("expected forgejo status mode to require explicit live opt-in")
	}
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: "disabled"}, mode, true); err == nil {
		t.Fatal("expected invalid live opt-in value to be rejected")
	}
}

func TestValidateStatusPublisherConfigRequiresSecretKeyForLiveMode(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: "enabled"}, mode, false); err == nil {
		t.Fatal("expected forgejo status mode to require secret key")
	}
}

func TestValidateStatusPublisherConfigRequiresRepositoryAllowlistForLiveMode(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: "enabled"}, mode, true); err == nil {
		t.Fatal("expected forgejo status mode to require repository allowlist")
	}
}

func TestValidateStatusPublisherConfigAcceptsExplicitLiveMode(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: " ENABLED ", LiveStatusRepos: "taua-almeida/thawguard"}, mode, true); err != nil {
		t.Fatalf("expected explicit live mode to pass guardrails: %v", err)
	}
}

func TestLiveStatusRepositoriesParsesList(t *testing.T) {
	repositories := liveStatusRepositories("taua-almeida/thawguard, acme/api\nEXAMPLE/repo")
	if len(repositories) != 3 || repositories[0] != "taua-almeida/thawguard" || repositories[1] != "acme/api" || repositories[2] != "example/repo" {
		t.Fatalf("unexpected repository allowlist parse: %+v", repositories)
	}
}

func TestLiveStatusRepositoriesIgnoresMalformedEntries(t *testing.T) {
	repositories := liveStatusRepositories("not-a-full-name, /missing-owner, missing-name/")
	if len(repositories) != 0 {
		t.Fatalf("expected malformed allowlist entries to be ignored, got %+v", repositories)
	}
}

func TestValidateStatusPublisherConfigAllowsDryRun(t *testing.T) {
	if err := validateStatusPublisherConfig(config.Config{}, statuspublication.AttemptModeDryRun, false); err != nil {
		t.Fatalf("expected dry-run mode without live guardrails to pass: %v", err)
	}
}
