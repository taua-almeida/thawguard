package app

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statuspublisher"
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

// The runtime has exactly one status publisher construction path: the live
// Forgejo/Codeberg publisher. There is no dry-run/shadow selection left.
func TestRuntimeStatusPublisherIsForgejoOnly(t *testing.T) {
	ctx := context.Background()
	database := newAppTestDB(t, ctx)
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorysetup.NewService(database))
	if _, ok := publisher.(*statuspublisher.ForgejoStatusPublisher); !ok {
		t.Fatalf("expected runtime to wire the Forgejo status publisher, got %T", publisher)
	}
}

type fakeUserPresenceChecker struct {
	hasUsers bool
	err      error
}

func (f fakeUserPresenceChecker) HasUsers(context.Context) (bool, error) {
	return f.hasUsers, f.err
}
