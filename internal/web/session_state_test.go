package web

import (
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
)

func TestSessionStateFromAuthCarriesGrants(t *testing.T) {
	session := auth.Session{
		ID:        "session-id",
		CSRFToken: "csrf-token",
		User: auth.User{
			ID:    7,
			Email: "lead@example.test",
		},
		Grants:    auth.NewGrants(false, map[int64]auth.RoleSet{3: {auth.RoleFreezer}}),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}

	state := sessionStateFromAuth(session)
	if !state.Grants.CanViewRepository(3) || !state.Grants.CanFreezeRepository(3) || state.Grants.CanThawRepository(3) {
		t.Fatalf("expected web session state to carry the scoped grant, got %+v", state.Grants)
	}
	if state.Grants.CanViewRepository(4) || state.Grants.CanFreezeRepository(4) {
		t.Fatalf("expected web session state grants not to bleed into another repository, got %+v", state.Grants)
	}
}

func TestCurrentUserLabelsDescribeAdminAndRepositoryAccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		grants auth.Grants
		want   string
	}{
		{name: "Admin", grants: auth.NewGrants(true, nil), want: "Admin"},
		{name: "repository access", grants: auth.NewGrants(false, map[int64]auth.RoleSet{3: {auth.RoleViewer}}), want: "Repository access"},
		{name: "no repository access", grants: auth.NewGrants(false, nil), want: "No repository access"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := currentUserFromSession(sessionState{Grants: test.grants}).RoleLabel; got != test.want {
				t.Fatalf("RoleLabel = %q, want %q", got, test.want)
			}
		})
	}
}
