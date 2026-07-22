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
			Role:  auth.RoleFreezer,
			Roles: auth.RoleSet{auth.RoleFreezer},
		},
		Grants:    auth.NewGrants(auth.RoleSet{auth.RoleFreezer}, map[int64]auth.RoleSet{3: {auth.RoleFreezer}}),
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
