package auth

import (
	"reflect"
	"testing"

	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

func TestNewGrantsCopiesAdminAndNormalizedRepositoryRoles(t *testing.T) {
	scoped := map[int64]RoleSet{
		1:  {RoleFreezer, RoleAdmin},
		2:  {RoleAdmin},
		0:  {RoleFreezer},
		-3: {RoleViewer},
	}
	grants := NewGrants(true, scoped)

	if !grants.isAdmin {
		t.Fatal("expected explicit Admin state to be retained")
	}
	if len(grants.byRepository) != 1 {
		t.Fatalf("expected only repository 1 to keep grants, got %+v", grants.byRepository)
	}
	kept := grants.byRepository[1]
	if len(kept) != 1 || !kept.Contains(RoleFreezer) {
		t.Fatalf("expected repository 1 to keep only the freezer role, got %+v", kept)
	}
	scoped[1][0] = RoleViewer
	scoped[3] = RoleSet{RoleThawApprover}
	if !grants.CanFreezeRepository(1) || grants.CanThawRepository(3) {
		t.Fatalf("expected Grants to own an immutable copy of repository roles, got %+v", grants)
	}
}

func TestRepositoryRoleValidity(t *testing.T) {
	for _, role := range RepositoryRoles() {
		if !role.ValidForRepository() {
			t.Fatalf("expected %s to be valid for a repository", role)
		}
	}
	if RoleAdmin.ValidForRepository() {
		t.Fatal("expected admin to be invalid as a repository role")
	}
	if Role("owner").ValidForRepository() {
		t.Fatal("expected unknown role to be invalid as a repository role")
	}
}

func TestGrantsCapabilityMatrix(t *testing.T) {
	admin := NewGrants(true, nil)
	freezer := NewGrants(false, map[int64]RoleSet{1: {RoleFreezer}})
	approver := NewGrants(false, map[int64]RoleSet{1: {RoleThawApprover}})
	viewer := NewGrants(false, map[int64]RoleSet{1: {RoleViewer}})
	lead := NewGrants(false, map[int64]RoleSet{1: {RoleFreezer, RoleThawApprover}})
	nobody := NewGrants(false, nil)

	cases := []struct {
		name               string
		grants             Grants
		repositoryID       int64
		view, freeze, thaw bool
	}{
		{name: "admin views any repository", grants: admin, repositoryID: 7, view: true},
		{name: "admin never freezes or thaws", grants: admin, repositoryID: 1, view: true},
		{name: "scoped freezer freezes and views own repository", grants: freezer, repositoryID: 1, view: true, freeze: true},
		{name: "scoped thaw approver thaws and views own repository", grants: approver, repositoryID: 1, view: true, thaw: true},
		{name: "scoped viewer only views own repository", grants: viewer, repositoryID: 1, view: true},
		{name: "combined scoped roles freeze and thaw own repository", grants: lead, repositoryID: 1, view: true, freeze: true, thaw: true},
		{name: "grants never bleed into another repository", grants: lead, repositoryID: 2},
		{name: "no grants denies everything", grants: nobody, repositoryID: 1},
		{name: "zero repository id denies even admin", grants: admin, repositoryID: 0},
		{name: "negative repository id denies even admin", grants: admin, repositoryID: -1},
		{name: "zero repository id denies scoped freezer", grants: freezer, repositoryID: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grants.CanViewRepository(tc.repositoryID); got != tc.view {
				t.Fatalf("CanViewRepository(%d) = %v, want %v", tc.repositoryID, got, tc.view)
			}
			if got := tc.grants.CanFreezeRepository(tc.repositoryID); got != tc.freeze {
				t.Fatalf("CanFreezeRepository(%d) = %v, want %v", tc.repositoryID, got, tc.freeze)
			}
			if got := tc.grants.CanThawRepository(tc.repositoryID); got != tc.thaw {
				t.Fatalf("CanThawRepository(%d) = %v, want %v", tc.repositoryID, got, tc.thaw)
			}
		})
	}
}

func TestGrantsRepositoryReadScope(t *testing.T) {
	cases := []struct {
		name   string
		grants Grants
		want   repositoryscope.ReadScope
	}{
		{name: "admin reads every repository", grants: NewGrants(true, nil), want: repositoryscope.All()},
		{name: "scoped viewer reads own repository", grants: NewGrants(false, map[int64]RoleSet{7: {RoleViewer}}), want: repositoryscope.IDs(7)},
		{name: "scoped freezer reads own repository", grants: NewGrants(false, map[int64]RoleSet{7: {RoleFreezer}}), want: repositoryscope.IDs(7)},
		{name: "scoped thaw approver reads own repository", grants: NewGrants(false, map[int64]RoleSet{7: {RoleThawApprover}}), want: repositoryscope.IDs(7)},
		{name: "combined roles keep one id per repository", grants: NewGrants(false, map[int64]RoleSet{7: {RoleFreezer, RoleThawApprover}, 3: {RoleViewer}}), want: repositoryscope.IDs(3, 7)},
		{name: "no grants reads nothing", grants: NewGrants(false, nil), want: repositoryscope.ReadScope{}},
		{name: "zero-value grants reads nothing", grants: Grants{}, want: repositoryscope.ReadScope{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grants.RepositoryReadScope(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("RepositoryReadScope() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
