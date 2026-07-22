package auth

import (
	"context"
	"testing"
)

func TestFirstAdminSessionCarriesAdminOnlyGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)

	session := mustCreateFirstAdmin(t, ctx, service)
	if !session.Grants.CanViewRepository(42) {
		t.Fatalf("expected first admin session to view repositories, got %+v", session.Grants)
	}
	if session.Grants.CanFreezeRepository(42) || session.Grants.CanThawRepository(42) {
		t.Fatalf("expected first admin session to hold no scoped freeze/thaw capability, got %+v", session.Grants)
	}
}

func TestLoginSessionCarriesCurrentRepositoryGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleFreezer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	otherRepositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "other")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}

	session, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if !session.Grants.CanViewRepository(repositoryID) || !session.Grants.CanFreezeRepository(repositoryID) || session.Grants.CanThawRepository(repositoryID) {
		t.Fatalf("expected login session to freeze and view only the granted repository, got %+v", session.Grants)
	}
	if session.Grants.CanViewRepository(otherRepositoryID) || session.Grants.CanFreezeRepository(otherRepositoryID) || session.Grants.CanThawRepository(otherRepositoryID) {
		t.Fatalf("expected login session grants not to bleed into another repository, got %+v", session.Grants)
	}
}

func TestChangePasswordSessionCarriesCurrentRepositoryGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "approver@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleThawApprover}); err != nil {
		t.Fatal(err)
	}

	session, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: user.ID, CurrentPassword: accountTestPassword, NewPassword: "an entirely new passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	if !session.Grants.CanViewRepository(repositoryID) || !session.Grants.CanThawRepository(repositoryID) || session.Grants.CanFreezeRepository(repositoryID) {
		t.Fatalf("expected rotated session to carry current scoped grants, got %+v", session.Grants)
	}
}

func TestSessionByIDRefreshesGrantsWithoutNewLogin(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	otherRepositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "other")

	session, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if session.Grants.CanFreezeRepository(repositoryID) {
		t.Fatalf("expected no freeze capability before the grant, got %+v", session.Grants)
	}

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := service.SessionByID(ctx, session.ID)
	if err != nil || !found {
		t.Fatalf("expected live session, found=%v err=%v", found, err)
	}
	if !loaded.Grants.CanFreezeRepository(repositoryID) || !loaded.Grants.CanViewRepository(repositoryID) {
		t.Fatalf("expected the next lookup to see the new grant without a new login, got %+v", loaded.Grants)
	}
	if loaded.Grants.CanFreezeRepository(otherRepositoryID) || loaded.Grants.CanViewRepository(otherRepositoryID) {
		t.Fatalf("expected the new grant not to bleed into another repository, got %+v", loaded.Grants)
	}

	if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	loaded, found, err = service.SessionByID(ctx, session.ID)
	if err != nil || !found {
		t.Fatalf("expected live session after revoke, found=%v err=%v", found, err)
	}
	if loaded.Grants.CanFreezeRepository(repositoryID) {
		t.Fatalf("expected the next lookup to drop the revoked grant, got %+v", loaded.Grants)
	}

	if _, err := service.DisableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, session.ID); err != nil || found {
		t.Fatalf("expected disabled user's session to stay rejected, found=%v err=%v", found, err)
	}
}
