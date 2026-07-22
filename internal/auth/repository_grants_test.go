package auth

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func TestGrantRepositoryRoleRoundTripWithAttribution(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	otherRepositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "other")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleThawApprover}); err != nil {
		t.Fatal(err)
	}

	grants, err := service.ListRepositoryGrants(ctx, repositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 {
		t.Fatalf("expected two grants, got %+v", grants)
	}
	for _, grant := range grants {
		if grant.RepositoryID != repositoryID || grant.UserID != user.ID {
			t.Fatalf("unexpected grant subject: %+v", grant)
		}
		if grant.GrantedByUserID == nil || *grant.GrantedByUserID != admin.User.ID {
			t.Fatalf("expected grant attributed to admin %d, got %+v", admin.User.ID, grant)
		}
		if grant.GrantedAt.IsZero() || time.Since(grant.GrantedAt) > time.Minute {
			t.Fatalf("expected a recent granted_at timestamp, got %+v", grant)
		}
	}
	if grants[0].Role != RoleFreezer || grants[1].Role != RoleThawApprover {
		t.Fatalf("expected grants ordered by role, got %+v", grants)
	}

	otherGrants, err := service.ListRepositoryGrants(ctx, otherRepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherGrants) != 0 {
		t.Fatalf("expected no grants to bleed into another repository, got %+v", otherGrants)
	}

	assertRepositoryGrantAuditEvent(t, ctx, database, audit.ActionRepositoryGrantAdded, repositoryID, admin.User.ID, `"user_id":"`+formatID(user.ID)+`"`)
	assertRepositoryGrantAuditEvent(t, ctx, database, audit.ActionRepositoryGrantAdded, repositoryID, admin.User.ID, `"role":"freezer"`)
}

func TestGrantRepositoryRoleRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleAdmin}); !IsValidationError(err) {
		t.Fatalf("expected admin repository grant to be rejected, got %v", err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID + 100, UserID: user.ID, Role: RoleViewer}); !IsValidationError(err) {
		t.Fatalf("expected unknown repository to be rejected, got %v", err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: -1, UserID: user.ID, Role: RoleViewer}); !IsValidationError(err) {
		t.Fatalf("expected invalid repository id to be rejected, got %v", err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID + 100, Role: RoleViewer}); !IsValidationError(err) {
		t.Fatalf("expected unknown user to be rejected, got %v", err)
	}

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); !IsValidationError(err) {
		t.Fatalf("expected duplicate grant to be rejected, got %v", err)
	}

	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ?`, audit.ActionRepositoryGrantAdded).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected rejected grants to record no audit events, got %d", count)
	}
}

func TestDisabledTargetsRetainReceiveAndLoseGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DisableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleViewer}); err != nil {
		t.Fatalf("expected disabled user to accept a grant, got %v", err)
	}

	grants, err := service.GrantsForUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !grants.CanFreezeRepository(repositoryID) || !grants.CanViewRepository(repositoryID) {
		t.Fatalf("expected disabled user's retained and new grants to stay readable for administration, got %+v", grants)
	}

	if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleViewer}); err != nil {
		t.Fatalf("expected disabled user to lose a grant, got %v", err)
	}
}

func TestRepositoryGrantMutationsRequireEnabledAdminActor(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	viewer := mustCreateUser(t, ctx, service, "viewer@example.test", []Role{RoleViewer})
	freezer := mustCreateUser(t, ctx, service, "freezer@example.test", []Role{RoleFreezer})
	approver := mustCreateUser(t, ctx, service, "approver@example.test", []Role{RoleThawApprover})
	disabledAdmin := mustCreateUser(t, ctx, service, "former-admin@example.test", []Role{RoleAdmin})
	target := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if _, err := service.DisableUser(ctx, admin.User.ID, disabledAdmin.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: target.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		actor int64
	}{
		{name: "viewer actor", actor: viewer.ID},
		{name: "freezer actor", actor: freezer.ID},
		{name: "thaw approver actor", actor: approver.ID},
		{name: "disabled admin actor", actor: disabledAdmin.ID},
		{name: "unknown actor", actor: target.ID + 100},
		{name: "zero actor", actor: 0},
		{name: "negative actor", actor: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: tc.actor, RepositoryID: repositoryID, UserID: target.ID, Role: RoleViewer}); !IsValidationError(err) {
				t.Fatalf("expected grant by non-admin actor to be rejected, got %v", err)
			}
			if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: tc.actor, RepositoryID: repositoryID, UserID: target.ID, Role: RoleFreezer}); !IsValidationError(err) {
				t.Fatalf("expected revoke by non-admin actor to be rejected, got %v", err)
			}
		})
	}

	grants, err := service.ListRepositoryGrants(ctx, repositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Role != RoleFreezer {
		t.Fatalf("expected rejected mutations to leave the admin's grant untouched, got %+v", grants)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action IN (?, ?)`, audit.ActionRepositoryGrantAdded, audit.ActionRepositoryGrantRevoked).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected rejected mutations to record no audit events, got %d", count)
	}
}

func TestRevokeRepositoryRole(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}

	grants, err := service.ListRepositoryGrants(ctx, repositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected revoked grant to disappear, got %+v", grants)
	}
	assertRepositoryGrantAuditEvent(t, ctx, database, audit.ActionRepositoryGrantRevoked, repositoryID, admin.User.ID, `"role":"freezer"`)

	if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); !IsValidationError(err) {
		t.Fatalf("expected revoking a missing grant to be rejected, got %v", err)
	}
	if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleAdmin}); !IsValidationError(err) {
		t.Fatalf("expected revoking an admin repository role to be rejected, got %v", err)
	}
}

func TestGrantsForUserCombinesGlobalAdminAndScopedRoles(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	lead := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleFreezer, RoleThawApprover})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	otherRepositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "other")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: lead.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}

	leadGrants, err := service.GrantsForUser(ctx, lead.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !leadGrants.CanViewRepository(repositoryID) || !leadGrants.CanFreezeRepository(repositoryID) || leadGrants.CanThawRepository(repositoryID) {
		t.Fatalf("expected lead to view and freeze only the granted repository, got %+v", leadGrants)
	}
	if leadGrants.CanViewRepository(otherRepositoryID) || leadGrants.CanFreezeRepository(otherRepositoryID) {
		t.Fatalf("expected lead's legacy global roles to authorize nothing elsewhere, got %+v", leadGrants)
	}

	adminGrants, err := service.GrantsForUser(ctx, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !adminGrants.CanViewRepository(repositoryID) || !adminGrants.CanViewRepository(otherRepositoryID) {
		t.Fatalf("expected admin to view every repository, got %+v", adminGrants)
	}
	if adminGrants.CanFreezeRepository(repositoryID) || adminGrants.CanThawRepository(repositoryID) {
		t.Fatalf("expected admin to gain no freeze/thaw capability, got %+v", adminGrants)
	}

	if _, err := service.GrantsForUser(ctx, lead.ID+100); !IsValidationError(err) {
		t.Fatalf("expected unknown user to be rejected, got %v", err)
	}
}

func TestRepositoryGrantSurvivesGranterDeletionWithoutAttribution(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	mustCreateFirstAdmin(t, ctx, service)
	granter := mustCreateUser(t, ctx, service, "granter@example.test", []Role{RoleAdmin})
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: granter.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleViewer}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, granter.ID); err != nil {
		t.Fatal(err)
	}

	grants, err := service.ListRepositoryGrants(ctx, repositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].UserID != user.ID {
		t.Fatalf("expected the grant to survive granter deletion, got %+v", grants)
	}
	if grants[0].GrantedByUserID != nil {
		t.Fatalf("expected attribution cleared after granter deletion, got %+v", grants[0])
	}
}

func TestRepositoryGrantMutationsRollBackWhenAuditPersistenceFails(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleViewer})
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleThawApprover}); err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(ctx, `ALTER TABLE audit_events_broken RENAME TO audit_events`)
	})

	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err == nil || IsValidationError(err) {
		t.Fatalf("expected internal error when audit persistence fails, got %v", err)
	}
	if err := service.RevokeRepositoryRole(ctx, RevokeRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleThawApprover}); err == nil || IsValidationError(err) {
		t.Fatalf("expected internal error when audit persistence fails, got %v", err)
	}

	grants, err := service.ListRepositoryGrants(ctx, repositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Role != RoleThawApprover {
		t.Fatalf("expected both mutations to roll back, got %+v", grants)
	}
}

func mustCreateTestRepository(t *testing.T, ctx context.Context, database *sql.DB, owner, name string) int64 {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := database.ExecContext(ctx, `
INSERT INTO repositories(forge, base_url, owner, name, default_branch, created_at, updated_at)
VALUES ('forgejo', 'https://forge.example.test', ?, ?, 'main', ?, ?)`, owner, name, now, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertRepositoryGrantAuditEvent(t *testing.T, ctx context.Context, database *sql.DB, action string, repositoryID int64, actorUserID int64, detailsFragment string) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action = ? AND subject_type = 'repository' AND subject_id = ? AND actor_user_id = ? AND details_json LIKE '%' || ? || '%'`, action, formatID(repositoryID), actorUserID, detailsFragment).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("expected audit event %s for repository %d by actor %d containing %s", action, repositoryID, actorUserID, detailsFragment)
	}
}

func formatID(id int64) string {
	return strconv.FormatInt(id, 10)
}
