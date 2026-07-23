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
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
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

func TestSetUserRepositoryRolesIsIdempotentAndAuditsOnlyChanges(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")

	if _, err := service.DisableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}

	assertTargetDisabled := func(stage string) {
		t.Helper()
		record, err := service.userByID(ctx, database, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !record.Disabled() {
			t.Fatalf("expected target to remain disabled %s, got %+v", stage, record.User)
		}
	}
	assertTargetDisabled("before setting repository roles")

	// Advance the service clock between calls so a delete-and-reinsert bug
	// cannot accidentally preserve metadata merely because calls ran quickly.
	nextRoleSetTime := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time {
		now := nextRoleSetTime
		nextRoleSetTime = nextRoleSetTime.Add(time.Hour)
		return now
	}

	grantsByRole := func() map[Role]RepositoryGrant {
		t.Helper()
		grants, err := service.ListRepositoryGrants(ctx, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
		byRole := make(map[Role]RepositoryGrant, len(grants))
		for _, grant := range grants {
			if grant.RepositoryID != repositoryID || grant.UserID != user.ID {
				t.Fatalf("unexpected repository grant subject: %+v", grant)
			}
			if _, exists := byRole[grant.Role]; exists {
				t.Fatalf("duplicate stored repository role %q", grant.Role)
			}
			byRole[grant.Role] = grant
		}
		return byRole
	}

	assertRoleSet := func(stage string, grants map[Role]RepositoryGrant, want ...Role) {
		t.Helper()
		if len(grants) != len(want) {
			t.Fatalf("%s: expected roles %v, got %+v", stage, want, grants)
		}
		for _, role := range want {
			if _, exists := grants[role]; !exists {
				t.Fatalf("%s: expected role %q, got %+v", stage, role, grants)
			}
		}
	}

	assertAttributedGrant := func(stage string, grant RepositoryGrant) {
		t.Helper()
		if grant.GrantedByUserID == nil || *grant.GrantedByUserID != admin.User.ID {
			t.Fatalf("%s: expected grant attributed to admin %d, got %+v", stage, admin.User.ID, grant)
		}
		if grant.GrantedAt.IsZero() {
			t.Fatalf("%s: expected non-zero granted_at, got %+v", stage, grant)
		}
	}

	assertMetadataUnchanged := func(stage string, before, after RepositoryGrant) {
		t.Helper()
		if before.GrantedByUserID == nil || after.GrantedByUserID == nil || *before.GrantedByUserID != *after.GrantedByUserID {
			t.Fatalf("%s: granted_by_user_id changed from %+v to %+v", stage, before.GrantedByUserID, after.GrantedByUserID)
		}
		if !after.GrantedAt.Equal(before.GrantedAt) {
			t.Fatalf("%s: granted_at changed from %s to %s", stage, before.GrantedAt, after.GrantedAt)
		}
	}

	type grantAuditKey struct {
		action string
		role   Role
	}
	assertGrantAuditState := func(stage string, want map[grantAuditKey]int) {
		t.Helper()
		var total int
		if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action IN (?, ?)`, audit.ActionRepositoryGrantAdded, audit.ActionRepositoryGrantRevoked).Scan(&total); err != nil {
			t.Fatal(err)
		}
		wantTotal := 0
		for _, count := range want {
			wantTotal += count
		}
		if total != wantTotal {
			t.Fatalf("%s: expected %d repository grant audit events, got %d", stage, wantTotal, total)
		}
		for key, wantCount := range want {
			var gotCount int
			if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action = ?
  AND subject_type = ?
  AND subject_id = ?
  AND actor_user_id = ?
  AND json_valid(details_json)
  AND json_extract(details_json, '$.user_id') = ?
  AND json_extract(details_json, '$.role') = ?`, key.action, audit.SubjectTypeRepository, formatID(repositoryID), admin.User.ID, formatID(user.ID), string(key.role)).Scan(&gotCount); err != nil {
				t.Fatal(err)
			}
			if gotCount != wantCount {
				t.Fatalf("%s: expected %d %s audit events for role %q, got %d", stage, wantCount, key.action, key.role, gotCount)
			}
		}
	}

	initialAuditState := map[grantAuditKey]int{
		grantAuditKey{action: audit.ActionRepositoryGrantAdded, role: RoleViewer}:  1,
		grantAuditKey{action: audit.ActionRepositoryGrantAdded, role: RoleFreezer}: 1,
	}
	if err := service.SetUserRepositoryRoles(ctx, SetUserRepositoryRolesParams{
		ActorUserID:  admin.User.ID,
		RepositoryID: repositoryID,
		UserID:       user.ID,
		Roles:        []Role{RoleViewer, RoleFreezer, RoleViewer},
	}); err != nil {
		t.Fatalf("set initial roles for disabled target: %v", err)
	}
	assertTargetDisabled("after the initial role set")
	initialGrants := grantsByRole()
	assertRoleSet("initial role set", initialGrants, RoleViewer, RoleFreezer)
	initialViewer := initialGrants[RoleViewer]
	initialFreezer := initialGrants[RoleFreezer]
	assertAttributedGrant("initial viewer grant", initialViewer)
	assertAttributedGrant("initial freezer grant", initialFreezer)
	assertGrantAuditState("initial role set", initialAuditState)

	if err := service.SetUserRepositoryRoles(ctx, SetUserRepositoryRolesParams{
		ActorUserID:  admin.User.ID,
		RepositoryID: repositoryID,
		UserID:       user.ID,
		Roles:        []Role{RoleFreezer, RoleViewer, RoleFreezer},
	}); err != nil {
		t.Fatalf("repeat initial logical role set: %v", err)
	}
	assertTargetDisabled("after the repeated initial role set")
	repeatedInitialGrants := grantsByRole()
	assertRoleSet("repeated initial role set", repeatedInitialGrants, RoleViewer, RoleFreezer)
	assertMetadataUnchanged("viewer grant after initial no-op", initialViewer, repeatedInitialGrants[RoleViewer])
	assertMetadataUnchanged("freezer grant after initial no-op", initialFreezer, repeatedInitialGrants[RoleFreezer])
	assertGrantAuditState("repeated initial role set", initialAuditState)

	replacementAuditState := map[grantAuditKey]int{
		grantAuditKey{action: audit.ActionRepositoryGrantAdded, role: RoleViewer}:       1,
		grantAuditKey{action: audit.ActionRepositoryGrantAdded, role: RoleFreezer}:      1,
		grantAuditKey{action: audit.ActionRepositoryGrantAdded, role: RoleThawApprover}: 1,
		grantAuditKey{action: audit.ActionRepositoryGrantRevoked, role: RoleViewer}:     1,
	}
	if err := service.SetUserRepositoryRoles(ctx, SetUserRepositoryRolesParams{
		ActorUserID:  admin.User.ID,
		RepositoryID: repositoryID,
		UserID:       user.ID,
		Roles:        []Role{RoleFreezer, RoleThawApprover, RoleThawApprover},
	}); err != nil {
		t.Fatalf("replace logical role set: %v", err)
	}
	assertTargetDisabled("after replacing the role set")
	replacementGrants := grantsByRole()
	assertRoleSet("replacement role set", replacementGrants, RoleFreezer, RoleThawApprover)
	assertMetadataUnchanged("unchanged freezer grant after replacement", initialFreezer, replacementGrants[RoleFreezer])
	assertAttributedGrant("new thaw approver grant", replacementGrants[RoleThawApprover])
	assertGrantAuditState("replacement role set", replacementAuditState)

	if err := service.SetUserRepositoryRoles(ctx, SetUserRepositoryRolesParams{
		ActorUserID:  admin.User.ID,
		RepositoryID: repositoryID,
		UserID:       user.ID,
		Roles:        []Role{RoleThawApprover, RoleFreezer, RoleThawApprover},
	}); err != nil {
		t.Fatalf("repeat replacement logical role set: %v", err)
	}
	assertTargetDisabled("after the final no-op")
	finalGrants := grantsByRole()
	assertRoleSet("final no-op role set", finalGrants, RoleFreezer, RoleThawApprover)
	assertMetadataUnchanged("freezer grant after final no-op", replacementGrants[RoleFreezer], finalGrants[RoleFreezer])
	assertMetadataUnchanged("thaw approver grant after final no-op", replacementGrants[RoleThawApprover], finalGrants[RoleThawApprover])
	assertGrantAuditState("final no-op", replacementAuditState)
}

func TestDisabledTargetsRetainReceiveAndLoseGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
	viewer := mustCreateUser(t, ctx, service, "viewer@example.test", false)
	freezer := mustCreateUser(t, ctx, service, "freezer@example.test", false)
	approver := mustCreateUser(t, ctx, service, "approver@example.test", false)
	disabledAdmin := mustCreateUser(t, ctx, service, "former-admin@example.test", true)
	target := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
	lead := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
		t.Fatalf("expected lead's repository grant not to authorize another repository, got %+v", leadGrants)
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
	granter := mustCreateUser(t, ctx, service, "granter@example.test", true)
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
	user := mustCreateUser(t, ctx, service, "lead@example.test", false)
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
