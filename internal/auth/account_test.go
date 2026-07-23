package auth

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const accountTestPassword = "correct horse battery staple"

func TestSetUserAdminChangesOnlyGlobalAdminAndPrimaryRole(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", nil)

	updated, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: user.ID, Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Roles.Contains(RoleAdmin) || len(updated.Roles) != 1 || updated.Role != RoleAdmin {
		t.Fatalf("unexpected updated user: %+v", updated)
	}
	updated, err = service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: user.ID, Admin: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Roles) != 0 || updated.Role != "" {
		t.Fatalf("expected no live global role after demotion, got %+v", updated)
	}

	var storedPrimary string
	if err := database.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, user.ID).Scan(&storedPrimary); err != nil {
		t.Fatal(err)
	}
	if storedPrimary != string(RoleViewer) {
		t.Fatalf("expected primary role column synchronized to viewer, got %q", storedPrimary)
	}
	var roleCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ?`, user.ID).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if roleCount != 0 {
		t.Fatalf("expected Admin row removed atomically, got %d rows", roleCount)
	}
	assertAuditEvent(t, ctx, database, audit.ActionUserRolesUpdated, user.ID, admin.User.ID)
}

func TestSetUserAdminRequiresEnabledAdminActorAndExistingTarget(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "viewer@example.test", nil)

	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: user.ID, UserID: user.ID, Admin: true}); !IsValidationError(err) {
		t.Fatalf("expected non-Admin actor rejection, got %v", err)
	}
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: 9999, Admin: true}); !IsValidationError(err) {
		t.Fatalf("expected missing user rejection, got %v", err)
	}
	loaded, err := service.userByID(ctx, database, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Roles) != 0 {
		t.Fatalf("expected rejected updates to leave zero global access, got %+v", loaded.Roles)
	}
}

func TestSetUserAdminIsVisibleThroughExistingSession(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", nil)
	session, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: user.ID, Admin: true}); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := service.SessionByID(ctx, session.ID)
	if err != nil || !found {
		t.Fatalf("expected session to remain valid, found=%v err=%v", found, err)
	}
	if !loaded.Grants.CanManageInstallation() || !loaded.User.Roles.Contains(RoleAdmin) {
		t.Fatalf("expected existing session to hydrate current Admin authority, got %+v", loaded)
	}
}

func TestSetUserAdminProtectsFinalEnabledAdmin(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)

	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: admin.User.ID, Admin: false}); !IsValidationError(err) {
		t.Fatalf("expected final enabled admin role removal to be rejected, got %v", err)
	}
	loaded, err := service.userByID(ctx, database, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Roles.Contains(RoleAdmin) {
		t.Fatalf("expected admin role preserved after rejected update, got %+v", loaded.Roles)
	}

	secondAdmin := mustCreateUser(t, ctx, service, "second@example.test", []Role{RoleAdmin})
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: admin.User.ID, Admin: false}); err != nil {
		t.Fatalf("expected role removal with a second enabled admin to succeed, got %v", err)
	}

	// A disabled admin does not satisfy the invariant: restore admin first,
	// disable the second admin, then attempt removal again.
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: secondAdmin.ID, UserID: admin.User.ID, Admin: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DisableUser(ctx, admin.User.ID, secondAdmin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: admin.User.ID, Admin: false}); !IsValidationError(err) {
		t.Fatalf("expected role removal to be rejected while the other admin is disabled, got %v", err)
	}
}

func TestDisableUserRevokesSessionsAndBlocksLogin(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "freezer@example.test", nil)
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	firstSession, err := service.Login(ctx, LoginParams{Email: "freezer@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "freezer@example.test", Password: accountTestPassword}); err != nil {
		t.Fatal(err)
	}

	disabled, err := service.DisableUser(ctx, admin.User.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Disabled() {
		t.Fatalf("expected disabled user state, got %+v", disabled)
	}
	var sessionCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = ?`, user.ID).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected all sessions revoked on disable, got %d", sessionCount)
	}
	if _, found, err := service.SessionByID(ctx, firstSession.ID); err != nil || found {
		t.Fatalf("expected revoked session to be gone, found=%v err=%v", found, err)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "freezer@example.test", Password: accountTestPassword}); !IsAuthenticationError(err) {
		t.Fatalf("expected generic authentication error for disabled login, got %v", err)
	}
	assertAuditEvent(t, ctx, database, audit.ActionUserDisabled, user.ID, admin.User.ID)
}

func TestSessionByIDRejectsAndDeletesSessionsOfDisabledUsers(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "freezer@example.test", []Role{RoleFreezer})
	session, err := service.Login(ctx, LoginParams{Email: "freezer@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}

	// Disable directly in SQL to simulate a session that survived revocation.
	if _, err := database.ExecContext(ctx, `UPDATE users SET disabled_at = '2026-07-13T00:00:00.000000000Z' WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, session.ID); err != nil || found {
		t.Fatalf("expected disabled user's session to be rejected, found=%v err=%v", found, err)
	}
	var sessionCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = ?`, session.ID).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected rejected session to be deleted defensively, got %d", sessionCount)
	}
}

func TestEnableUserPermitsLoginWithoutRestoringSessions(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "freezer@example.test", nil)
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	oldSession, err := service.Login(ctx, LoginParams{Email: "freezer@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DisableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnableUser(ctx, admin.User.ID, user.ID); !IsValidationError(err) {
		t.Fatalf("expected enable of enabled user to be rejected, got %v", err)
	}
	if _, found, err := service.SessionByID(ctx, oldSession.ID); err != nil || found {
		t.Fatalf("expected re-enable to restore no old session, found=%v err=%v", found, err)
	}
	newSession, err := service.Login(ctx, LoginParams{Email: "freezer@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatalf("expected re-enabled user to log in with preserved password, got %v", err)
	}
	if !newSession.Grants.CanFreezeRepository(repositoryID) {
		t.Fatalf("expected re-enabled user to keep repository grants, got %+v", newSession.Grants)
	}
	assertAuditEvent(t, ctx, database, audit.ActionUserEnabled, user.ID, admin.User.ID)
}

func TestDisableUserProtectsFinalEnabledAdmin(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)

	if _, err := service.DisableUser(ctx, admin.User.ID, admin.User.ID); !IsValidationError(err) {
		t.Fatalf("expected final enabled admin disable to be rejected, got %v", err)
	}
	loaded, err := service.userByID(ctx, database, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Disabled() {
		t.Fatalf("expected admin to stay enabled after rejected disable, got %+v", loaded.User)
	}

	secondAdmin := mustCreateUser(t, ctx, service, "second@example.test", []Role{RoleAdmin})
	if _, err := service.DisableUser(ctx, admin.User.ID, secondAdmin.ID); err != nil {
		t.Fatalf("expected disabling one of two enabled admins to succeed, got %v", err)
	}
	if _, err := service.DisableUser(ctx, admin.User.ID, admin.User.ID); !IsValidationError(err) {
		t.Fatalf("expected disable to be rejected while the other admin is disabled, got %v", err)
	}
	if _, err := service.EnableUser(ctx, admin.User.ID, secondAdmin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DisableUser(ctx, secondAdmin.ID, admin.User.ID); err != nil {
		t.Fatalf("expected disable to succeed after re-enabling the other admin, got %v", err)
	}
}

func TestConcurrentDisablesCannotCommitZeroEnabledAdmins(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	secondAdmin := mustCreateUser(t, ctx, service, "second@example.test", []Role{RoleAdmin})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = service.DisableUser(ctx, admin.User.ID, secondAdmin.ID)
	}()
	go func() {
		defer wg.Done()
		_, _ = service.DisableUser(ctx, secondAdmin.ID, admin.User.ID)
	}()
	wg.Wait()

	var enabledAdmins int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM users u
JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
WHERE u.disabled_at IS NULL`).Scan(&enabledAdmins); err != nil {
		t.Fatal(err)
	}
	if enabledAdmins < 1 {
		t.Fatalf("expected at least one enabled admin after concurrent disables, got %d", enabledAdmins)
	}
}

func TestChangePasswordValidatesCurrentPasswordAndNewPassword(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)

	if _, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: admin.User.ID, CurrentPassword: "wrong password entirely", NewPassword: "a brand new local password"}); !IsValidationError(err) {
		t.Fatalf("expected wrong current password rejection, got %v", err)
	}
	if _, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: admin.User.ID, CurrentPassword: accountTestPassword, NewPassword: "short"}); !IsValidationError(err) {
		t.Fatalf("expected short new password rejection, got %v", err)
	}
	if _, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: admin.User.ID, CurrentPassword: accountTestPassword, NewPassword: strings.Repeat("a", 1025)}); !IsValidationError(err) {
		t.Fatalf("expected overlong new password rejection, got %v", err)
	}
	if _, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: admin.User.ID, CurrentPassword: accountTestPassword, NewPassword: accountTestPassword}); !IsValidationError(err) {
		t.Fatalf("expected password reuse rejection, got %v", err)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "admin@example.test", Password: accountTestPassword}); err != nil {
		t.Fatalf("expected password unchanged after rejected changes, got %v", err)
	}
}

func TestChangePasswordRotatesSessionRevokesOthersAndClearsForcedFlag(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleFreezer})
	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); err != nil {
		t.Fatal(err)
	}
	tempSession, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: "temporary local password"})
	if err != nil {
		t.Fatal(err)
	}
	if !tempSession.User.MustChangePassword {
		t.Fatalf("expected temporary-password login session to carry forced flag, got %+v", tempSession.User)
	}
	otherSession, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: "temporary local password"})
	if err != nil {
		t.Fatal(err)
	}

	newSession, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: user.ID, CurrentPassword: "temporary local password", NewPassword: "a brand new local password"})
	if err != nil {
		t.Fatal(err)
	}
	if newSession.ID == tempSession.ID || newSession.ID == otherSession.ID || newSession.CSRFToken == tempSession.CSRFToken {
		t.Fatalf("expected freshly rotated session, got %+v", newSession)
	}
	if newSession.User.MustChangePassword {
		t.Fatalf("expected forced flag cleared on returned session, got %+v", newSession.User)
	}
	for _, revoked := range []string{tempSession.ID, otherSession.ID} {
		if _, found, err := service.SessionByID(ctx, revoked); err != nil || found {
			t.Fatalf("expected previous session %q to be revoked, found=%v err=%v", revoked, found, err)
		}
	}
	loaded, found, err := service.SessionByID(ctx, newSession.ID)
	if err != nil || !found {
		t.Fatalf("expected rotated session to be valid, found=%v err=%v", found, err)
	}
	if loaded.User.MustChangePassword {
		t.Fatalf("expected forced flag cleared in storage, got %+v", loaded.User)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: "a brand new local password"}); err != nil {
		t.Fatalf("expected login with new password, got %v", err)
	}
	assertAuditEvent(t, ctx, database, audit.ActionUserPasswordChanged, user.ID, user.ID)
}

func TestResetPasswordSetsForcedFlagRevokesSessionsAndPreservesState(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", nil)
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	if err := service.SetUserRepositoryRoles(ctx, SetUserRepositoryRolesParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Roles: []Role{RoleViewer, RoleFreezer}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: accountTestPassword}); err != nil {
		t.Fatal(err)
	}

	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: admin.User.ID, TemporaryPassword: "temporary local password"}); !IsValidationError(err) {
		t.Fatalf("expected self reset to be rejected, got %v", err)
	}
	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "short"}); !IsValidationError(err) {
		t.Fatalf("expected short temporary password rejection, got %v", err)
	}
	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); err != nil {
		t.Fatal(err)
	}

	var storedHash string
	var mustChangePassword int
	if err := database.QueryRowContext(ctx, `SELECT password_hash, must_change_password FROM users WHERE id = ?`, user.ID).Scan(&storedHash, &mustChangePassword); err != nil {
		t.Fatal(err)
	}
	if storedHash == "temporary local password" || !strings.HasPrefix(storedHash, "$argon2id$") {
		t.Fatal("expected temporary password to be stored as an argon2id hash")
	}
	if mustChangePassword != 1 {
		t.Fatalf("expected forced password change flag set, got %d", mustChangePassword)
	}
	var sessionCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = ?`, user.ID).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected all target sessions revoked on reset, got %d", sessionCount)
	}
	loaded, err := service.userByID(ctx, database, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := service.GrantsForUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !grants.CanFreezeRepository(repositoryID) || !grants.CanViewRepository(repositoryID) || loaded.Disabled() {
		t.Fatalf("expected repository grants and enabled state preserved, user=%+v grants=%+v", loaded.User, grants)
	}
	assertAuditEvent(t, ctx, database, audit.ActionUserPasswordReset, user.ID, admin.User.ID)

	// Reset must not enable a disabled user.
	if _, err := service.DisableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "another temporary password"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := service.userByID(ctx, database, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Disabled() {
		t.Fatalf("expected reset to preserve disabled state, got %+v", reloaded.User)
	}
}

func TestAccountMutationsRollBackWhenAuditPersistenceFails(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "lead@example.test", []Role{RoleFreezer})
	session, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(ctx, `ALTER TABLE audit_events_broken RENAME TO audit_events`)
	})

	if _, err := service.DisableUser(ctx, admin.User.ID, user.ID); err == nil || IsValidationError(err) {
		t.Fatalf("expected internal error when audit persistence fails, got %v", err)
	}
	loaded, err := service.userByID(ctx, database, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Disabled() {
		t.Fatalf("expected disable to roll back with audit failure, got %+v", loaded.User)
	}
	if _, found, err := service.SessionByID(ctx, session.ID); err != nil || !found {
		t.Fatalf("expected session revocation to roll back with audit failure, found=%v err=%v", found, err)
	}

	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); err == nil || IsValidationError(err) {
		t.Fatalf("expected reset to fail when audit persistence fails, got %v", err)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: accountTestPassword}); err != nil {
		t.Fatalf("expected password unchanged after rolled-back reset, got %v", err)
	}
}

func mustCreateFirstAdmin(t *testing.T, ctx context.Context, service *Service) Session {
	t.Helper()
	session, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func mustCreateUser(t *testing.T, ctx context.Context, service *Service, email string, roles []Role) User {
	t.Helper()
	var actorUserID int64
	if err := service.db.QueryRowContext(ctx, `
SELECT u.id
FROM users u
JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
WHERE u.disabled_at IS NULL
ORDER BY u.id
LIMIT 1`).Scan(&actorUserID); err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(ctx, CreateUserParams{ActorUserID: actorUserID, Email: email, DisplayName: "User " + email, Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role == RoleAdmin {
			user, err = service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorUserID, UserID: user.ID, Admin: true})
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		// Scoped rows in user_roles are deliberately inert after cutover. A few
		// compatibility tests seed them directly to prove they cannot authorize.
		if _, err := service.db.ExecContext(ctx, `INSERT OR IGNORE INTO user_roles(user_id, role, created_at) VALUES (?, ?, ?)`, user.ID, role, service.now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	return user
}

func assertAuditEvent(t *testing.T, ctx context.Context, database *sql.DB, action string, subjectUserID int64, actorUserID int64) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action = ? AND subject_type = 'user' AND subject_id = ? AND actor_user_id = ?`, action, subjectUserID, actorUserID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("expected audit event %s for user %d by actor %d", action, subjectUserID, actorUserID)
	}
	var leaked int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action = ? AND (details_json LIKE '%password%' OR details_json LIKE '%session%' OR details_json LIKE '%hash%')`, action).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("expected audit details for %s to exclude password/session/hash data", action)
	}
}
