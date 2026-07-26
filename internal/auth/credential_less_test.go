package auth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// removeLocalCredential models a future OIDC-only account. There is no
// production credential-removal API, so tests delete the row directly.
func removeLocalCredential(t *testing.T, ctx context.Context, database *sql.DB, userID int64) {
	t.Helper()
	result, err := database.ExecContext(ctx, `DELETE FROM local_credentials WHERE user_id = ?`, userID)
	if err != nil {
		t.Fatal(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if affected != 1 {
		t.Fatalf("expected exactly one credential row to remove, got %d", affected)
	}
}

func TestCredentialLessUserRemainsReadableWithValidSessionAndGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "solo@example.test", false)
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	session, err := service.Login(ctx, LoginParams{Email: "solo@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	removeLocalCredential(t, ctx, database, user.ID)

	loaded, err := service.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("expected credential-less user to stay readable, got %v", err)
	}
	if loaded.HasLocalPassword || loaded.MustChangePassword || loaded.Disabled() {
		t.Fatalf("expected enabled credential-less user without password flags, got %+v", loaded)
	}

	users, err := service.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, entry := range users {
		if entry.ID != user.ID {
			continue
		}
		listed = true
		if entry.HasLocalPassword || entry.MustChangePassword {
			t.Fatalf("expected credential-less list entry without password flags, got %+v", entry)
		}
	}
	if !listed {
		t.Fatalf("expected credential-less user in ListUsers, got %+v", users)
	}

	entries, err := service.ListUsersDirectory(ctx, UserDirectoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	inDirectory := false
	for _, entry := range entries {
		if entry.ID != user.ID {
			continue
		}
		inDirectory = true
		if entry.HasLocalPassword || entry.MustChangePassword {
			t.Fatalf("expected credential-less directory entry without password flags, got %+v", entry)
		}
	}
	if !inDirectory {
		t.Fatalf("expected credential-less user in directory, got %+v", entries)
	}

	// The pre-existing session stays valid and still refreshes grants that were
	// added after the credential row was removed.
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{ActorUserID: admin.User.ID, RepositoryID: repositoryID, UserID: user.ID, Role: RoleFreezer}); err != nil {
		t.Fatal(err)
	}
	refreshed, found, err := service.SessionByID(ctx, session.ID)
	if err != nil || !found {
		t.Fatalf("expected session to survive credential removal, found=%v err=%v", found, err)
	}
	if refreshed.User.HasLocalPassword || refreshed.User.MustChangePassword {
		t.Fatalf("expected refreshed session without password flags, got %+v", refreshed.User)
	}
	if !refreshed.Grants.CanFreezeRepository(repositoryID) {
		t.Fatalf("expected grants to refresh after credential removal, got %+v", refreshed.Grants)
	}
}

func TestCredentialLessUserPasswordPathsRejectWithoutCreatingCredential(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	user := mustCreateUser(t, ctx, service, "solo@example.test", false)
	recovery := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, user.ID)
	removeLocalCredential(t, ctx, database, user.ID)

	if _, err := service.Login(ctx, LoginParams{Email: "solo@example.test", Password: accountTestPassword}); !IsAuthenticationError(err) {
		t.Fatalf("expected generic authentication failure for credential-less login, got %v", err)
	}
	if _, err := service.ChangePassword(ctx, ChangePasswordParams{UserID: user.ID, CurrentPassword: accountTestPassword, NewPassword: "a brand new local password"}); !IsValidationError(err) || !strings.Contains(err.Error(), "local password is not configured") {
		t.Fatalf("expected neutral change rejection without a credential, got %v", err)
	}
	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); !IsValidationError(err) || !strings.Contains(err.Error(), "local password is not configured") {
		t.Fatalf("expected neutral reset rejection without a credential, got %v", err)
	}
	if _, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{ActorUserID: admin.User.ID, UserID: user.ID}); !IsValidationError(err) || !strings.Contains(err.Error(), "local password is not configured") {
		t.Fatalf("expected neutral recovery issuance rejection without a credential, got %v", err)
	}
	// A token issued before credential removal completes with the same generic
	// failure an invalid token produces, before password validation or hashing.
	for _, password := range []string{"short", "a recovered local password"} {
		if err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: recovery.Token, NewPassword: password}); !IsInvalidPasswordRecoveryToken(err) {
			t.Fatalf("expected generic invalid-token result without a credential for password %q, got %v", password, err)
		}
	}
	if tokens := countPasswordRecoveryTokens(t, ctx, database, user.ID); tokens != 1 {
		t.Fatalf("expected rejected recovery attempts to preserve the existing token, got %d", tokens)
	}

	var credentialRows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM local_credentials WHERE user_id = ?`, user.ID).Scan(&credentialRows); err != nil {
		t.Fatal(err)
	}
	if credentialRows != 0 {
		t.Fatalf("expected rejected password paths to create no credential, got %d rows", credentialRows)
	}
	if _, err := service.Login(ctx, LoginParams{Email: "solo@example.test", Password: accountTestPassword}); !IsAuthenticationError(err) {
		t.Fatalf("expected login to keep failing after rejected password paths, got %v", err)
	}
}

func TestCredentialLessAdminSessionRetainsAdminAuthority(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	coAdmin := mustCreateUser(t, ctx, service, "second@example.test", true)
	session, err := service.Login(ctx, LoginParams{Email: "second@example.test", Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	removeLocalCredential(t, ctx, database, coAdmin.ID)

	refreshed, found, err := service.SessionByID(ctx, session.ID)
	if err != nil || !found {
		t.Fatalf("expected credential-less admin session to stay valid, found=%v err=%v", found, err)
	}
	if !refreshed.User.IsAdmin || !refreshed.Grants.CanManageInstallation() || refreshed.User.HasLocalPassword {
		t.Fatalf("expected admin authority without a local password, got %+v", refreshed)
	}

	member, err := service.CreateUser(ctx, CreateUserParams{ActorUserID: coAdmin.ID, Email: "member@example.test", DisplayName: "Member", Password: accountTestPassword})
	if err != nil {
		t.Fatalf("expected credential-less admin to create users, got %v", err)
	}
	if err := service.ResetPassword(ctx, ResetPasswordParams{ActorUserID: coAdmin.ID, UserID: member.ID, TemporaryPassword: "temporary local password"}); err != nil {
		t.Fatalf("expected credential-less admin to reset a member password, got %v", err)
	}

	// The other enabled admin keeps its local credential, so recovery safety
	// never depended on the credential-less admin.
	firstAdmin, err := service.GetUser(ctx, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !firstAdmin.HasLocalPassword || firstAdmin.Disabled() {
		t.Fatalf("expected the local-credential admin to preserve recovery safety, got %+v", firstAdmin)
	}
}
