package auth

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/db"
)

func TestCreateFirstAdminBootstrapsOnlyEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)

	session, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: " Admin@Example.test ", DisplayName: " Taua ", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if session.User.ID == 0 || session.User.Email != "admin@example.test" || session.User.Role != RoleAdmin || !session.User.Roles.Contains(RoleAdmin) || !session.User.Roles.CanFreeze() || !session.User.Roles.CanThaw() || session.ID == "" || session.CSRFToken == "" {
		t.Fatalf("unexpected first admin session: %+v", session)
	}
	hasUsers, err := service.HasUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasUsers {
		t.Fatal("expected service to report configured users")
	}

	var storedHash string
	if err := database.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE email = ?`, "admin@example.test").Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash == "correct horse battery staple" {
		t.Fatal("expected password to be hashed")
	}
	passwordOK, err := VerifyPassword("correct horse battery staple", storedHash)
	if err != nil {
		t.Fatal(err)
	}
	if !passwordOK {
		t.Fatal("expected stored password hash to verify")
	}

	if _, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "second@example.test", DisplayName: "Second", Password: "correct horse battery staple"}); !IsValidationError(err) {
		t.Fatalf("expected second first-admin setup to be rejected, got %v", err)
	}
}

func TestRoleSetRequiresExplicitActionRoles(t *testing.T) {
	adminOnly := RoleSet{RoleAdmin}
	if !adminOnly.CanManageRepositories() || adminOnly.CanFreeze() || adminOnly.CanThaw() || !adminOnly.CanView() {
		t.Fatalf("expected admin-only role to manage configuration but not freeze/thaw: %+v", adminOnly)
	}

	lead := RoleSet{RoleFreezer, RoleThawApprover}
	if lead.CanManageRepositories() || !lead.CanFreeze() || !lead.CanThaw() || !lead.CanView() {
		t.Fatalf("expected lead roles to freeze and thaw without admin: %+v", lead)
	}

	viewer := RoleSet{RoleViewer}
	if viewer.CanManageRepositories() || viewer.CanFreeze() || viewer.CanThaw() || !viewer.CanView() {
		t.Fatalf("expected viewer role to remain read-only: %+v", viewer)
	}
}

func TestLoginCreatesPersistentSession(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	if _, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Login(ctx, LoginParams{Email: "admin@example.test", Password: "wrong password"}); !IsAuthenticationError(err) {
		t.Fatalf("expected bad password to be rejected, got %v", err)
	}
	session, err := service.Login(ctx, LoginParams{Email: " ADMIN@example.test ", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := service.SessionByID(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || loaded.User.Email != "admin@example.test" || !loaded.User.Roles.Contains(RoleAdmin) || loaded.CSRFToken != session.CSRFToken {
		t.Fatalf("expected persistent session, found=%v session=%+v", found, loaded)
	}
	if err := service.Logout(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, session.ID); err != nil || found {
		t.Fatalf("expected logged out session to be gone, found=%v err=%v", found, err)
	}
}

func TestCreateUserSupportsMultipleRolesAndValidatesDuplicates(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	if _, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}

	user, err := service.CreateUser(ctx, CreateUserParams{Email: " lead@example.test ", DisplayName: "Lead", Password: "correct horse battery staple", Roles: []Role{RoleThawApprover, RoleFreezer}})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "lead@example.test" || user.Role != RoleFreezer || !user.Roles.CanFreeze() || !user.Roles.CanThaw() || user.Roles.CanManageRepositories() {
		t.Fatalf("unexpected user: %+v", user)
	}
	session, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if !session.User.Roles.CanFreeze() || !session.User.Roles.CanThaw() {
		t.Fatalf("expected login session to carry multiple roles: %+v", session.User.Roles)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{Email: "lead@example.test", DisplayName: "Lead", Password: "correct horse battery staple", Roles: []Role{RoleFreezer}}); !IsValidationError(err) {
		t.Fatalf("expected duplicate email validation error, got %v", err)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{Email: "viewer@example.test", DisplayName: "Viewer", Password: "correct horse battery staple", Roles: []Role{Role("owner")}}); !IsValidationError(err) {
		t.Fatalf("expected invalid role validation error, got %v", err)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{Email: "blank@example.test", DisplayName: "Blank", Password: "correct horse battery staple"}); !IsValidationError(err) {
		t.Fatalf("expected missing role validation error, got %v", err)
	}
}

func TestSessionByIDExpiresSessions(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.sessionTTL = -time.Second
	session, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, session.ID); err != nil || found {
		t.Fatalf("expected expired session to be rejected, found=%v err=%v", found, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = ?`, session.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected expired session to be deleted, got %d", count)
	}
}

func TestSessionByIDRejectsLegacyEmptyCSRFToken(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	session, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`, "legacy-empty-csrf", session.User.ID, "", time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, "legacy-empty-csrf"); err != nil || found {
		t.Fatalf("expected legacy empty-csrf session to be rejected, found=%v err=%v", found, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = ?`, "legacy-empty-csrf").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected legacy empty-csrf session to be deleted, got %d", count)
	}
}

func newAuthTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-auth-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := db.LoadMigrations(authTestMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return database
}

func authTestMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
