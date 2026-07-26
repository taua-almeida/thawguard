package auth

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"sync/atomic"
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
	if session.User.ID == 0 || session.User.Email != "admin@example.test" || !session.User.IsAdmin || !session.Grants.CanManageInstallation() || session.Grants.CanFreezeRepository(1) || session.Grants.CanThawRepository(1) || session.ID == "" || session.CSRFToken == "" {
		t.Fatalf("unexpected first admin session: %+v", session)
	}
	var adminRows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ?`, session.User.ID).Scan(&adminRows); err != nil {
		t.Fatal(err)
	}
	if adminRows != 1 {
		t.Fatalf("expected first account to have exactly one Admin row, got %d", adminRows)
	}
	hasUsers, err := service.HasUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasUsers {
		t.Fatal("expected service to report configured users")
	}

	var storedHash string
	if err := database.QueryRowContext(ctx, `
SELECT lc.password_hash
FROM local_credentials lc
JOIN users u ON u.id = lc.user_id
WHERE u.email = ?`, "admin@example.test").Scan(&storedHash); err != nil {
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
	if !found || loaded.User.Email != "admin@example.test" || !loaded.User.IsAdmin || loaded.CSRFToken != session.CSRFToken {
		t.Fatalf("expected persistent session, found=%v session=%+v", found, loaded)
	}
	if err := service.Logout(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, session.ID); err != nil || found {
		t.Fatalf("expected logged out session to be gone, found=%v err=%v", found, err)
	}
}

func TestCreateUserStartsWithZeroAccessAndValidatesDuplicates(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}

	user, err := service.CreateUser(ctx, CreateUserParams{ActorUserID: admin.User.ID, Email: " lead@example.test ", DisplayName: "Lead", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "lead@example.test" || user.IsAdmin || !user.MustChangePassword {
		t.Fatalf("unexpected user: %+v", user)
	}
	var adminRows, repositoryRows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ?`, user.ID).Scan(&adminRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ?`, user.ID).Scan(&repositoryRows); err != nil {
		t.Fatal(err)
	}
	if adminRows != 0 || repositoryRows != 0 {
		t.Fatalf("expected ordinary user to start with no Admin or repository rows, admin=%d repository=%d", adminRows, repositoryRows)
	}
	session, err := service.Login(ctx, LoginParams{Email: "lead@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if session.Grants.HasRepositoryAccess() || session.Grants.CanManageInstallation() {
		t.Fatalf("expected login session to carry zero access, got %+v", session.Grants)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{ActorUserID: admin.User.ID, Email: "lead@example.test", DisplayName: "Lead", Password: "correct horse battery staple"}); !IsValidationError(err) {
		t.Fatalf("expected duplicate email validation error, got %v", err)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{ActorUserID: user.ID, Email: "blank@example.test", DisplayName: "Blank", Password: "correct horse battery staple"}); !IsValidationError(err) {
		t.Fatalf("expected non-Admin actor rejection, got %v", err)
	}
}

func TestCreateUserSerializationLockWaitsBeforeMutationTime(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)

	blocker, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, admin.User.ID); err != nil {
		t.Fatal(err)
	}

	beforeLock := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	afterLock := beforeLock.Add(time.Minute)
	var clockNanos atomic.Int64
	clockNanos.Store(beforeLock.UnixNano())
	clockRead := make(chan struct{}, 1)
	service.now = func() time.Time {
		select {
		case clockRead <- struct{}{}:
		default:
		}
		return time.Unix(0, clockNanos.Load()).UTC()
	}

	type lockResult struct {
		sampled time.Time
		err     error
	}
	result := make(chan lockResult, 1)
	go func() {
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			result <- lockResult{err: err}
			return
		}
		defer tx.Rollback()
		if err := service.lockEnabledAdminActor(ctx, tx, admin.User.ID); err != nil {
			result <- lockResult{err: err}
			return
		}
		sampled := service.now().UTC()
		if err := tx.Commit(); err != nil {
			result <- lockResult{err: err}
			return
		}
		result <- lockResult{sampled: sampled}
	}()

	select {
	case <-clockRead:
		t.Fatal("mutation time was sampled before SQLite writer ownership")
	case got := <-result:
		t.Fatalf("controlled writer contention returned before release: %v", got.err)
	case <-time.After(200 * time.Millisecond):
	}

	clockNanos.Store(afterLock.UnixNano())
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("expected contention released within BusyTimeout to succeed, got %v", got.err)
		}
		if !got.sampled.Equal(afterLock) {
			t.Fatalf("expected post-lock mutation time %s, got %s", afterLock, got.sampled)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for identity-management writer lock")
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
