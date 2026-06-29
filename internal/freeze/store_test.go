package freeze

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreCreatesAndListsActiveFreezes(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: " dev ", Reason: " QA freeze "})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected freeze id")
	}
	if created.RepositoryID != repo.ID || created.Branch != "dev" || created.Reason != "QA freeze" {
		t.Fatalf("unexpected freeze: %+v", created)
	}
	if created.Status != domain.BranchFreezeStatusActive || !created.Active {
		t.Fatalf("expected active freeze, got %+v", created)
	}
	if created.StartsAt == nil {
		t.Fatal("expected active freeze start time")
	}

	freezes, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(freezes) != 1 || freezes[0].ID != created.ID {
		t.Fatalf("expected created freeze in active list, got %+v", freezes)
	}
}

func TestStoreRejectsInvalidFreezeParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.CreateActive(ctx, CreateParams{Branch: "main", Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing branch validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main"}); !IsValidationError(err) {
		t.Fatalf("expected missing reason validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: 999, Branch: "main", Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
}

func TestStoreRejectsDuplicateActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	params := CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}

	if _, err := store.CreateActive(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateActive(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected duplicate active freeze validation error, got %v", err)
	}
}

func TestDatabaseRejectsDuplicateActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := database.ExecContext(ctx, `
INSERT INTO branch_freezes(repository_id, branch, status, reason, starts_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, repo.ID, "main", domain.BranchFreezeStatusActive, "duplicate", now, now, now)
	if err == nil {
		t.Fatal("expected database unique constraint to reject duplicate active freeze")
	}
}

func TestStoreEndsActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"})
	if err != nil {
		t.Fatal(err)
	}

	ended, err := store.End(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded || ended.Active || ended.EndsAt == nil {
		t.Fatalf("expected ended inactive freeze with end time, got %+v", ended)
	}
	freezes, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(freezes) != 0 {
		t.Fatalf("expected no active freezes after ending, got %+v", freezes)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "next release"}); err != nil {
		t.Fatalf("expected branch to be free after ending freeze: %v", err)
	}
}

func TestStoreCancelsActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "mistake"})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := store.Cancel(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled || cancelled.Active || cancelled.EndsAt == nil {
		t.Fatalf("expected cancelled inactive freeze with end time, got %+v", cancelled)
	}
}

func TestStoreRejectsClosingInvalidOrInactiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(ctx, 0); !IsValidationError(err) {
		t.Fatalf("expected missing freeze validation error, got %v", err)
	}
	if _, err := store.End(ctx, 999); !IsValidationError(err) {
		t.Fatalf("expected missing freeze validation error, got %v", err)
	}
	if _, err := store.End(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cancel(ctx, created.ID); !IsValidationError(err) {
		t.Fatalf("expected inactive freeze validation error, got %v", err)
	}
}

func TestServiceCreatesFreezeAndAuditEventAtomically(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)

	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	event := events[0]
	if event.Action != audit.ActionBranchFreezeCreated || event.SubjectType != audit.SubjectTypeBranchFreeze || event.SubjectID != "1" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" || details["branch"] != created.Branch || details["reason"] != created.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
	}
}

func TestServiceEndsFreezeAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	ended, err := service.End(ctx, created.ID, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected ended freeze, got %+v", ended)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionBranchFreezeEnded, ended)
}

func TestServiceCancelsFreezeAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "mistake"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := service.Cancel(ctx, created.ID, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled {
		t.Fatalf("expected cancelled freeze, got %+v", cancelled)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionBranchFreezeCancelled, cancelled)
}

func TestServiceRollsBackEndWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	missingUserID := int64(999)

	_, err = service.End(ctx, created.ID, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	freeze, getErr := NewStore(database).Get(ctx, created.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if freeze.Status != domain.BranchFreezeStatusActive || !freeze.Active || freeze.EndsAt != nil {
		t.Fatalf("expected rollback to leave freeze active, got %+v", freeze)
	}
}

func TestServiceRollsBackFreezeWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	missingUserID := int64(999)

	_, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	freezes, listErr := service.ListActive(ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(freezes) != 0 {
		t.Fatalf("expected rollback to leave no freezes, got %d", len(freezes))
	}
}

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func assertLatestFreezeAudit(t *testing.T, ctx context.Context, database *sql.DB, action string, freeze domain.BranchFreeze) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	event := events[0]
	if event.Action != action || event.SubjectType != audit.SubjectTypeBranchFreeze || event.SubjectID != strconv.FormatInt(freeze.ID, 10) {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" || details["repository_id"] != strconv.FormatInt(freeze.RepositoryID, 10) || details["branch"] != freeze.Branch || details["status"] != string(freeze.Status) || details["reason"] != freeze.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
	}
}

func newTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	migrations, err := db.LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return database
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
