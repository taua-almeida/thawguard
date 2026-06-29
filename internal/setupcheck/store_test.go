package setupcheck

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreRecordsAndListsSetupChecks(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	checkedAt := time.Date(2026, 6, 29, 13, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return checkedAt }

	results := Evaluate(Report{CanPostStatuses: true, RequiredContextPresent: false, WebhookConfigured: true})
	if err := store.Record(ctx, repo.ID, repo.DefaultBranch, results); err != nil {
		t.Fatal(err)
	}

	checks, err := store.ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 3 {
		t.Fatalf("expected 3 setup checks, got %d", len(checks))
	}

	byName := make(map[string]Check)
	for _, check := range checks {
		byName[check.Result.Name] = check
		if check.RepositoryID != repo.ID {
			t.Fatalf("expected repository id %d, got %d", repo.ID, check.RepositoryID)
		}
		if check.Branch != repo.DefaultBranch {
			t.Fatalf("expected branch %q, got %q", repo.DefaultBranch, check.Branch)
		}
		if !check.CheckedAt.Equal(checkedAt) {
			t.Fatalf("expected checked_at %s, got %s", checkedAt, check.CheckedAt)
		}
	}

	contextCheck := byName["Required status context configured"]
	if contextCheck.ID == 0 {
		t.Fatal("expected required-context check")
	}
	if contextCheck.Result.Status != StatusFailed {
		t.Fatalf("expected required-context failure, got %s", contextCheck.Result.Status)
	}
	if contextCheck.Result.Remediation == "" {
		t.Fatal("expected remediation to round trip")
	}
}

func TestStoreRejectsInvalidSetupChecks(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	cases := []struct {
		name         string
		repositoryID int64
		results      []Result
	}{
		{name: "missing repository", repositoryID: 0, results: []Result{{Name: "Bot can post statuses", Status: StatusOK, Description: "ok"}}},
		{name: "missing name", repositoryID: repo.ID, results: []Result{{Status: StatusOK, Description: "ok"}}},
		{name: "invalid status", repositoryID: repo.ID, results: []Result{{Name: "Bot can post statuses", Status: Status("unknown"), Description: "ok"}}},
		{name: "missing description", repositoryID: repo.ID, results: []Result{{Name: "Bot can post statuses", Status: StatusOK}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Record(ctx, tc.repositoryID, "main", tc.results); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestStoreOrdersSetupChecksByCheckedAt(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	first := time.Date(2026, 6, 29, 13, 0, 0, 0, time.UTC)
	second := first.Add(100 * time.Millisecond)

	store.now = func() time.Time { return first }
	if err := store.Record(ctx, repo.ID, "main", []Result{{Name: "first", Status: StatusOK, Description: "first check"}}); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return second }
	if err := store.Record(ctx, repo.ID, "main", []Result{{Name: "second", Status: StatusOK, Description: "second check"}}); err != nil {
		t.Fatal(err)
	}

	checks, err := store.ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 2 {
		t.Fatalf("expected 2 setup checks, got %d", len(checks))
	}
	if checks[0].Result.Name != "second" {
		t.Fatalf("expected newest check first, got %q", checks[0].Result.Name)
	}
}

func TestStoreRejectsMissingRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewStore(database)
	missingRepositoryID := int64(999)

	err := store.Record(ctx, missingRepositoryID, "main", []Result{
		{Name: "Bot can post statuses", Status: StatusOK, Description: "ok"},
		{Name: "Required status context configured", Status: StatusFailed, Description: "missing"},
	})
	if err == nil {
		t.Fatal("expected foreign-key error")
	}

	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM setup_checks WHERE repository_id = ?`, missingRepositoryID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected rollback to leave no setup checks, got %d", count)
	}
}

func TestStoreAllowsEmptyResults(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if err := store.Record(ctx, repo.ID, "main", nil); err != nil {
		t.Fatal(err)
	}
	checks, err := store.ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 0 {
		t.Fatalf("expected no setup checks, got %d", len(checks))
	}
}

func TestStoreRejectsMissingRepositoryIDForEmptyResults(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewStore(database)

	if err := store.Record(ctx, 0, "main", nil); err == nil {
		t.Fatal("expected repository id error")
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

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) repositoryRecord {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	return repositoryRecord{ID: repo.ID, DefaultBranch: repo.DefaultBranch}
}

type repositoryRecord struct {
	ID            int64
	DefaultBranch string
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
