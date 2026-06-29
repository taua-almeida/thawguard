package statuspublication

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

func TestStorePublishesLocalStatusIntent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	result := createStatusResult(t, ctx, database, repo.ID)
	store := NewStore(database)

	publication, err := store.Publish(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if publication.ID == 0 {
		t.Fatal("expected publication id")
	}
	if publication.StatusResultID != result.ID || publication.RepositoryID != repo.ID || publication.HeadSHA != result.HeadSHA {
		t.Fatalf("unexpected publication: %+v", publication)
	}
	if publication.DeliveryMode != DeliveryModeLocalRecord {
		t.Fatalf("expected local delivery mode, got %q", publication.DeliveryMode)
	}

	publications, err := store.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 1 || publications[0].ID != publication.ID {
		t.Fatalf("expected recent publication, got %+v", publications)
	}
}

func TestStoreRejectsInvalidPublicationResult(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewStore(database)

	if _, err := store.Publish(ctx, statusresult.Result{}); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := store.Publish(ctx, statusresult.Result{ID: 1, RepositoryID: 1, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: "invalid", Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid state validation error, got %v", err)
	}
}

func createStatusResult(t *testing.T, ctx context.Context, database *sql.DB, repositoryID int64) statusresult.Result {
	t.Helper()
	result, err := statusresult.NewStore(database).Create(ctx, statusresult.CreateParams{RepositoryID: repositoryID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	return repo
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
