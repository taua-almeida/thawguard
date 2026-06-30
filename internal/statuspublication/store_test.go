package statuspublication

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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
	if publication.CreatedAt.IsZero() || publication.UpdatedAt.IsZero() {
		t.Fatalf("expected publication timestamps, got %+v", publication)
	}
	if !publication.CreatedAt.Equal(publication.UpdatedAt) {
		t.Fatalf("expected created and updated timestamps to match on insert, got %+v", publication)
	}

	publications, err := store.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 1 || publications[0].ID != publication.ID {
		t.Fatalf("expected recent publication, got %+v", publications)
	}
}

func TestStorePublishUpsertsLocalStatusIntentByStatusKey(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	firstResult := createStatusResultWithParams(t, ctx, database, repo.ID, 42, "main", "abc123", domain.CommitStatusFailure, "Branch is frozen; merge is blocked by Thawguard")
	store := NewStore(database)
	firstTime := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return firstTime }

	first, err := store.Publish(ctx, firstResult)
	if err != nil {
		t.Fatal(err)
	}

	secondResult := createStatusResultWithParams(t, ctx, database, repo.ID, 43, "release", "abc123", domain.CommitStatusSuccess, "No active freeze applies to this PR")
	secondTime := firstTime.Add(5 * time.Minute)
	store.now = func() time.Time { return secondTime }
	second, err := store.Publish(ctx, secondResult)
	if err != nil {
		t.Fatal(err)
	}

	if second.ID != first.ID {
		t.Fatalf("expected publication row to be updated, got first id %d and second id %d", first.ID, second.ID)
	}
	if second.StatusResultID != secondResult.ID || second.PullRequestIndex != 43 || second.TargetBranch != "release" || second.State != domain.CommitStatusSuccess || second.Description != "No active freeze applies to this PR" {
		t.Fatalf("expected latest status publication fields, got %+v", second)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("expected created_at to stay first-seen time, got %s want %s", second.CreatedAt, first.CreatedAt)
	}
	if !second.UpdatedAt.Equal(secondTime) {
		t.Fatalf("expected updated_at to be refreshed, got %s want %s", second.UpdatedAt, secondTime)
	}

	publications, err := store.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 1 || publications[0].ID != first.ID || publications[0].StatusResultID != secondResult.ID {
		t.Fatalf("expected one updated publication intent, got %+v", publications)
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
	return createStatusResultWithParams(t, ctx, database, repositoryID, 42, "main", "abc123", domain.CommitStatusFailure, "Branch is frozen; merge is blocked by Thawguard")
}

func createStatusResultWithParams(t *testing.T, ctx context.Context, database *sql.DB, repositoryID int64, pullRequestIndex int, targetBranch string, headSHA string, state domain.CommitStatusState, description string) statusresult.Result {
	t.Helper()
	result, err := statusresult.NewStore(database).Create(ctx, statusresult.CreateParams{RepositoryID: repositoryID, PullRequestIndex: pullRequestIndex, TargetBranch: targetBranch, HeadSHA: headSHA, Context: domain.RequiredStatusContext, State: state, Description: description})
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
