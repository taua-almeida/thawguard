package pullrequest

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreUpsertsAndReadsPullRequestCache(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: " main ", HeadSHA: " ABC123 ", Title: " Example fix ", URL: "https://codeberg.org/example-owner/example-repo/pulls/42"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 || created.TargetBranch != "main" || created.HeadSHA != "abc123" || created.Title != "Example fix" {
		t.Fatalf("unexpected created pull request: %+v", created)
	}

	updated, err := store.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "closed", TargetBranch: "dev", HeadSHA: "def456", Title: "Done"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.State != "closed" || updated.TargetBranch != "dev" || updated.HeadSHA != "def456" {
		t.Fatalf("unexpected updated pull request: %+v", updated)
	}
}

func TestStoreListsOpenPullRequestsByHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	for _, pr := range []domain.PullRequest{
		{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "release", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 3, State: "closed", TargetBranch: "main", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 4, State: "open", TargetBranch: "main", HeadSHA: "def456"},
	} {
		if _, err := store.Upsert(ctx, pr); err != nil {
			t.Fatal(err)
		}
	}

	prs, err := store.ListOpenByHead(ctx, repo.ID, "ABC123")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].Index != 1 || prs[1].Index != 2 {
		t.Fatalf("unexpected open PRs: %+v", prs)
	}
}

func TestStoreRejectsInvalidPullRequestCacheParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.Upsert(ctx, domain.PullRequest{Index: 1, TargetBranch: "main", HeadSHA: "abc123"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, TargetBranch: "main", HeadSHA: "abc123"}); !IsValidationError(err) {
		t.Fatalf("expected missing pull request validation error, got %v", err)
	}
	if _, err := store.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, HeadSHA: "abc123"}); !IsValidationError(err) {
		t.Fatalf("expected missing target branch validation error, got %v", err)
	}
	if _, err := store.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, TargetBranch: "main", HeadSHA: "not-a-sha"}); !IsValidationError(err) {
		t.Fatalf("expected invalid head SHA validation error, got %v", err)
	}
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
