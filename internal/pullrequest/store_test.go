package pullrequest

import (
	"context"
	"database/sql"
	"errors"
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

func TestStoreGetsPullRequestByRepositoryAndIndex(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123", Title: "Example fix", URL: "https://codeberg.org/example-owner/example-repo/pulls/42"}); err != nil {
		t.Fatal(err)
	}

	pr, err := store.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Index != 42 || pr.TargetBranch != "main" || pr.HeadSHA != "abc123" || pr.Title != "Example fix" || pr.URL == "" {
		t.Fatalf("unexpected pull request: %+v", pr)
	}

	if _, err := store.Get(ctx, repo.ID, 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows for uncached index, got %v", err)
	}
	if _, err := store.Get(ctx, repo.ID+1, 42); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows for other repository, got %v", err)
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

func TestStoreListsOpenPullRequestsByTargetBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	for _, pr := range []domain.PullRequest{
		{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "release", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 3, State: "closed", TargetBranch: "main", HeadSHA: "def456"},
		{RepositoryID: repo.ID, Index: 4, State: "open", TargetBranch: "main", HeadSHA: "def456"},
	} {
		if _, err := store.Upsert(ctx, pr); err != nil {
			t.Fatal(err)
		}
	}

	prs, err := store.ListOpenByTargetBranch(ctx, repo.ID, " main ")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].Index != 1 || prs[1].Index != 4 {
		t.Fatalf("unexpected open PRs: %+v", prs)
	}
}

func TestStoreMarksAbsentOpenPullRequestsClosedByTargetBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	for _, pr := range []domain.PullRequest{
		{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "main", HeadSHA: "def456"},
		{RepositoryID: repo.ID, Index: 3, State: "open", TargetBranch: "release", HeadSHA: "bbb123"},
		{RepositoryID: repo.ID, Index: 4, State: "closed", TargetBranch: "main", HeadSHA: "ccc123"},
	} {
		if _, err := store.Upsert(ctx, pr); err != nil {
			t.Fatal(err)
		}
	}

	closed, err := store.MarkAbsentOpenClosed(ctx, repo.ID, " main ", []int{2})
	if err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("expected one stale open PR to close, got %d", closed)
	}
	mainPRs, err := store.ListOpenByTargetBranch(ctx, repo.ID, "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(mainPRs) != 1 || mainPRs[0].Index != 2 {
		t.Fatalf("expected only current main PR to remain open, got %+v", mainPRs)
	}
	releasePRs, err := store.ListOpenByTargetBranch(ctx, repo.ID, "release")
	if err != nil {
		t.Fatal(err)
	}
	if len(releasePRs) != 1 || releasePRs[0].Index != 3 {
		t.Fatalf("expected other branches to remain open, got %+v", releasePRs)
	}
}

func TestStoreMarksAbsentOpenPullRequestsClosedAcrossRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	for _, pr := range []domain.PullRequest{
		{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "release", HeadSHA: "def456"},
		{RepositoryID: repo.ID, Index: 3, State: "open", TargetBranch: "hotfix", HeadSHA: "bbb123"},
	} {
		if _, err := store.Upsert(ctx, pr); err != nil {
			t.Fatal(err)
		}
	}

	closed, err := store.MarkAbsentOpenClosed(ctx, repo.ID, "", []int{2})
	if err != nil {
		t.Fatal(err)
	}
	if closed != 2 {
		t.Fatalf("expected two stale open PRs to close, got %d", closed)
	}
	open, err := store.ListOpenByHead(ctx, repo.ID, "def456")
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Index != 2 {
		t.Fatalf("expected only repository-wide current PR to remain open, got %+v", open)
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
