package thawexception

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
)

func TestStoreApprovesAndFindsActiveExceptionForPullRequest(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	approved, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, PullRequestURL: "https://codeberg.org/taua-almeida/thawguard/pulls/42", TargetBranch: " main ", HeadSHA: " ABC123 ", Reason: " production fix "}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if approved.ID == 0 || approved.RepositoryID != repo.ID || approved.PullRequestIndex != 42 || approved.TargetBranch != "main" || approved.HeadSHA != "abc123" || !approved.Active || approved.Reason != "production fix" {
		t.Fatalf("unexpected approved thaw exception: %+v", approved)
	}

	active, err := store.ActiveForPullRequest(ctx, domain.PullRequest{ID: 99, RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.ID != approved.ID || active.PullRequestID != 99 {
		t.Fatalf("expected active thaw exception for PR, got %+v", active)
	}
}

func TestStoreActiveForPullRequestIgnoresChangedOrExpiredHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	expiresAt := time.Now().UTC().Add(-time.Hour)
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix", ExpiresAt: &expiresAt}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	active, err := store.ActiveForPullRequest(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("expected expired exception to be ignored, got %+v", active)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveForPullRequest(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "def456"})
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("expected changed head to miss thaw exception, got %+v", active)
	}
}

func TestStoreRejectsInvalidApproveParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.Approve(ctx, ApproveParams{PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing pull request validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing target branch validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing head SHA validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing reason validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: 999, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
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
