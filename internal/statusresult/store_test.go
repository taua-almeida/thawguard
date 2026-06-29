package statusresult

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreCreatesAndListsStatusResults(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.Create(ctx, CreateParams{
		RepositoryID:     repo.ID,
		PullRequestIndex: 42,
		TargetBranch:     " main ",
		HeadSHA:          " ABC123 ",
		Context:          domain.RequiredStatusContext,
		State:            domain.CommitStatusSuccess,
		Description:      "No active freeze applies to this PR",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected status result id")
	}
	if created.TargetBranch != "main" || created.HeadSHA != "abc123" || created.PullRequestIndex != 42 || created.State != domain.CommitStatusSuccess {
		t.Fatalf("unexpected status result: %+v", created)
	}

	results, err := store.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != created.ID {
		t.Fatalf("expected created result in recent list, got %+v", results)
	}
}

func TestStoreRejectsInvalidStatusResultParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.Create(ctx, CreateParams{PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, TargetBranch: "main", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing pull request validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing target branch validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "main", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing head SHA validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: "invalid", Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid state validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: 999, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "ma\nin", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid target branch validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "not-a-sha", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid head SHA validation error, got %v", err)
	}
}

func TestServiceRunLocalBlocksFrozenBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(NewStore(database), freezeService)

	result, err := service.RunLocal(ctx, LocalDecisionParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.Context != domain.RequiredStatusContext {
		t.Fatalf("expected failure decision for frozen branch, got %+v", result)
	}
	if result.Description != "Branch is frozen; merge is blocked by Thawguard" {
		t.Fatalf("unexpected description: %q", result.Description)
	}
}

func TestServiceRunLocalAllowsUnfrozenBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(NewStore(database), freeze.NewService(database))

	result, err := service.RunLocal(ctx, LocalDecisionParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusSuccess {
		t.Fatalf("expected success decision for unfrozen branch, got %+v", result)
	}
}

func TestServiceRunLocalRejectsMissingFields(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewService(NewStore(database), freeze.NewService(database))

	if _, err := service.RunLocal(ctx, LocalDecisionParams{}); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
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
