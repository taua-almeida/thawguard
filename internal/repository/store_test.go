package repository

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
)

func TestStoreCreatesAndListsRepositories(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)

	repo, err := store.Create(ctx, CreateParams{
		Forge:         "Forgejo",
		BaseURL:       "https://codeberg.org/",
		Owner:         "taua-almeida",
		Name:          "thawguard",
		DefaultBranch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}

	if repo.ID == 0 {
		t.Fatal("expected repository id")
	}
	if repo.Forge != "forgejo" {
		t.Fatalf("expected normalized forge, got %q", repo.Forge)
	}
	if repo.BaseURL != "https://codeberg.org" {
		t.Fatalf("expected trimmed base URL, got %q", repo.BaseURL)
	}
	if repo.FullName() != "taua-almeida/thawguard" {
		t.Fatalf("unexpected full name: %q", repo.FullName())
	}
	if !repo.Active {
		t.Fatal("expected repository to be active")
	}

	repositories, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 1 {
		t.Fatalf("expected 1 repository, got %d", len(repositories))
	}
}

func TestStoreDefaultsRepositoryFields(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)

	repo, err := store.Create(ctx, CreateParams{Owner: "example", Name: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.Forge != "forgejo" {
		t.Fatalf("expected forgejo default, got %q", repo.Forge)
	}
	if repo.BaseURL != "https://codeberg.org" {
		t.Fatalf("expected Codeberg default, got %q", repo.BaseURL)
	}
	if repo.DefaultBranch != "main" {
		t.Fatalf("expected main default, got %q", repo.DefaultBranch)
	}
}

func TestStoreRejectsMissingRequiredFields(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)

	if _, err := store.Create(ctx, CreateParams{Name: "repo"}); !IsValidationError(err) {
		t.Fatal("expected missing owner error")
	}
	if _, err := store.Create(ctx, CreateParams{Owner: "example"}); !IsValidationError(err) {
		t.Fatal("expected missing name error")
	}
}

func TestStoreRejectsDuplicateRepositoryAsValidationError(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	params := CreateParams{Owner: "taua-almeida", Name: "thawguard"}
	if _, err := store.Create(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected duplicate validation error, got %v", err)
	}
}

func newTestStore(t *testing.T, ctx context.Context) *Store {
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
	return NewStore(database)
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
