package repository

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
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
	if repo.EnforcementState != domain.EnforcementSetupIncomplete {
		t.Fatalf("expected new repository to default to setup_incomplete enforcement, got %q", repo.EnforcementState)
	}
	if repo.EnforcementActive() {
		t.Fatal("expected new repository not to be enforcement-active")
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

func TestStoreFindsActiveRepositoryByRemote(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	created, err := store.Create(ctx, CreateParams{Forge: "Forgejo", BaseURL: "https://codeberg.org/", Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}

	found, ok, err := store.FindActiveByRemote(ctx, RemoteParams{Forge: "forgejo", BaseURL: "https://codeberg.org/", Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected repository to be found")
	}
	if found.ID != created.ID {
		t.Fatalf("expected repository %d, got %d", created.ID, found.ID)
	}

	_, ok, err = store.FindActiveByRemote(ctx, RemoteParams{Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected missing repository not to be found")
	}
}

func TestStoreSetsAndReadsWebhookSecretCiphertext(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.HasWebhookSecret {
		t.Fatal("expected new repository not to have webhook secret")
	}

	updated, err := store.SetWebhookSecretCiphertext(ctx, repo.ID, []byte("encrypted-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.HasWebhookSecret {
		t.Fatal("expected repository to have webhook secret after update")
	}

	ciphertext, found, err := store.WebhookSecretCiphertext(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || string(ciphertext) != "encrypted-secret" {
		t.Fatalf("expected stored ciphertext, found=%v ciphertext=%q", found, ciphertext)
	}
	ciphertext[0] = 'X'
	again, found, err := store.WebhookSecretCiphertext(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || string(again) != "encrypted-secret" {
		t.Fatalf("expected ciphertext copy, found=%v ciphertext=%q", found, again)
	}
	var stored int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM repository_webhook_secrets WHERE repository_id = ?`, repo.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("expected one repository webhook secret row, got %d", stored)
	}
}

func TestStoreSetsAndReadsStatusTokenCiphertext(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.HasStatusToken {
		t.Fatal("expected new repository not to have status token")
	}

	updated, err := store.SetStatusTokenCiphertext(ctx, repo.ID, []byte("encrypted-token"))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.HasStatusToken {
		t.Fatal("expected repository to have status token after update")
	}

	ciphertext, found, err := store.StatusTokenCiphertext(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || string(ciphertext) != "encrypted-token" {
		t.Fatalf("expected stored ciphertext, found=%v ciphertext=%q", found, ciphertext)
	}
	ciphertext[0] = 'X'
	again, found, err := store.StatusTokenCiphertext(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || string(again) != "encrypted-token" {
		t.Fatalf("expected ciphertext copy, found=%v ciphertext=%q", found, again)
	}
	var stored int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM repository_status_tokens WHERE repository_id = ?`, repo.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("expected one repository status token row, got %d", stored)
	}
}

func TestStoreEnforcementStateRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := store.SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive || !updated.EnforcementActive() {
		t.Fatalf("expected active enforcement state, got %q", updated.EnforcementState)
	}

	fetched, err := store.Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.EnforcementState != domain.EnforcementActive {
		t.Fatalf("expected enforcement state to round-trip, got %q", fetched.EnforcementState)
	}

	reverted, err := store.SetEnforcementState(ctx, repo.ID, domain.EnforcementSetupIncomplete)
	if err != nil {
		t.Fatal(err)
	}
	if reverted.EnforcementState != domain.EnforcementSetupIncomplete {
		t.Fatalf("expected setup_incomplete enforcement state, got %q", reverted.EnforcementState)
	}
}

func TestStoreRejectsInvalidEnforcementState(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.SetEnforcementState(ctx, repo.ID, "shadow"); !IsValidationError(err) {
		t.Fatalf("expected invalid enforcement state validation error, got %v", err)
	}
	if _, err := store.SetEnforcementState(ctx, 0, domain.EnforcementActive); !IsValidationError(err) {
		t.Fatalf("expected repository id validation error, got %v", err)
	}
}

func TestStoreCreateInsertsDefaultManagedBranch(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)

	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo", DefaultBranch: "release/1.4"})
	if err != nil {
		t.Fatal(err)
	}

	branches, err := store.ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(branches) != 1 || branches[0].Name != "release/1.4" {
		t.Fatalf("expected default branch to be managed, got %+v", branches)
	}
	if branches[0].Protected || branches[0].SetupStatus != "unknown" || branches[0].LastCheckedAt != nil {
		t.Fatalf("expected unverified managed branch defaults, got %+v", branches[0])
	}
}

func TestStoreListBranchesIsDeterministicallyOrdered(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"release/1.4", "production", "Develop"} {
		if _, err := store.AddBranch(ctx, repo.ID, name); err != nil {
			t.Fatal(err)
		}
	}

	branches, err := store.ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(branches))
	for _, branch := range branches {
		got = append(got, branch.Name)
	}
	if want := []string{"Develop", "main", "production", "release/1.4"}; !slices.Equal(got, want) {
		t.Fatalf("expected branches %v, got %v", want, got)
	}
}

func TestStoreBranchManagedMatchesExactNamesOnly(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddBranch(ctx, repo.ID, "release/1.4"); err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{
		"main":        true,
		"release/1.4": true,
		"Main":        false,
		"release/*":   false,
		"release/1":   false,
		"":            false,
	}
	for name, want := range cases {
		managed, err := store.BranchManaged(ctx, repo.ID, name)
		if err != nil {
			t.Fatal(err)
		}
		if managed != want {
			t.Fatalf("BranchManaged(%q): want %v, got %v", name, want, managed)
		}
	}
	managed, err := store.BranchManaged(ctx, repo.ID+1, "main")
	if err != nil {
		t.Fatal(err)
	}
	if managed {
		t.Fatal("expected branch of another repository not to be managed")
	}
}

func TestStoreAddBranchValidatesNames(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}

	added, err := store.AddBranch(ctx, repo.ID, "  release/1.4  ")
	if err != nil {
		t.Fatal(err)
	}
	if added.Name != "release/1.4" {
		t.Fatalf("expected trimmed exact branch name, got %q", added.Name)
	}
	if _, err := store.AddBranch(ctx, repo.ID, "release/1.4"); !IsValidationError(err) || err.Error() != "branch is already managed" {
		t.Fatalf("expected duplicate managed branch validation error, got %v", err)
	}
	if _, err := store.AddBranch(ctx, repo.ID, "  "); !IsValidationError(err) {
		t.Fatalf("expected empty branch name validation error, got %v", err)
	}
	if _, err := store.AddBranch(ctx, repo.ID, "bad\tbranch"); !IsValidationError(err) {
		t.Fatalf("expected control character validation error, got %v", err)
	}
	if _, err := store.AddBranch(ctx, repo.ID, strings.Repeat("b", 256)); !IsValidationError(err) {
		t.Fatalf("expected long branch name validation error, got %v", err)
	}
	preserved, err := store.AddBranch(ctx, repo.ID, "Release/CASE")
	if err != nil {
		t.Fatal(err)
	}
	if preserved.Name != "Release/CASE" {
		t.Fatalf("expected branch case to be preserved, got %q", preserved.Name)
	}
}

func TestStoreRemoveBranchReportsUnknownBranch(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "example-owner", Name: "example-repo"})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.RemoveBranch(ctx, repo.ID, "missing"); !IsValidationError(err) || err.Error() != "managed branch not found" {
		t.Fatalf("expected managed branch not found error, got %v", err)
	}
	if _, err := store.AddBranch(ctx, repo.ID, "release/1.4"); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveBranch(ctx, repo.ID, "release/1.4"); err != nil {
		t.Fatal(err)
	}
	managed, err := store.BranchManaged(ctx, repo.ID, "release/1.4")
	if err != nil {
		t.Fatal(err)
	}
	if managed {
		t.Fatal("expected removed branch not to be managed")
	}
}

func TestStoreSetsAndClearsStatusPostVerification(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.StatusPostVerifiedAt != nil {
		t.Fatalf("expected new repository without verification evidence, got %+v", repo.StatusPostVerifiedAt)
	}

	verifiedAt := time.Date(2026, 7, 12, 10, 30, 0, 0, time.UTC)
	updated, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, &verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	if updated.StatusPostVerifiedAt == nil || !updated.StatusPostVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("expected persisted verification time, got %+v", updated.StatusPostVerifiedAt)
	}

	cleared, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.StatusPostVerifiedAt != nil {
		t.Fatalf("expected cleared verification evidence, got %+v", cleared.StatusPostVerifiedAt)
	}

	if _, err := store.SetStatusPostVerifiedAt(ctx, 999, &verifiedAt); err == nil {
		t.Fatal("expected missing repository error")
	}
	if _, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, &time.Time{}); !IsValidationError(err) {
		t.Fatalf("expected zero-time validation error, got %v", err)
	}
}

func TestStoreSetsAndClearsEnforcementFailure(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.EnforcementFailureReason != "" || repo.EnforcementFailedAt != nil {
		t.Fatalf("expected new repository without failure state, got %+v", repo)
	}

	failedAt := time.Date(2026, 7, 12, 10, 30, 0, 123456789, time.UTC)
	updated, err := store.SetEnforcementFailure(ctx, repo.ID, domain.EnforcementFailurePublication, failedAt)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementFailureReason != domain.EnforcementFailurePublication {
		t.Fatalf("unexpected stored reason: %q", updated.EnforcementFailureReason)
	}
	if updated.EnforcementFailedAt == nil || !updated.EnforcementFailedAt.Equal(failedAt) {
		t.Fatalf("expected failure timestamp round-trip, got %+v", updated.EnforcementFailedAt)
	}

	// Updating with a newer failure replaces both fields together.
	laterAt := failedAt.Add(time.Hour)
	updated, err = store.SetEnforcementFailure(ctx, repo.ID, domain.EnforcementFailureReadinessChecks, laterAt)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementFailureReason != domain.EnforcementFailureReadinessChecks || !updated.EnforcementFailedAt.Equal(laterAt) {
		t.Fatalf("expected replaced failure state, got %+v", updated)
	}

	cleared, err := store.ClearEnforcementFailure(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.EnforcementFailureReason != "" || cleared.EnforcementFailedAt != nil {
		t.Fatalf("expected cleared failure state, got %+v", cleared)
	}
}

func TestStoreRejectsInvalidEnforcementFailures(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repo, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "thawguard"})
	if err != nil {
		t.Fatal(err)
	}

	// Only the stable bounded categories may reach repository state: raw
	// wrapped errors and free-form strings are rejected.
	for _, reason := range []string{"", "surprise error with token abc123", strings.Repeat("x", 500)} {
		if _, err := store.SetEnforcementFailure(ctx, repo.ID, reason, time.Now()); !IsValidationError(err) {
			t.Fatalf("expected validation error for reason %q, got %v", reason, err)
		}
	}
	if _, err := store.SetEnforcementFailure(ctx, repo.ID, domain.EnforcementFailurePublication, time.Time{}); !IsValidationError(err) {
		t.Fatalf("expected zero-time validation error, got %v", err)
	}
	if _, err := store.SetEnforcementFailure(ctx, 999, domain.EnforcementFailurePublication, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected missing repository error, got %v", err)
	}
	if _, err := store.ClearEnforcementFailure(ctx, 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected missing repository error on clear, got %v", err)
	}
	stored, err := store.Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnforcementFailureReason != "" || stored.EnforcementFailedAt != nil {
		t.Fatalf("expected rejected updates to leave failure state untouched, got %+v", stored)
	}
}

func TestStoreEnforcementStateAndFailureRollBackTogether(t *testing.T) {
	ctx := context.Background()
	database := newTestDatabase(t, ctx)
	repo, err := NewStore(database).Create(ctx, CreateParams{Owner: "taua-almeida", Name: "thawguard"})
	if err != nil {
		t.Fatal(err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	txStore := NewStoreTx(tx)
	if _, err := txStore.SetEnforcementState(ctx, repo.ID, domain.EnforcementUnhealthy); err != nil {
		t.Fatal(err)
	}
	if _, err := txStore.SetEnforcementFailure(ctx, repo.ID, domain.EnforcementFailureOpenPRSync, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	stored, err := NewStore(database).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnforcementState != domain.EnforcementSetupIncomplete || stored.EnforcementFailureReason != "" || stored.EnforcementFailedAt != nil {
		t.Fatalf("expected rolled-back state and failure fields, got %+v", stored)
	}
}

func newTestStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	return NewStore(newTestDatabase(t, ctx))
}

func newTestDatabase(t *testing.T, ctx context.Context) *sql.DB {
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

func TestStoreScopedListAndLookup(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repoA, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	repoB, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "frost-api"})
	if err != nil {
		t.Fatal(err)
	}

	assertListedIDs := func(t *testing.T, scope repositoryscope.ReadScope, wantIDs []int64) {
		t.Helper()
		listed, err := store.ListForScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		gotIDs := make([]int64, 0, len(listed))
		for _, repo := range listed {
			gotIDs = append(gotIDs, repo.ID)
		}
		if !slices.Equal(gotIDs, wantIDs) {
			t.Fatalf("expected repository ids %v, got %v", wantIDs, gotIDs)
		}
	}

	// List still orders by owner and name, so frost-api precedes thawguard.
	assertListedIDs(t, repositoryscope.All(), []int64{repoB.ID, repoA.ID})
	assertListedIDs(t, repositoryscope.IDs(repoA.ID), []int64{repoA.ID})
	assertListedIDs(t, repositoryscope.ReadScope{}, nil)

	scopeA := repositoryscope.IDs(repoA.ID)
	if got, err := store.GetForScope(ctx, scopeA, repoA.ID); err != nil || got.ID != repoA.ID {
		t.Fatalf("expected in-scope lookup to succeed, got %+v, %v", got, err)
	}
	inaccessibleErr := func(t *testing.T, scope repositoryscope.ReadScope, id int64) error {
		t.Helper()
		_, err := store.GetForScope(ctx, scope, id)
		if err == nil {
			t.Fatalf("expected lookup of repository %d to fail", id)
		}
		return err
	}
	hiddenErr := inaccessibleErr(t, scopeA, repoB.ID)
	missingErr := inaccessibleErr(t, scopeA, 999_999)
	if !errors.Is(hiddenErr, sql.ErrNoRows) || !errors.Is(missingErr, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows for hidden and missing repositories, got %v and %v", hiddenErr, missingErr)
	}
	if hiddenErr.Error() != missingErr.Error() {
		t.Fatalf("expected indistinguishable errors, got %q and %q", hiddenErr.Error(), missingErr.Error())
	}
	if err := inaccessibleErr(t, repositoryscope.ReadScope{}, repoA.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected zero-value scope to deny lookup, got %v", err)
	}

	// The unrestricted APIs stay unrestricted for workers and internal paths.
	unrestricted, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unrestricted) != 2 {
		t.Fatalf("expected unrestricted list to keep both repositories, got %+v", unrestricted)
	}
	if got, err := store.Get(ctx, repoB.ID); err != nil || got.ID != repoB.ID {
		t.Fatalf("expected unrestricted lookup to keep repository B, got %+v, %v", got, err)
	}
}

func TestStoreScopedListMatchesRepositoryGrants(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	repoA, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, CreateParams{Owner: "taua-almeida", Name: "frost-api"}); err != nil {
		t.Fatal(err)
	}

	for _, role := range auth.RepositoryRoles() {
		scope := auth.NewGrants(false, map[int64]auth.RoleSet{repoA.ID: {role}}).RepositoryReadScope()
		listed, err := store.ListForScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 1 || listed[0].ID != repoA.ID {
			t.Fatalf("%s: expected visibility for exactly the granted repository, got %+v", role, listed)
		}
	}

	admin, err := store.ListForScope(ctx, auth.NewGrants(true, nil).RepositoryReadScope())
	if err != nil {
		t.Fatal(err)
	}
	if len(admin) != 2 {
		t.Fatalf("expected admin to see both repositories, got %+v", admin)
	}

	nobody, err := store.ListForScope(ctx, auth.NewGrants(false, nil).RepositoryReadScope())
	if err != nil {
		t.Fatal(err)
	}
	if len(nobody) != 0 {
		t.Fatalf("expected a user without grants to see no repositories, got %+v", nobody)
	}
}
