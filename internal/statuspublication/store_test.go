package statuspublication

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

func TestStorePublishesForgejoStatusIntent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	result := createStatusResult(t, ctx, database, repo.ID)
	store := NewStore(database)

	publication, err := store.PublishForgejoStatus(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if publication.ID == 0 {
		t.Fatal("expected publication id")
	}
	if publication.StatusResultID != result.ID || publication.RepositoryID != repo.ID || publication.HeadSHA != result.HeadSHA {
		t.Fatalf("unexpected publication: %+v", publication)
	}
	if publication.DeliveryMode != DeliveryModeForgejoStatus {
		t.Fatalf("expected forgejo delivery mode, got %q", publication.DeliveryMode)
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

func TestStorePublishUpsertsForgejoStatusIntentByStatusKey(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	firstResult := createStatusResultWithParams(t, ctx, database, repo.ID, 42, "main", "abc123", domain.CommitStatusFailure, "Branch is frozen; merge is blocked by Thawguard")
	store := NewStore(database)
	firstTime := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return firstTime }

	first, err := store.PublishForgejoStatus(ctx, firstResult)
	if err != nil {
		t.Fatal(err)
	}

	secondResult := createStatusResultWithParams(t, ctx, database, repo.ID, 43, "release", "abc123", domain.CommitStatusSuccess, "No active freeze applies to this PR")
	secondTime := firstTime.Add(5 * time.Minute)
	store.now = func() time.Time { return secondTime }
	second, err := store.PublishForgejoStatus(ctx, secondResult)
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

func TestStoreKeepsHistoricalLocalRecordIntentsReadable(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	result := createStatusResult(t, ctx, database, repo.ID)
	store := NewStore(database)

	if _, err := database.ExecContext(ctx, `INSERT INTO status_publication_intents(status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, delivery_mode, created_at, updated_at) VALUES (?, ?, 42, 'main', 'abc123', ?, 'failure', 'historical shadow record', 'local_record', '2026-06-30T12:00:00.000000000Z', '2026-06-30T12:00:00.000000000Z')`, result.ID, repo.ID, domain.RequiredStatusContext); err != nil {
		t.Fatal(err)
	}

	publications, err := store.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 1 || publications[0].DeliveryMode != "local_record" {
		t.Fatalf("expected historical local_record intent to stay readable, got %+v", publications)
	}
}

func TestStoreRecordsForgejoStatusPublicationAttempts(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	result := createStatusResult(t, ctx, database, repo.ID)
	store := NewStore(database)
	publication, err := store.PublishForgejoStatus(ctx, result)
	if err != nil {
		t.Fatal(err)
	}

	posted, err := store.RecordForgejoStatusAttempt(ctx, publication, AttemptResultPosted, "")
	if err != nil {
		t.Fatal(err)
	}
	if posted.Mode != AttemptModeForgejoStatus || posted.Result != AttemptResultPosted || posted.Error != "" {
		t.Fatalf("unexpected posted attempt: %+v", posted)
	}
	if posted.PublicationID != publication.ID || posted.StatusResultID != result.ID || posted.RepositoryID != repo.ID {
		t.Fatalf("unexpected attempt identity: %+v", posted)
	}

	failed, err := store.RecordForgejoStatusAttempt(ctx, publication, AttemptResultFailed, "forge returned 500")
	if err != nil {
		t.Fatal(err)
	}
	if failed.Mode != AttemptModeForgejoStatus || failed.Result != AttemptResultFailed || failed.Error != "forge returned 500" {
		t.Fatalf("unexpected failed attempt: %+v", failed)
	}

	attempts, err := store.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected two recent attempts, got %+v", attempts)
	}
}

func TestStoreRejectsInvalidPublicationAttempt(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewStore(database)

	if _, err := store.RecordForgejoStatusAttempt(ctx, Publication{}, AttemptResultPosted, ""); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	publication := Publication{ID: 1, StatusResultID: 1, RepositoryID: 1, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "blocked", DeliveryMode: DeliveryModeForgejoStatus}
	if _, err := store.RecordForgejoStatusAttempt(ctx, publication, "planned", ""); !IsValidationError(err) {
		t.Fatalf("expected invalid forgejo attempt result validation error, got %v", err)
	}
	if _, err := store.RecordForgejoStatusAttempt(ctx, publication, AttemptResultFailed, ""); !IsValidationError(err) {
		t.Fatalf("expected failed forgejo attempt error validation, got %v", err)
	}
}

func TestStoreRejectsInvalidPublicationResult(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewStore(database)

	if _, err := store.PublishForgejoStatus(ctx, statusresult.Result{}); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := store.PublishForgejoStatus(ctx, statusresult.Result{ID: 1, RepositoryID: 1, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: "invalid", Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid state validation error, got %v", err)
	}
}

func TestStoreListPageFiltersAndPaginates(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	repo2, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example-owner", Name: "second-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(database)

	seed := []struct {
		repositoryID int64
		index        int
		state        domain.CommitStatusState
	}{
		{repo.ID, 1, domain.CommitStatusFailure},
		{repo.ID, 2, domain.CommitStatusSuccess},
		{repo2.ID, 3, domain.CommitStatusFailure},
		{repo.ID, 4, domain.CommitStatusPending},
		{repo2.ID, 5, domain.CommitStatusSuccess},
	}
	for _, entry := range seed {
		result := createStatusResultWithParams(t, ctx, database, entry.repositoryID, entry.index, "main", fmt.Sprintf("abc%03d", entry.index), entry.state, "seeded")
		if _, err := store.PublishForgejoStatus(ctx, result); err != nil {
			t.Fatal(err)
		}
	}

	assertPageIndexes := func(label string, publications []Publication, want ...int) {
		t.Helper()
		got := make([]int, 0, len(publications))
		for _, publication := range publications {
			got = append(got, publication.PullRequestIndex)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: expected indexes %v, got %v", label, want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: expected indexes %v, got %v", label, want, got)
			}
		}
	}

	page, total, err := store.ListPage(ctx, "", 0, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	assertPageIndexes("first page", page, 5, 4)

	page, total, err = store.ListPage(ctx, "", 0, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("expected stable total 5, got %d", total)
	}
	assertPageIndexes("second page", page, 3, 2)

	page, _, err = store.ListPage(ctx, string(domain.CommitStatusFailure), 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	assertPageIndexes("state filter", page, 3, 1)

	page, _, err = store.ListPage(ctx, "", repo2.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	assertPageIndexes("repository filter", page, 5, 3)

	page, total, err = store.ListPage(ctx, string(domain.CommitStatusFailure), repo2.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected combined-filter total 1, got %d", total)
	}
	assertPageIndexes("combined filter", page, 3)

	page, total, err = store.ListPage(ctx, "bogus", 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(page) != 0 {
		t.Fatalf("expected unknown state to match nothing, got total %d rows %v", total, page)
	}

	page, total, err = store.ListPage(ctx, "", 0, -5, -1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(page) != 5 {
		t.Fatalf("expected clamped page to return everything, got total %d rows %d", total, len(page))
	}
}

func TestStoreListAttemptsPageFiltersAndPaginates(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	repo2, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example-owner", Name: "second-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(database)

	result1 := createStatusResultWithParams(t, ctx, database, repo.ID, 1, "main", "abc001", domain.CommitStatusFailure, "seeded")
	publication1, err := store.PublishForgejoStatus(ctx, result1)
	if err != nil {
		t.Fatal(err)
	}
	result2 := createStatusResultWithParams(t, ctx, database, repo2.ID, 2, "main", "abc002", domain.CommitStatusSuccess, "seeded")
	publication2, err := store.PublishForgejoStatus(ctx, result2)
	if err != nil {
		t.Fatal(err)
	}

	seed := []struct {
		publication Publication
		result      string
		message     string
	}{
		{publication1, AttemptResultPosted, ""},
		{publication1, AttemptResultFailed, "forge returned 500"},
		{publication2, AttemptResultPosted, ""},
		{publication2, AttemptResultFailed, "forge returned 403"},
	}
	ids := make([]int64, 0, len(seed))
	for _, entry := range seed {
		attempt, err := store.RecordForgejoStatusAttempt(ctx, entry.publication, entry.result, entry.message)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, attempt.ID)
	}

	assertAttemptIDs := func(label string, attempts []Attempt, want ...int64) {
		t.Helper()
		got := make([]int64, 0, len(attempts))
		for _, attempt := range attempts {
			got = append(got, attempt.ID)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: expected ids %v, got %v", label, want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: expected ids %v, got %v", label, want, got)
			}
		}
	}

	page, total, err := store.ListAttemptsPage(ctx, "", 0, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("expected total 4, got %d", total)
	}
	assertAttemptIDs("first page", page, ids[3], ids[2], ids[1])

	page, total, err = store.ListAttemptsPage(ctx, "", 0, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("expected stable total 4, got %d", total)
	}
	assertAttemptIDs("second page", page, ids[0])

	page, _, err = store.ListAttemptsPage(ctx, AttemptResultFailed, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	assertAttemptIDs("result filter", page, ids[3], ids[1])

	page, _, err = store.ListAttemptsPage(ctx, "", repo2.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	assertAttemptIDs("repository filter", page, ids[3], ids[2])

	page, total, err = store.ListAttemptsPage(ctx, AttemptResultPosted, repo2.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected combined-filter total 1, got %d", total)
	}
	assertAttemptIDs("combined filter", page, ids[2])

	page, total, err = store.ListAttemptsPage(ctx, "", 0, -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || len(page) != 4 {
		t.Fatalf("expected clamped page to return everything, got total %d rows %d", total, len(page))
	}
}

func TestStoreListsPageForScope(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example-owner", Name: "second-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(database)

	// Repository B rows are created after each repository A row, so the
	// newest intents an unrestricted page would serve first are foreign to a
	// scope over repository A.
	seed := []struct {
		repositoryID int64
		index        int
		state        domain.CommitStatusState
	}{
		{repoA.ID, 1, domain.CommitStatusSuccess},
		{repoB.ID, 2, domain.CommitStatusFailure},
		{repoB.ID, 3, domain.CommitStatusSuccess},
		{repoA.ID, 4, domain.CommitStatusFailure},
		{repoB.ID, 5, domain.CommitStatusSuccess},
	}
	ids := make([]int64, 0, len(seed))
	for _, entry := range seed {
		result := createStatusResultWithParams(t, ctx, database, entry.repositoryID, entry.index, "main", fmt.Sprintf("abc%03d", entry.index), entry.state, "seeded")
		publication, err := store.PublishForgejoStatus(ctx, result)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, publication.ID)
	}

	assertPage := func(t *testing.T, scope repositoryscope.ReadScope, state string, repositoryID int64, offset, limit int, wantTotal int, wantIDs []int64) {
		t.Helper()
		rows, total, err := store.ListPageForScope(ctx, scope, state, repositoryID, offset, limit)
		if err != nil {
			t.Fatal(err)
		}
		if total != wantTotal {
			t.Fatalf("expected total %d, got %d", wantTotal, total)
		}
		if len(rows) != len(wantIDs) {
			t.Fatalf("expected %d rows, got %+v", len(wantIDs), rows)
		}
		for i, row := range rows {
			if row.ID != wantIDs[i] {
				t.Fatalf("row %d: expected id %d, got %d", i, wantIDs[i], row.ID)
			}
		}
	}

	scopeA := repositoryscope.IDs(repoA.ID)
	// A one-row page skips the newer foreign intent and still serves the
	// accessible one, with the total counted under the same conditions.
	assertPage(t, scopeA, "", 0, 0, 1, 2, []int64{ids[3]})
	assertPage(t, scopeA, "", 0, 1, 1, 2, []int64{ids[0]})
	// State and repository filters intersect the scope, never widen it.
	assertPage(t, scopeA, string(domain.CommitStatusSuccess), 0, 0, 10, 1, []int64{ids[0]})
	assertPage(t, scopeA, string(domain.CommitStatusSuccess), repoA.ID, 0, 10, 1, []int64{ids[0]})
	// Filtering for an inaccessible repository yields nothing, not the
	// accessible rows.
	assertPage(t, scopeA, "", repoB.ID, 0, 10, 0, nil)
	assertPage(t, scopeA, string(domain.CommitStatusSuccess), repoB.ID, 0, 10, 0, nil)
	// The zero-value scope denies everything; the all scope matches the
	// unrestricted method.
	assertPage(t, repositoryscope.ReadScope{}, "", 0, 0, 10, 0, nil)
	assertPage(t, repositoryscope.All(), "", 0, 0, 10, 5, []int64{ids[4], ids[3], ids[2], ids[1], ids[0]})

	unrestricted, total, err := store.ListPage(ctx, "", 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(unrestricted) != 5 {
		t.Fatalf("expected unrestricted page to keep every row, got total %d and %+v", total, unrestricted)
	}
}

func TestStoreListsAttemptsPageForScope(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example-owner", Name: "second-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(database)

	resultA := createStatusResultWithParams(t, ctx, database, repoA.ID, 1, "main", "abc001", domain.CommitStatusFailure, "seeded")
	publicationA, err := store.PublishForgejoStatus(ctx, resultA)
	if err != nil {
		t.Fatal(err)
	}
	resultB := createStatusResultWithParams(t, ctx, database, repoB.ID, 2, "main", "abc002", domain.CommitStatusSuccess, "seeded")
	publicationB, err := store.PublishForgejoStatus(ctx, resultB)
	if err != nil {
		t.Fatal(err)
	}

	// The final attempts belong to repository B, so the newest rows an
	// unrestricted page would serve first are foreign to a scope over
	// repository A.
	seed := []struct {
		publication Publication
		result      string
		message     string
	}{
		{publicationA, AttemptResultPosted, ""},
		{publicationB, AttemptResultFailed, "forge returned 500"},
		{publicationA, AttemptResultFailed, "forge returned 502"},
		{publicationB, AttemptResultPosted, ""},
		{publicationB, AttemptResultPosted, ""},
	}
	ids := make([]int64, 0, len(seed))
	for _, entry := range seed {
		attempt, err := store.RecordForgejoStatusAttempt(ctx, entry.publication, entry.result, entry.message)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, attempt.ID)
	}

	assertPage := func(t *testing.T, scope repositoryscope.ReadScope, result string, repositoryID int64, offset, limit int, wantTotal int, wantIDs []int64) {
		t.Helper()
		rows, total, err := store.ListAttemptsPageForScope(ctx, scope, result, repositoryID, offset, limit)
		if err != nil {
			t.Fatal(err)
		}
		if total != wantTotal {
			t.Fatalf("expected total %d, got %d", wantTotal, total)
		}
		if len(rows) != len(wantIDs) {
			t.Fatalf("expected %d rows, got %+v", len(wantIDs), rows)
		}
		for i, row := range rows {
			if row.ID != wantIDs[i] {
				t.Fatalf("row %d: expected id %d, got %d", i, wantIDs[i], row.ID)
			}
		}
	}

	scopeA := repositoryscope.IDs(repoA.ID)
	// A one-row page skips the newer foreign attempts and still serves the
	// accessible one, with the total counted under the same conditions.
	assertPage(t, scopeA, "", 0, 0, 1, 2, []int64{ids[2]})
	assertPage(t, scopeA, "", 0, 1, 1, 2, []int64{ids[0]})
	// Result and repository filters intersect the scope, never widen it.
	assertPage(t, scopeA, AttemptResultPosted, 0, 0, 10, 1, []int64{ids[0]})
	assertPage(t, scopeA, AttemptResultPosted, repoA.ID, 0, 10, 1, []int64{ids[0]})
	// Filtering for an inaccessible repository yields nothing, not the
	// accessible rows.
	assertPage(t, scopeA, "", repoB.ID, 0, 10, 0, nil)
	assertPage(t, scopeA, AttemptResultFailed, repoB.ID, 0, 10, 0, nil)
	// The zero-value scope denies everything; the all scope matches the
	// unrestricted method.
	assertPage(t, repositoryscope.ReadScope{}, "", 0, 0, 10, 0, nil)
	assertPage(t, repositoryscope.All(), "", 0, 0, 10, 5, []int64{ids[4], ids[3], ids[2], ids[1], ids[0]})

	unrestricted, total, err := store.ListAttemptsPage(ctx, "", 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(unrestricted) != 5 {
		t.Fatalf("expected unrestricted page to keep every row, got total %d and %+v", total, unrestricted)
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
