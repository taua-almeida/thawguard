package jobs

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

func TestReconciliationEnqueueDeduplicatesAndAdvancesGeneration(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo1 := createRepository(t, ctx, database, "one")
	repo2 := createRepository(t, ctx, database, "two")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	first, err := store.EnqueueReconciliation(ctx, repo1.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.EnqueueReconciliation(ctx, repo1.ID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.EnqueueReconciliation(ctx, repo2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Generation != 1 || second.Generation != 2 || other.ID == first.ID {
		t.Fatalf("unexpected deduplicated jobs: first=%+v second=%+v other=%+v", first, second, other)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE type = ?`, ReconcileRepositoryEnforcement).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected one job per repository, got %d", count)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO jobs(type, payload_json, repository_id, generation, run_at, created_at) VALUES (?, '{}', ?, 1, ?, ?)`, ReconcileRepositoryEnforcement, repo1.ID, formatTime(now), formatTime(now)); err == nil {
		t.Fatal("expected partial unique index to reject duplicate repository job")
	}
}

func TestListReconciliationsForScopeBoundsVisibilityButNotWorkers(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo1 := createRepository(t, ctx, database, "one")
	repo2 := createRepository(t, ctx, database, "two")
	repo3 := createRepository(t, ctx, database, "three")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	for _, id := range []int64{repo1.ID, repo2.ID, repo3.ID} {
		if _, err := store.EnqueueReconciliation(ctx, id); err != nil {
			t.Fatal(err)
		}
	}

	assertScoped := func(t *testing.T, scope repositoryscope.ReadScope, wantRepositoryIDs []int64) {
		t.Helper()
		listed, err := store.ListReconciliationsForScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != len(wantRepositoryIDs) {
			t.Fatalf("expected %d scoped jobs, got %+v", len(wantRepositoryIDs), listed)
		}
		for i, want := range wantRepositoryIDs {
			if listed[i].RepositoryID != want {
				t.Fatalf("job %d: expected repository %d, got %+v", i, want, listed[i])
			}
		}
	}

	// A bounded scope lists only its repository's job; multi-repository
	// scopes keep the repository ordering; the zero-value scope denies all.
	assertScoped(t, repositoryscope.IDs(repo2.ID), []int64{repo2.ID})
	assertScoped(t, repositoryscope.IDs(repo3.ID, repo1.ID), []int64{repo1.ID, repo3.ID})
	assertScoped(t, repositoryscope.ReadScope{}, nil)
	assertScoped(t, repositoryscope.All(), []int64{repo1.ID, repo2.ID, repo3.ID})

	unrestricted, err := store.ListReconciliations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unrestricted) != 3 {
		t.Fatalf("expected unrestricted list to keep every job, got %+v", unrestricted)
	}

	// Worker claiming stays unrestricted: every repository's due job is
	// claimed regardless of any read scope.
	claimed, err := store.ClaimDue(ctx, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 3 {
		t.Fatalf("expected workers to claim every repository's job, got %+v", claimed)
	}
}

func TestReconciliationClaimHonorsDueTimeAndLease(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createRepository(t, ctx, database, "claim")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	job, err := store.EnqueueReconciliation(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE jobs SET run_at = ? WHERE id = ?`, formatTime(now.Add(time.Minute)), job.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := store.ClaimDue(ctx, 25); err != nil || len(due) != 0 {
		t.Fatalf("expected future job not to be claimed, due=%+v err=%v", due, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE jobs SET run_at = ? WHERE id = ?`, formatTime(now), job.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimDue(ctx, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].Attempts != 1 || claimed[0].LockedAt == nil {
		t.Fatalf("expected due claim, got %+v", claimed)
	}
	if again, err := store.ClaimDue(ctx, 25); err != nil || len(again) != 0 {
		t.Fatalf("expected active lease not to be reclaimed, got %+v err=%v", again, err)
	}
}

func TestReconciliationEnqueueDuringLeaseFencesOldCompletion(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createRepository(t, ctx, database, "generation")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if _, err := store.EnqueueReconciliation(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := store.ClaimRepository(ctx, repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected claim, got %+v claimed=%v err=%v", claim, claimed, err)
	}
	if current, err := store.ClaimCurrent(ctx, claim); err != nil || !current {
		t.Fatalf("expected live claim to be current, current=%v err=%v", current, err)
	}
	newer, err := store.EnqueueReconciliation(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newer.Generation != claim.Generation+1 || newer.LockedAt == nil {
		t.Fatalf("expected generation advance without lease loss, old=%+v newer=%+v", claim, newer)
	}
	if current, err := store.ClaimCurrent(ctx, claim); err != nil || current {
		t.Fatalf("expected superseded claim not to be current, current=%v err=%v", current, err)
	}
	completed, err := store.CompleteClaim(ctx, claim)
	if err != nil || completed {
		t.Fatalf("expected old completion fenced out, completed=%v err=%v", completed, err)
	}
	remaining, err := store.GetReconciliation(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if remaining.Generation != newer.Generation || remaining.LockedAt != nil {
		t.Fatalf("expected newer generation pending and old lease released, got %+v", remaining)
	}
}

func TestReconciliationStaleClaimantsCannotCompleteOrReschedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createRepository(t, ctx, database, "stale")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if _, err := store.EnqueueReconciliation(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	oldClaim, claimed, err := store.ClaimRepository(ctx, repo.ID)
	if err != nil || !claimed {
		t.Fatal("expected initial claim")
	}
	now = now.Add(ReconciliationLease + time.Second)
	newClaim, claimed, err := store.ClaimRepository(ctx, repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected stale lease reclaim, claimed=%v err=%v", claimed, err)
	}
	if newClaim.LockedAt.Equal(*oldClaim.LockedAt) || newClaim.Attempts != 2 {
		t.Fatalf("expected new lease token and attempt, old=%+v new=%+v", oldClaim, newClaim)
	}
	if completed, err := store.CompleteClaim(ctx, oldClaim); err != nil || completed {
		t.Fatalf("stale completion must be fenced, completed=%v err=%v", completed, err)
	}
	if rescheduled, err := store.RescheduleClaim(ctx, oldClaim, domain.EnforcementFailurePublication); err != nil || rescheduled {
		t.Fatalf("stale reschedule must be fenced, rescheduled=%v err=%v", rescheduled, err)
	}
	current, err := store.GetReconciliation(ctx, repo.ID)
	if err != nil || current.LockedAt == nil || !current.LockedAt.Equal(*newClaim.LockedAt) {
		t.Fatalf("expected new lease preserved, current=%+v err=%v", current, err)
	}
}

func TestManualMakeDueRespectsActiveLeaseAndReclaimsStaleLease(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createRepository(t, ctx, database, "manual")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if _, err := store.EnqueueReconciliation(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := store.ClaimRepository(ctx, repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected claim, claimed=%v err=%v", claimed, err)
	}
	if _, err := store.MakeDueNow(ctx, repo.ID); !errors.Is(err, ErrReconciliationInProgress) {
		t.Fatalf("expected active lease conflict, got %v", err)
	}
	now = now.Add(ReconciliationLease + time.Second)
	job, err := store.MakeDueNow(ctx, repo.ID)
	if err != nil || job.Generation != claim.Generation+1 {
		t.Fatalf("expected stale lease generation refresh, job=%+v err=%v", job, err)
	}
	reclaimed, ok, err := store.ClaimRepository(ctx, repo.ID)
	if err != nil || !ok || reclaimed.Attempts != 2 {
		t.Fatalf("expected stale lease reclaim for manual retry, claim=%+v ok=%v err=%v", reclaimed, ok, err)
	}
}

func TestRepositoryDeletionCascadesReconciliationJob(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createRepository(t, ctx, database, "delete")
	store := NewStore(database)
	if _, err := store.EnqueueReconciliation(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, repo.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetReconciliation(ctx, repo.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected repository delete to remove job, got %v", err)
	}
}

func TestReconciliationBackoffAndPersistedRestartClaim(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createRepository(t, ctx, database, "backoff")
	store := NewStore(database)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if _, err := store.EnqueueReconciliation(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	wantDelays := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for attempt, want := range wantDelays {
		claim, claimed, err := store.ClaimRepository(ctx, repo.ID)
		if err != nil || !claimed {
			t.Fatalf("attempt %d: expected claim, claimed=%v err=%v", attempt+1, claimed, err)
		}
		if claim.Attempts != attempt+1 {
			t.Fatalf("want attempt %d, got %d", attempt+1, claim.Attempts)
		}
		if rescheduled, err := store.RescheduleClaim(ctx, claim, domain.EnforcementFailurePublication); err != nil || !rescheduled {
			t.Fatalf("attempt %d: reschedule=%v err=%v", attempt+1, rescheduled, err)
		}
		job, err := store.GetReconciliation(ctx, repo.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got := job.RunAt.Sub(now); got != want || job.LastError != domain.EnforcementFailurePublication {
			t.Fatalf("attempt %d: want delay %s/category, got delay=%s job=%+v", attempt+1, want, got, job)
		}
		now = job.RunAt
	}

	restarted := NewStore(database)
	restarted.now = func() time.Time { return now }
	claimed, err := restarted.ClaimDue(ctx, 25)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("expected persisted work claim after restart, claimed=%+v err=%v", claimed, err)
	}
}

func newTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "jobs-test.db")))
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

func createRepository(t *testing.T, ctx context.Context, database *sql.DB, name string) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example", Name: name, DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
