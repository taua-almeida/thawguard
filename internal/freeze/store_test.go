package freeze

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

func TestStoreCreatesAndListsActiveFreezes(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: " dev ", Reason: " QA freeze "})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected freeze id")
	}
	if created.RepositoryID != repo.ID || created.Branch != "dev" || created.Reason != "QA freeze" {
		t.Fatalf("unexpected freeze: %+v", created)
	}
	if created.Status != domain.BranchFreezeStatusActive || !created.Active {
		t.Fatalf("expected active freeze, got %+v", created)
	}
	if created.StartsAt == nil {
		t.Fatal("expected active freeze start time")
	}

	freezes, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(freezes) != 1 || freezes[0].ID != created.ID {
		t.Fatalf("expected created freeze in active list, got %+v", freezes)
	}
}

func TestStoreCreatesImmediateFreezeWithUTCPlannedEnd(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 12, 12, 0, 0, 123, time.UTC)
	store.now = func() time.Time { return now }
	plannedLocal := time.Date(2026, 7, 13, 9, 0, 0, 0, time.FixedZone("browser", -4*60*60))

	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "production deployment", PlannedEndsAt: &plannedLocal})
	if err != nil {
		t.Fatal(err)
	}
	if created.Scheduled || created.PlannedEndsAt == nil {
		t.Fatalf("expected immediate freeze with planned end, got %+v", created)
	}
	if got, want := created.PlannedEndsAt.Format(time.RFC3339Nano), "2026-07-13T13:00:00Z"; got != want {
		t.Fatalf("expected UTC planned end %s, got %s", want, got)
	}
	var stored string
	if err := database.QueryRowContext(ctx, `SELECT planned_ends_at FROM branch_freezes WHERE id = ?`, created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "2026-07-13T13:00:00.000000000Z" {
		t.Fatalf("expected fixed-width SQLite timestamp, got %q", stored)
	}
}

func TestStoreRejectsPastOrEqualImmediatePlannedEnd(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	for _, planned := range []time.Time{now, now.Add(-time.Nanosecond)} {
		if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", PlannedEndsAt: &planned}); !IsValidationError(err) {
			t.Fatalf("expected planned end %s to be rejected, got %v", planned, err)
		}
	}
}

func TestStoreSelectsAndExecutesDuePlannedUnfreezesAcrossFreezeKinds(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	base := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	createImmediate := func(branch string, planned time.Time) domain.BranchFreeze {
		t.Helper()
		created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: branch, Reason: branch, PlannedEndsAt: &planned})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	immediate := createImmediate("main", base.Add(time.Hour))
	_ = createImmediate("future", base.Add(10*time.Hour))
	ended := createImmediate("ended", base.Add(90*time.Minute))
	if _, err := store.End(ctx, ended.ID); err != nil {
		t.Fatal(err)
	}
	cancelled := createImmediate("cancelled", base.Add(75*time.Minute))
	if _, err := store.Cancel(ctx, cancelled.ID); err != nil {
		t.Fatal(err)
	}

	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "release", Reason: "scheduled", StartsAt: base.Add(30 * time.Minute), PlannedEndsAt: timePointer(base.Add(2 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(30 * time.Minute) }
	if _, err := store.ActivateScheduled(ctx, scheduled.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "later", Reason: "not active", StartsAt: base.Add(4 * time.Hour), PlannedEndsAt: timePointer(base.Add(5 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE branch_freezes SET planned_ends_at = ? WHERE id = ?`, base.Add(2*time.Hour).Format(sqliteTimestampFormat), pending.ID); err != nil {
		t.Fatal(err)
	}

	store.now = func() time.Time { return base.Add(3 * time.Hour) }
	due, err := store.ListDuePlannedUnfreezes(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 || due[0].ID != immediate.ID || due[1].ID != scheduled.ID {
		t.Fatalf("expected deterministic immediate then scheduled due rows, got %+v", due)
	}
	endedImmediate, err := store.ExecutePlannedUnfreeze(ctx, immediate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if endedImmediate.Status != domain.BranchFreezeStatusEnded || endedImmediate.Scheduled || endedImmediate.EndsAt == nil || endedImmediate.PlannedEndsAt == nil || !endedImmediate.NeedsRecompute {
		t.Fatalf("unexpected ended immediate freeze %+v", endedImmediate)
	}
	if _, err := store.ExecutePlannedUnfreeze(ctx, immediate.ID); !IsValidationError(err) {
		t.Fatalf("expected duplicate execution to be rejected, got %v", err)
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func TestStoreRejectsInvalidFreezeParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.CreateActive(ctx, CreateParams{Branch: "main", Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing branch validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main"}); err != nil {
		t.Fatalf("expected a freeze without a reason to be accepted, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: 999, Branch: "main", Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "dev", Reason: strings.Repeat("r", 501)}); !IsValidationError(err) {
		t.Fatalf("expected over-length reason validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "dev", Reason: "line one\nline two"}); !IsValidationError(err) {
		t.Fatalf("expected control-character reason validation error, got %v", err)
	}
}

func TestStoreRejectsDuplicateActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	params := CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}

	if _, err := store.CreateActive(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateActive(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected duplicate active freeze validation error, got %v", err)
	}
}

func TestStoreAllowsScheduledFreezeWhenBranchIsAlreadyFrozen(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}); err != nil {
		t.Fatal(err)
	}
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekend", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("expected scheduled freeze to be allowed while branch is active: %v", err)
	}
	if scheduled.Status != domain.BranchFreezeStatusScheduled || !scheduled.Scheduled {
		t.Fatalf("expected scheduled freeze, got %+v", scheduled)
	}
	store.now = func() time.Time { return now.Add(time.Hour + time.Minute) }
	activated, err := store.ActivateScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatalf("expected scheduled freeze to activate even while another freeze is active: %v", err)
	}
	if activated.Status != domain.BranchFreezeStatusActive || !activated.Active || !activated.Scheduled {
		t.Fatalf("expected active scheduled freeze, got %+v", activated)
	}
	active, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("expected manual and scheduled active freezes, got %+v", active)
	}
}

func TestStoreAllowsMultipleScheduledFreezesForSameBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekday freeze", StartsAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekend freeze", StartsAt: now.Add(48 * time.Hour)}); err != nil {
		t.Fatalf("expected multiple scheduled freezes for one branch: %v", err)
	}
	scheduled, err := store.ListScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scheduled) != 2 {
		t.Fatalf("expected two scheduled freezes for same branch, got %+v", scheduled)
	}
}

func TestStoreListsScheduledPageWithFilterAndOffset(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	ids := make([]int64, 0, 3)
	for i, reason := range []string{"first window", "second window", "third window"} {
		created, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: reason, StartsAt: now.Add(time.Duration(i+1) * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}
	if _, err := store.CancelScheduled(ctx, ids[2]); err != nil {
		t.Fatal(err)
	}

	all, total, err := store.ListScheduledPage(ctx, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("expected all three windows with total 3, got total=%d list=%+v", total, all)
	}
	if all[0].ID != ids[0] || all[1].ID != ids[1] || all[2].ID != ids[2] {
		t.Fatalf("expected pending windows before cancelled, got %+v", all)
	}

	pending, total, err := store.ListScheduledPage(ctx, domain.BranchFreezeStatusScheduled, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(pending) != 2 {
		t.Fatalf("expected two pending windows, got total=%d list=%+v", total, pending)
	}

	page, total, err := store.ListScheduledPage(ctx, "", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(page) != 1 || page[0].ID != ids[2] {
		t.Fatalf("expected offset page with cancelled window, got total=%d list=%+v", total, page)
	}

	cancelled, total, err := store.ListScheduledPage(ctx, domain.BranchFreezeStatusCancelled, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(cancelled) != 1 || cancelled[0].ID != ids[2] {
		t.Fatalf("expected single cancelled window, got total=%d list=%+v", total, cancelled)
	}
}

func TestStoreScopesActiveFreezeReads(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB := createTestRepositoryNamed(t, ctx, database, "thawguard-docs")
	store := NewStore(database)
	base := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	frozenA, err := store.CreateActive(ctx, CreateParams{RepositoryID: repoA.ID, Branch: "main", Reason: "release freeze"})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(time.Minute) }
	frozenB, err := store.CreateActive(ctx, CreateParams{RepositoryID: repoB.ID, Branch: "main", Reason: "docs freeze"})
	if err != nil {
		t.Fatal(err)
	}

	all, err := store.ListActiveForScope(ctx, repositoryscope.All())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != frozenB.ID || all[1].ID != frozenA.ID {
		t.Fatalf("expected both active freezes newest first, got %+v", all)
	}

	scoped, err := store.ListActiveForScope(ctx, repositoryscope.IDs(repoA.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].ID != frozenA.ID {
		t.Fatalf("expected only repo A's active freeze, got %+v", scoped)
	}

	denied, err := store.ListActiveForScope(ctx, repositoryscope.ReadScope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Fatalf("expected zero-value scope to hide every freeze, got %+v", denied)
	}

	unrestricted, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unrestricted) != 2 {
		t.Fatalf("expected unrestricted list to keep both freezes, got %+v", unrestricted)
	}

	viaService, err := NewService(database).ListActiveForScope(ctx, repositoryscope.IDs(repoA.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(viaService) != 1 || viaService[0].ID != frozenA.ID {
		t.Fatalf("expected service pass-through to scope like the store, got %+v", viaService)
	}
}

func TestStoreGetForScopeHidesForeignAndMissingFreezes(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB := createTestRepositoryNamed(t, ctx, database, "thawguard-docs")
	store := NewStore(database)

	frozenA, err := store.CreateActive(ctx, CreateParams{RepositoryID: repoA.ID, Branch: "main", Reason: "release freeze"})
	if err != nil {
		t.Fatal(err)
	}
	frozenB, err := store.CreateActive(ctx, CreateParams{RepositoryID: repoB.ID, Branch: "main", Reason: "docs freeze"})
	if err != nil {
		t.Fatal(err)
	}

	scopeA := repositoryscope.IDs(repoA.ID)
	visible, err := store.GetForScope(ctx, scopeA, frozenA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if visible.ID != frozenA.ID {
		t.Fatalf("expected in-scope freeze, got %+v", visible)
	}

	if _, err := store.GetForScope(ctx, scopeA, frozenB.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected hidden freeze to look nonexistent, got %v", err)
	}
	if _, err := store.GetForScope(ctx, scopeA, frozenB.ID+99999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected missing freeze to return sql.ErrNoRows, got %v", err)
	}
	if _, err := store.GetForScope(ctx, repositoryscope.ReadScope{}, frozenA.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected zero-value scope to hide every freeze, got %v", err)
	}

	foreign, err := store.Get(ctx, frozenB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if foreign.ID != frozenB.ID {
		t.Fatalf("expected unrestricted get to keep fetching any freeze, got %+v", foreign)
	}

	if _, err := NewService(database).GetForScope(ctx, scopeA, frozenB.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected service pass-through to hide the foreign freeze, got %v", err)
	}
}

func TestStoreListScheduledForScopeFiltersBeforeLimit(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB := createTestRepositoryNamed(t, ctx, database, "thawguard-docs")
	store := NewStore(database)
	base := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	foreign, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoB.ID, Branch: "main", Reason: "docs window", StartsAt: base.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	firstA, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoA.ID, Branch: "main", Reason: "first window", StartsAt: base.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	secondA, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoA.ID, Branch: "release", Reason: "second window", StartsAt: base.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	scoped, err := store.ListScheduledForScope(ctx, repositoryscope.IDs(repoA.ID), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 2 || scoped[0].ID != firstA.ID || scoped[1].ID != secondA.ID {
		t.Fatalf("expected the limit to fill with in-scope rows even though a foreign row sorts first, got %+v", scoped)
	}

	all, err := store.ListScheduledForScope(ctx, repositoryscope.All(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].ID != foreign.ID || all[1].ID != firstA.ID || all[2].ID != secondA.ID {
		t.Fatalf("expected every scheduled freeze in start order, got %+v", all)
	}

	denied, err := store.ListScheduledForScope(ctx, repositoryscope.ReadScope{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Fatalf("expected zero-value scope to hide every scheduled freeze, got %+v", denied)
	}

	unrestricted, err := store.ListScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(unrestricted) != 3 {
		t.Fatalf("expected unrestricted list to keep every scheduled freeze, got %+v", unrestricted)
	}

	viaService, err := NewService(database).ListScheduledForScope(ctx, repositoryscope.IDs(repoA.ID), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(viaService) != 2 || viaService[0].ID != firstA.ID {
		t.Fatalf("expected service pass-through to scope like the store, got %+v", viaService)
	}
}

func TestStoreListScheduledPageForScopeCountsAndPagesInsideScope(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB := createTestRepositoryNamed(t, ctx, database, "thawguard-docs")
	store := NewStore(database)
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoB.ID, Branch: "main", Reason: "docs window", StartsAt: base.Add(30 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoB.ID, Branch: "release", Reason: "docs release window", StartsAt: base.Add(45 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	pendingA, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoA.ID, Branch: "main", Reason: "first window", StartsAt: base.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cancelledA, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoA.ID, Branch: "release", Reason: "abandoned window", StartsAt: base.Add(90 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CancelScheduled(ctx, cancelledA.ID); err != nil {
		t.Fatal(err)
	}
	laterA, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoA.ID, Branch: "hotfix", Reason: "second window", StartsAt: base.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	scopeA := repositoryscope.IDs(repoA.ID)
	rows, total, err := store.ListScheduledPageForScope(ctx, scopeA, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(rows) != 3 || rows[0].ID != pendingA.ID || rows[1].ID != laterA.ID || rows[2].ID != cancelledA.ID {
		t.Fatalf("expected repo A's three windows with agreeing total, got total=%d list=%+v", total, rows)
	}

	pending, total, err := store.ListScheduledPageForScope(ctx, scopeA, domain.BranchFreezeStatusScheduled, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(pending) != 2 || pending[0].ID != pendingA.ID || pending[1].ID != laterA.ID {
		t.Fatalf("expected the status filter to intersect the scope, got total=%d list=%+v", total, pending)
	}

	page, total, err := store.ListScheduledPageForScope(ctx, scopeA, "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(page) != 1 || page[0].ID != laterA.ID {
		t.Fatalf("expected offset and limit to apply after the scope filter, got total=%d list=%+v", total, page)
	}

	allRows, total, err := store.ListScheduledPageForScope(ctx, repositoryscope.All(), "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(allRows) != 5 {
		t.Fatalf("expected the all scope to page every window, got total=%d list=%+v", total, allRows)
	}

	deniedRows, total, err := store.ListScheduledPageForScope(ctx, repositoryscope.ReadScope{}, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(deniedRows) != 0 {
		t.Fatalf("expected zero-value scope to hide every window, got total=%d list=%+v", total, deniedRows)
	}

	unrestricted, total, err := store.ListScheduledPage(ctx, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(unrestricted) != 5 {
		t.Fatalf("expected unrestricted page to keep every window, got total=%d list=%+v", total, unrestricted)
	}

	viaService, total, err := NewService(database).ListScheduledPageForScope(ctx, scopeA, domain.BranchFreezeStatusScheduled, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(viaService) != 2 {
		t.Fatalf("expected service pass-through to scope like the store, got total=%d list=%+v", total, viaService)
	}
}

func TestStoreWorkerReadsRemainUnrestrictedAcrossRepositories(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB := createTestRepositoryNamed(t, ctx, database, "thawguard-docs")
	store := NewStore(database)
	base := time.Date(2026, 7, 20, 7, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	dueA, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoA.ID, Branch: "release", Reason: "window a", StartsAt: base.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	dueB, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repoB.ID, Branch: "release", Reason: "window b", StartsAt: base.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	plannedEndA := base.Add(time.Hour)
	immediateA, err := store.CreateActive(ctx, CreateParams{RepositoryID: repoA.ID, Branch: "main", Reason: "freeze a", PlannedEndsAt: &plannedEndA})
	if err != nil {
		t.Fatal(err)
	}
	plannedEndB := base.Add(70 * time.Minute)
	immediateB, err := store.CreateActive(ctx, CreateParams{RepositoryID: repoB.ID, Branch: "main", Reason: "freeze b", PlannedEndsAt: &plannedEndB})
	if err != nil {
		t.Fatal(err)
	}

	store.now = func() time.Time { return base.Add(2 * time.Hour) }
	dueScheduled, err := store.ListDueScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dueScheduled) != 2 || dueScheduled[0].ID != dueA.ID || dueScheduled[1].ID != dueB.ID {
		t.Fatalf("expected due scheduled freezes from both repositories, got %+v", dueScheduled)
	}

	dueUnfreezes, err := store.ListDuePlannedUnfreezes(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dueUnfreezes) != 2 || dueUnfreezes[0].ID != immediateA.ID || dueUnfreezes[1].ID != immediateB.ID {
		t.Fatalf("expected due planned unfreezes from both repositories, got %+v", dueUnfreezes)
	}
}

func TestStoreCreatesListsActivatesAndEndsScheduledFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	startsAt := now.Add(time.Hour)
	plannedEndsAt := startsAt.Add(2 * time.Hour)

	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: " main ", Reason: " weekend freeze ", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt})
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled.Scheduled || scheduled.Status != domain.BranchFreezeStatusScheduled || scheduled.Active || scheduled.StartsAt == nil || scheduled.PlannedEndsAt == nil {
		t.Fatalf("expected scheduled freeze metadata, got %+v", scheduled)
	}
	listed, err := store.ListScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != scheduled.ID {
		t.Fatalf("expected scheduled freeze in list, got %+v", listed)
	}
	if due, err := store.ListDueScheduled(ctx, 10); err != nil || len(due) != 0 {
		t.Fatalf("expected no due freezes before start, due=%+v err=%v", due, err)
	}

	store.now = func() time.Time { return startsAt.Add(123 * time.Millisecond) }
	due, err := store.ListDueScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != scheduled.ID {
		t.Fatalf("expected due scheduled freeze, got %+v", due)
	}
	activated, err := store.ActivateScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Status != domain.BranchFreezeStatusActive || !activated.Active || !activated.Scheduled || !activated.NeedsRecompute {
		t.Fatalf("expected activated scheduled freeze, got %+v", activated)
	}
	recompute, err := store.ListNeedsRecompute(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recompute) != 1 || recompute[0].ID != scheduled.ID {
		t.Fatalf("expected activated schedule to need recompute, got %+v", recompute)
	}
	marked, err := store.MarkRecomputed(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if marked.NeedsRecompute {
		t.Fatalf("expected recompute marker to clear, got %+v", marked)
	}

	store.now = func() time.Time { return plannedEndsAt.Add(time.Minute) }
	dueEnds, err := store.ListDuePlannedUnfreezes(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dueEnds) != 1 || dueEnds[0].ID != scheduled.ID {
		t.Fatalf("expected due planned unfreeze, got %+v", dueEnds)
	}
	ended, err := store.ExecutePlannedUnfreeze(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded || ended.Active || ended.EndsAt == nil || ended.PlannedEndsAt == nil || !ended.NeedsRecompute {
		t.Fatalf("expected ended scheduled freeze with planned end preserved, got %+v", ended)
	}
}

func TestStoreCancelsScheduledFreezeBeforeActivation(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "maintenance", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := store.CancelScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled || cancelled.EndsAt == nil || !cancelled.Scheduled {
		t.Fatalf("expected cancelled scheduled freeze, got %+v", cancelled)
	}
}

func TestStoreEditsPendingScheduledFreezeWithoutChangingTarget(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	originalStart := now.Add(2 * time.Hour)
	originalEnd := originalStart.Add(time.Hour)
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "original", StartsAt: originalStart, PlannedEndsAt: &originalEnd})
	if err != nil {
		t.Fatal(err)
	}

	replacementStart := now.Add(3 * time.Hour)
	replacementEnd := replacementStart.Add(2 * time.Hour)
	updated, err := store.EditScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: " updated reason ", StartsAt: replacementStart, PlannedEndsAt: &replacementEnd})
	if err != nil {
		t.Fatal(err)
	}
	if updated.RepositoryID != repo.ID || updated.Branch != "main" || updated.Reason != "updated reason" || updated.Status != domain.BranchFreezeStatusScheduled || updated.NeedsRecompute {
		t.Fatalf("expected target and state to remain unchanged, got %+v", updated)
	}
	if updated.StartsAt == nil || !updated.StartsAt.Equal(replacementStart) || updated.PlannedEndsAt == nil || !updated.PlannedEndsAt.Equal(replacementEnd) {
		t.Fatalf("expected replacement schedule times, got %+v", updated)
	}

	cleared, err := store.EditScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: "no expiry", StartsAt: replacementStart.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.PlannedEndsAt != nil {
		t.Fatalf("expected empty planned unfreeze to clear value, got %+v", cleared)
	}
}

func TestStoreRejectsInvalidOrNonPendingScheduledFreezeEdits(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	for _, start := range []time.Time{now, now.Add(-time.Nanosecond)} {
		if _, err := store.EditScheduled(ctx, EditScheduleParams{ID: 1, Reason: "release", StartsAt: start}); !IsValidationError(err) {
			t.Fatalf("expected start %s to be rejected, got %v", start, err)
		}
	}
	start := now.Add(time.Hour)
	for _, planned := range []time.Time{start, start.Add(-time.Nanosecond)} {
		if _, err := store.EditScheduled(ctx, EditScheduleParams{ID: 1, Reason: "release", StartsAt: start, PlannedEndsAt: &planned}); !IsValidationError(err) {
			t.Fatalf("expected planned unfreeze %s to be rejected, got %v", planned, err)
		}
	}

	for _, status := range []domain.BranchFreezeStatus{domain.BranchFreezeStatusActive, domain.BranchFreezeStatusEnded, domain.BranchFreezeStatusCancelled} {
		t.Run(string(status), func(t *testing.T) {
			scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: string(status), Reason: "original", StartsAt: now.Add(2 * time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.ExecContext(ctx, `UPDATE branch_freezes SET status = ? WHERE id = ?`, status, scheduled.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.EditScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: "changed", StartsAt: now.Add(3 * time.Hour)}); !IsValidationError(err) {
				t.Fatalf("expected %s schedule edit to be rejected, got %v", status, err)
			}
			unchanged, err := store.Get(ctx, scheduled.ID)
			if err != nil {
				t.Fatal(err)
			}
			if unchanged.Reason != "original" {
				t.Fatalf("expected rejected edit to preserve reason, got %+v", unchanged)
			}
		})
	}
}

func TestStoreRejectsScheduledEditWithStaleAuditPreimage(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "original", StartsAt: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	staleUpdatedAt := scheduled.UpdatedAt
	if _, err := store.editScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: "first edit", StartsAt: now.Add(3 * time.Hour)}, &staleUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.editScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: "stale edit", StartsAt: now.Add(4 * time.Hour)}, &staleUpdatedAt); !IsValidationError(err) {
		t.Fatalf("expected stale edit preimage to lose safely, got %v", err)
	}
	current, err := store.Get(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Reason != "first edit" {
		t.Fatalf("expected stale edit not to overwrite current schedule, got %+v", current)
	}
}

func TestStoreStartsPendingScheduleNowAndPreservesPlannedUnfreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 123, time.UTC)
	store.now = func() time.Time { return now }
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "existing freeze"}); err != nil {
		t.Fatal(err)
	}
	planned := now.Add(4 * time.Hour)
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: now.Add(2 * time.Hour), PlannedEndsAt: &planned})
	if err != nil {
		t.Fatal(err)
	}

	started, err := store.StartScheduledNow(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != domain.BranchFreezeStatusActive || !started.Active || !started.Scheduled || !started.NeedsRecompute || started.StartsAt == nil || !started.StartsAt.Equal(now) {
		t.Fatalf("expected active schedule at current time, got %+v", started)
	}
	if started.RepositoryID != repo.ID || started.Branch != "main" || started.Reason != "release" || started.PlannedEndsAt == nil || !started.PlannedEndsAt.Equal(planned) {
		t.Fatalf("expected immutable fields and planned unfreeze preserved, got %+v", started)
	}
	if _, err := store.StartScheduledNow(ctx, scheduled.ID); !IsValidationError(err) {
		t.Fatalf("expected duplicate Start Now to be rejected, got %v", err)
	}
	active, err := store.ListActive(ctx)
	if err != nil || len(active) != 2 {
		t.Fatalf("expected Start Now alongside existing active freeze, active=%+v err=%v", active, err)
	}
	store.now = func() time.Time { return planned.Add(time.Minute) }
	ended, err := store.ExecutePlannedUnfreeze(ctx, scheduled.ID)
	if err != nil || ended.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected preserved planned unfreeze to execute, ended=%+v err=%v", ended, err)
	}
}

func TestStoreRejectsStartNowForExpiredPlannedUnfreezeAndNonPendingSchedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	expired, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: now.Add(2 * time.Hour), PlannedEndsAt: timePointer(now.Add(3 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE branch_freezes SET planned_ends_at = ? WHERE id = ?`, now.Add(-time.Minute).Format(sqliteTimestampFormat), expired.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartScheduledNow(ctx, expired.ID); !IsValidationError(err) || !strings.Contains(err.Error(), "edit the schedule") {
		t.Fatalf("expected expired planned unfreeze remediation, got %v", err)
	}

	if _, err := database.ExecContext(ctx, `UPDATE branch_freezes SET status = ? WHERE id = ?`, domain.BranchFreezeStatusCancelled, expired.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartScheduledNow(ctx, expired.ID); !IsValidationError(err) {
		t.Fatalf("expected non-pending schedule to be rejected, got %v", err)
	}
}

func TestStoreMarksActiveScheduledFreezeForRecomputeWhenManuallyClosed(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "manual lift later", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(time.Hour) }
	activated, err := store.ActivateScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRecomputed(ctx, activated.ID); err != nil {
		t.Fatal(err)
	}

	ended, err := store.End(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ended.Scheduled || !ended.NeedsRecompute || ended.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected manually ended scheduled freeze to need recompute, got %+v", ended)
	}
}

func TestStoreRejectsInvalidScheduledFreezeParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	startsAt := now.Add(time.Hour)
	plannedEndsAt := now.Add(30 * time.Minute)

	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: now}); !IsValidationError(err) {
		t.Fatalf("expected past start validation error, got %v", err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt}); !IsValidationError(err) {
		t.Fatalf("expected invalid planned end validation error, got %v", err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: 999, Branch: "main", Reason: "release", StartsAt: startsAt}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
}

func TestStoreAcceptsScheduledFreezeWithoutReason(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("expected a scheduled freeze without a reason to be accepted, got %v", err)
	}
	if scheduled.Reason != "" {
		t.Fatalf("expected an empty reason, got %q", scheduled.Reason)
	}

	edited, err := store.EditScheduled(ctx, EditScheduleParams{ID: scheduled.ID, StartsAt: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("expected an edit clearing the reason to be accepted, got %v", err)
	}
	if edited.Reason != "" {
		t.Fatalf("expected the cleared reason to persist, got %q", edited.Reason)
	}
}

func TestStoreEndsActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"})
	if err != nil {
		t.Fatal(err)
	}

	ended, err := store.End(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded || ended.Active || ended.EndsAt == nil {
		t.Fatalf("expected ended inactive freeze with end time, got %+v", ended)
	}
	freezes, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(freezes) != 0 {
		t.Fatalf("expected no active freezes after ending, got %+v", freezes)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "next release"}); err != nil {
		t.Fatalf("expected branch to be free after ending freeze: %v", err)
	}
}

func TestStoreCancelsActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "mistake"})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := store.Cancel(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled || cancelled.Active || cancelled.EndsAt == nil {
		t.Fatalf("expected cancelled inactive freeze with end time, got %+v", cancelled)
	}
}

func TestStoreRejectsClosingInvalidOrInactiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(ctx, 0); !IsValidationError(err) {
		t.Fatalf("expected missing freeze validation error, got %v", err)
	}
	if _, err := store.End(ctx, 999); !IsValidationError(err) {
		t.Fatalf("expected missing freeze validation error, got %v", err)
	}
	if _, err := store.End(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cancel(ctx, created.ID); !IsValidationError(err) {
		t.Fatalf("expected inactive freeze validation error, got %v", err)
	}
}

func TestServiceCreatesFreezeAndAuditEventAtomically(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	plannedEndsAt := time.Now().UTC().Add(time.Hour)

	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window", PlannedEndsAt: &plannedEndsAt}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	event := events[0]
	if event.Action != audit.ActionBranchFreezeCreated || event.SubjectType != audit.SubjectTypeBranchFreeze || event.SubjectID != "1" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" || details["branch"] != created.Branch || details["reason"] != created.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
	}
	if details["planned_ends_at"] != created.PlannedEndsAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("expected planned end in creation audit details, got %s", event.DetailsJSON)
	}
	job, err := jobs.NewStore(database).GetReconciliation(ctx, repo.ID)
	if err != nil || job.Generation != 1 {
		t.Fatalf("expected freeze and durable intent to commit together, job=%+v err=%v", job, err)
	}
}

func TestServiceEndsFreezeAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	ended, err := service.End(ctx, created.ID, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected ended freeze, got %+v", ended)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionBranchFreezeEnded, ended)
}

func TestServiceCancelsFreezeAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "mistake"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := service.Cancel(ctx, created.ID, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled {
		t.Fatalf("expected cancelled freeze, got %+v", cancelled)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionBranchFreezeCancelled, cancelled)
}

func TestServiceScheduledFreezeLifecycleRecordsAuditEvents(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	startsAt := time.Now().UTC().Add(time.Hour)
	plannedEndsAt := startsAt.Add(time.Hour)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekend", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt}, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionFreezeScheduleCreated, scheduled)

	cancelled, err := service.CancelScheduled(ctx, scheduled.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionFreezeScheduleCancelled, cancelled)
}

func TestServiceEditsScheduledFreezeWithAuditAndNoReconciliation(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	start := time.Now().UTC().Add(2 * time.Hour)
	planned := start.Add(time.Hour)
	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "before", StartsAt: start, PlannedEndsAt: &planned}, actor)
	if err != nil {
		t.Fatal(err)
	}
	afterStart := start.Add(time.Hour)
	afterPlanned := afterStart.Add(2 * time.Hour)
	updated, err := service.EditScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: "after", StartsAt: afterStart, PlannedEndsAt: &afterPlanned}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Reason != "after" {
		t.Fatalf("expected edited schedule, got %+v", updated)
	}
	events, err := audit.NewStore(database).List(ctx, 1)
	if err != nil || len(events) != 1 || events[0].Action != audit.ActionFreezeScheduleUpdated {
		t.Fatalf("expected update audit event, events=%+v err=%v", events, err)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"repository_id":          strconv.FormatInt(repo.ID, 10),
		"branch":                 "main",
		"reason_before":          "before",
		"reason_after":           "after",
		"starts_at_before":       start.Format(time.RFC3339Nano),
		"starts_at_after":        afterStart.Format(time.RFC3339Nano),
		"planned_ends_at_before": planned.Format(time.RFC3339Nano),
		"planned_ends_at_after":  afterPlanned.Format(time.RFC3339Nano),
	} {
		if details[key] != want {
			t.Fatalf("audit detail %s: want %q, got %q", key, want, details[key])
		}
	}
	if _, err := jobs.NewStore(database).GetReconciliation(ctx, repo.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected edit not to enqueue reconciliation, got %v", err)
	}
}

func TestServiceRollsBackScheduledEditWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	start := time.Now().UTC().Add(2 * time.Hour)
	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "before", StartsAt: start}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	missingUserID := int64(999)
	if _, err := service.EditScheduled(ctx, EditScheduleParams{ID: scheduled.ID, Reason: "after", StartsAt: start.Add(time.Hour)}, domain.Actor{UserID: &missingUserID, Kind: domain.ActorKindUser, Role: "freezer"}); err == nil {
		t.Fatal("expected audit foreign-key error")
	}
	unchanged, err := service.Get(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Reason != "before" || unchanged.StartsAt == nil || !unchanged.StartsAt.Equal(start) {
		t.Fatalf("expected failed audit to roll back edit, got %+v", unchanged)
	}
}

func TestServiceStartsScheduledFreezeNowAtomicallyAndOnlyOnce(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	start := time.Now().UTC().Add(2 * time.Hour)
	planned := start.Add(time.Hour)
	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: start, PlannedEndsAt: &planned}, actor)
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.StartScheduledNow(ctx, scheduled.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != domain.BranchFreezeStatusActive || !started.NeedsRecompute || started.PlannedEndsAt == nil || !started.PlannedEndsAt.Equal(planned) {
		t.Fatalf("unexpected Start Now result: %+v", started)
	}
	if _, err := service.StartScheduledNow(ctx, scheduled.ID, actor); !IsValidationError(err) {
		t.Fatalf("expected duplicate Start Now rejection, got %v", err)
	}
	var auditCount, jobCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ? AND subject_id = ?`, audit.ActionFreezeScheduleStartedNow, strconv.FormatInt(scheduled.ID, 10)).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE type = ? AND repository_id = ?`, jobs.ReconcileRepositoryEnforcement, repo.ID).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || jobCount != 1 {
		t.Fatalf("expected one Start Now audit and durable intent, audit=%d jobs=%d", auditCount, jobCount)
	}
}

func TestServiceConcurrentStartNowCommitsOneTransitionAndAudit(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: time.Now().UTC().Add(2 * time.Hour)}, actor)
	if err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			ready.Done()
			<-start
			_, err := service.StartScheduledNow(ctx, scheduled.ID, actor)
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	first, second := <-errs, <-errs
	successes := 0
	validationFailures := 0
	for _, err := range []error{first, second} {
		switch {
		case err == nil:
			successes++
		case IsValidationError(err):
			validationFailures++
		default:
			t.Fatalf("expected losing request to receive validation error, got %v", err)
		}
	}
	if successes != 1 || validationFailures != 1 {
		t.Fatalf("expected one success and one safe losing request, success=%d validation=%d errors=%v, %v", successes, validationFailures, first, second)
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ? AND subject_id = ?`, audit.ActionFreezeScheduleStartedNow, strconv.FormatInt(scheduled.ID, 10)).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected one Start Now audit event, got %d", auditCount)
	}
}

func TestServiceRollsBackStartNowWhenAuditOrJobFails(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, context.Context, *sql.DB) domain.Actor
	}{
		{name: "audit", prepare: func(t *testing.T, ctx context.Context, database *sql.DB) domain.Actor {
			missingUserID := int64(999)
			return domain.Actor{UserID: &missingUserID, Kind: domain.ActorKindUser, Role: "freezer"}
		}},
		{name: "job", prepare: func(t *testing.T, ctx context.Context, database *sql.DB) domain.Actor {
			if _, err := database.ExecContext(ctx, `CREATE TRIGGER fail_reconciliation_enqueue BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT, 'job enqueue failed'); END`); err != nil {
				t.Fatal(err)
			}
			return domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			database := newTestDB(t, ctx)
			repo := createTestRepository(t, ctx, database)
			service := NewService(database)
			start := time.Now().UTC().Add(2 * time.Hour)
			scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: start}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
			if err != nil {
				t.Fatal(err)
			}
			actor := test.prepare(t, ctx, database)
			if _, err := service.StartScheduledNow(ctx, scheduled.ID, actor); err == nil {
				t.Fatal("expected Start Now transaction failure")
			}
			unchanged, err := service.Get(ctx, scheduled.ID)
			if err != nil {
				t.Fatal(err)
			}
			if unchanged.Status != domain.BranchFreezeStatusScheduled || unchanged.NeedsRecompute || unchanged.StartsAt == nil || !unchanged.StartsAt.Equal(start) {
				t.Fatalf("expected failed Start Now to roll back transition, got %+v", unchanged)
			}
			var auditCount int
			if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ?`, audit.ActionFreezeScheduleStartedNow).Scan(&auditCount); err != nil {
				t.Fatal(err)
			}
			if auditCount != 0 {
				t.Fatalf("expected no committed Start Now audit, got %d", auditCount)
			}
		})
	}
}

func TestServicePlannedUnfreezeUsesTruthfulAuditActionForImmediateAndScheduledFreezes(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}
	future := time.Now().UTC().Add(time.Hour)

	immediate, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "deployment", PlannedEndsAt: &future}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	makeFreezeDue(t, ctx, database, immediate.ID)
	endedImmediate, err := service.ExecutePlannedUnfreeze(ctx, immediate.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestPlannedUnfreezeAudit(t, ctx, database, audit.ActionBranchFreezePlannedUnfreeze, endedImmediate)
	if _, err := service.ExecutePlannedUnfreeze(ctx, immediate.ID, actor); !IsValidationError(err) {
		t.Fatalf("expected duplicate planned unfreeze to be rejected, got %v", err)
	}
	var immediateAuditCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ? AND subject_id = ?`, audit.ActionBranchFreezePlannedUnfreeze, strconv.FormatInt(immediate.ID, 10)).Scan(&immediateAuditCount); err != nil {
		t.Fatal(err)
	}
	if immediateAuditCount != 1 {
		t.Fatalf("expected one immediate planned-unfreeze audit event, got %d", immediateAuditCount)
	}

	startsAt := time.Now().UTC().Add(time.Hour)
	plannedEndsAt := startsAt.Add(time.Hour)
	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "release", Reason: "window", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE branch_freezes SET status = 'active' WHERE id = ?`, scheduled.ID); err != nil {
		t.Fatal(err)
	}
	makeFreezeDue(t, ctx, database, scheduled.ID)
	endedScheduled, err := service.ExecutePlannedUnfreeze(ctx, scheduled.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestPlannedUnfreezeAudit(t, ctx, database, audit.ActionFreezeSchedulePlannedUnfreeze, endedScheduled)
}

func TestServiceRollsBackPlannedUnfreezeWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	future := time.Now().UTC().Add(time.Hour)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "deployment", PlannedEndsAt: &future}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	makeFreezeDue(t, ctx, database, created.ID)
	missingUserID := int64(999)
	if _, err := service.ExecutePlannedUnfreeze(ctx, created.ID, domain.Actor{UserID: &missingUserID, Kind: domain.ActorKindSystem, Role: "scheduler"}); err == nil {
		t.Fatal("expected audit foreign-key error")
	}
	unchanged, err := service.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != domain.BranchFreezeStatusActive || unchanged.EndsAt != nil || unchanged.NeedsRecompute {
		t.Fatalf("expected failed audit to roll back planned unfreeze, got %+v", unchanged)
	}
}

func makeFreezeDue(t *testing.T, ctx context.Context, database *sql.DB, id int64) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `UPDATE branch_freezes SET planned_ends_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format(sqliteTimestampFormat), id); err != nil {
		t.Fatal(err)
	}
}

func assertLatestPlannedUnfreezeAudit(t *testing.T, ctx context.Context, database *sql.DB, action string, ended domain.BranchFreeze) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != action {
		t.Fatalf("expected %s audit event, got %+v", action, events)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"repository_id":   strconv.FormatInt(ended.RepositoryID, 10),
		"branch":          ended.Branch,
		"planned_ends_at": ended.PlannedEndsAt.UTC().Format(time.RFC3339Nano),
		"ends_at":         ended.EndsAt.UTC().Format(time.RFC3339Nano),
		"actor_kind":      domain.ActorKindSystem,
		"actor_role":      "scheduler",
		"status":          string(domain.BranchFreezeStatusEnded),
		"reason":          ended.Reason,
	} {
		if details[key] != want {
			t.Fatalf("audit detail %s: want %q, got %q in %s", key, want, details[key], events[0].DetailsJSON)
		}
	}
}

func TestServiceRollsBackEndWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	missingUserID := int64(999)

	_, err = service.End(ctx, created.ID, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	freeze, getErr := NewStore(database).Get(ctx, created.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if freeze.Status != domain.BranchFreezeStatusActive || !freeze.Active || freeze.EndsAt != nil {
		t.Fatalf("expected rollback to leave freeze active, got %+v", freeze)
	}
}

func TestServiceRollsBackFreezeWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	missingUserID := int64(999)

	_, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	freezes, listErr := service.ListActive(ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(freezes) != 0 {
		t.Fatalf("expected rollback to leave no freezes, got %d", len(freezes))
	}
	if _, err := jobs.NewStore(database).GetReconciliation(ctx, repo.ID); err == nil {
		t.Fatal("expected rollback to leave no reconciliation job")
	}
}

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	return createTestRepositoryNamed(t, ctx, database, "thawguard")
}

func createTestRepositoryNamed(t *testing.T, ctx context.Context, database *sql.DB, name string) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: name, DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err = repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func assertLatestFreezeAudit(t *testing.T, ctx context.Context, database *sql.DB, action string, freeze domain.BranchFreeze) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	event := events[0]
	if event.Action != action || event.SubjectType != audit.SubjectTypeBranchFreeze || event.SubjectID != strconv.FormatInt(freeze.ID, 10) {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" || details["repository_id"] != strconv.FormatInt(freeze.RepositoryID, 10) || details["branch"] != freeze.Branch || details["status"] != string(freeze.Status) || details["reason"] != freeze.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
	}
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
