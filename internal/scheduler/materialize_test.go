package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeScheduleSource struct {
	coverages []schedule.Coverage
	err       error
}

func (s *fakeScheduleSource) ListActiveCoverages(ctx context.Context) ([]schedule.Coverage, error) {
	return s.coverages, s.err
}

type fakeFreezeStore struct {
	activeByBranch map[branchKey]domain.BranchFreeze
	materialized   []domain.BranchFreeze
	created        []freeze.CreateParams
	createdActors  []domain.Actor
	ended          []int64
	updated        []freeze.UpdateAttributionParams
	createErr      error
	endErr         error
	updateErr      error
}

func (s *fakeFreezeStore) GetActiveForBranch(ctx context.Context, repositoryID int64, branch string) (domain.BranchFreeze, bool, error) {
	live, ok := s.activeByBranch[branchKey{RepositoryID: repositoryID, Branch: branch}]
	return live, ok, nil
}

func (s *fakeFreezeStore) ListActiveMaterialized(ctx context.Context) ([]domain.BranchFreeze, error) {
	return s.materialized, nil
}

func (s *fakeFreezeStore) CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.createErr != nil {
		return domain.BranchFreeze{}, s.createErr
	}
	s.created = append(s.created, params)
	s.createdActors = append(s.createdActors, actor)
	return domain.BranchFreeze{ID: int64(100 + len(s.created)), RepositoryID: params.RepositoryID, Branch: params.Branch, ScheduleID: params.ScheduleID}, nil
}

func (s *fakeFreezeStore) EndMaterialized(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.endErr != nil {
		return domain.BranchFreeze{}, s.endErr
	}
	s.ended = append(s.ended, id)
	return domain.BranchFreeze{ID: id}, nil
}

func (s *fakeFreezeStore) UpdateMaterializedAttribution(ctx context.Context, params freeze.UpdateAttributionParams) (domain.BranchFreeze, error) {
	if s.updateErr != nil {
		return domain.BranchFreeze{}, s.updateErr
	}
	s.updated = append(s.updated, params)
	return domain.BranchFreeze{ID: params.FreezeID}, nil
}

// weeklyCoverage builds one active schedule covering Mon 09:00 → Fri 17:00 UTC
// every week, which contains the fixed test clock (Mon 2026-07-20 12:00 UTC).
func weeklyCoverage(scheduleID int64, branch, reason string) schedule.Coverage {
	return schedule.Coverage{
		Schedule: domain.Schedule{ID: scheduleID, RepositoryID: 1, Branch: branch, Name: "Work week lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC", Reason: reason, Active: true},
		Rules: []domain.ScheduleWeeklyRule{{
			ID: scheduleID * 10, ScheduleID: scheduleID,
			StartWeekday: time.Monday, StartTime: "09:00",
			EndWeekday: time.Friday, EndTime: "17:00",
		}},
	}
}

func TestMaterializerCreatesLinkedFreezeForCoveredBranch(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeStore{}
	materializer := NewMaterializer(
		&fakeScheduleSource{coverages: []schedule.Coverage{weeklyCoverage(7, "main", "Work week")}},
		freezes, fixedClock{now: decideNow}, nil)

	if err := materializer.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(freezes.created) != 1 {
		t.Fatalf("expected one created freeze, got %+v", freezes.created)
	}
	created := freezes.created[0]
	if created.RepositoryID != 1 || created.Branch != "main" || created.Reason != "Work week" {
		t.Fatalf("unexpected create params: %+v", created)
	}
	if created.ScheduleID == nil || *created.ScheduleID != 7 {
		t.Fatalf("expected freeze linked to schedule 7, got %+v", created.ScheduleID)
	}
	if created.ScheduleName != "Work week lock" {
		t.Fatalf("expected snapshotted schedule name, got %q", created.ScheduleName)
	}
	wantEnd := time.Date(2026, 7, 24, 17, 0, 0, 0, time.UTC)
	if created.PlannedEndsAt == nil || !created.PlannedEndsAt.Equal(wantEnd) {
		t.Fatalf("expected planned end %v, got %v", wantEnd, created.PlannedEndsAt)
	}
	actor := freezes.createdActors[0]
	if actor.Kind != domain.ActorKindSystem || actor.Role != "scheduler" {
		t.Fatalf("expected truthful scheduler attribution, got %+v", actor)
	}
}

func TestMaterializerIsIdempotentWhileBranchStaysFrozen(t *testing.T) {
	ctx := context.Background()
	live := domain.BranchFreeze{
		ID: 40, RepositoryID: 1, Branch: "main",
		ScheduleID: int64Ptr(7), ScheduleName: "Work week lock",
		PlannedEndsAt: timePtr(time.Date(2026, 7, 24, 17, 0, 0, 0, time.UTC)),
	}
	freezes := &fakeFreezeStore{
		activeByBranch: map[branchKey]domain.BranchFreeze{{RepositoryID: 1, Branch: "main"}: live},
		materialized:   []domain.BranchFreeze{live},
	}
	materializer := NewMaterializer(
		&fakeScheduleSource{coverages: []schedule.Coverage{weeklyCoverage(7, "main", "")}},
		freezes, fixedClock{now: decideNow}, nil)

	for run := 0; run < 2; run++ {
		if err := materializer.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(freezes.created) != 0 || len(freezes.ended) != 0 || len(freezes.updated) != 0 {
		t.Fatalf("expected no churn on a covered frozen branch, created=%+v ended=%+v updated=%+v", freezes.created, freezes.ended, freezes.updated)
	}
}

// datedCoverage builds one active dated schedule with a window covering the
// fixed test clock's day (Mon 2026-07-20, UTC wall clocks).
func datedCoverage(scheduleID int64, branch, name, reason string, createdAt time.Time) schedule.Coverage {
	return schedule.Coverage{
		Schedule: domain.Schedule{ID: scheduleID, RepositoryID: 1, Branch: branch, Name: name, Kind: domain.ScheduleKindDated, Timezone: "UTC", Reason: reason, Active: true, CreatedAt: createdAt},
		Windows: []domain.ScheduleDatedWindow{{
			ID: scheduleID * 10, ScheduleID: scheduleID, Name: "Holiday",
			StartsAt: "2026-07-20T00:00", EndsAt: "2026-07-21T00:00",
		}},
	}
}

func TestMaterializerRelabelsFreezeWhenDatedWindowTakesOver(t *testing.T) {
	ctx := context.Background()
	live := domain.BranchFreeze{
		ID: 40, RepositoryID: 1, Branch: "main",
		ScheduleID: int64Ptr(7), ScheduleName: "Work week lock", Reason: "Work week",
		PlannedEndsAt: timePtr(time.Date(2026, 7, 24, 17, 0, 0, 0, time.UTC)),
	}
	freezes := &fakeFreezeStore{
		activeByBranch: map[branchKey]domain.BranchFreeze{{RepositoryID: 1, Branch: "main"}: live},
		materialized:   []domain.BranchFreeze{live},
	}
	materializer := NewMaterializer(
		&fakeScheduleSource{coverages: []schedule.Coverage{
			weeklyCoverage(7, "main", "Work week"),
			datedCoverage(9, "main", "Christmas maintenance", "Holiday change stop", decideNow.Add(-24*time.Hour)),
		}},
		freezes, fixedClock{now: decideNow}, nil)

	if err := materializer.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(freezes.created) != 0 || len(freezes.ended) != 0 {
		t.Fatalf("relabel must not churn rows, created=%+v ended=%+v", freezes.created, freezes.ended)
	}
	if len(freezes.updated) != 1 {
		t.Fatalf("expected one attribution update, got %+v", freezes.updated)
	}
	updated := freezes.updated[0]
	if updated.FreezeID != 40 || updated.ScheduleID != 9 || updated.ScheduleName != "Christmas maintenance" || updated.Reason != "Holiday change stop" {
		t.Fatalf("unexpected update params: %+v", updated)
	}
	// Coverage is untouched: the union still runs to the weekly rule's end.
	wantEnd := time.Date(2026, 7, 24, 17, 0, 0, 0, time.UTC)
	if updated.PlannedEndsAt == nil || !updated.PlannedEndsAt.Equal(wantEnd) {
		t.Fatalf("expected planned end %v, got %v", wantEnd, updated.PlannedEndsAt)
	}
}

func TestMaterializerSkipsAttributionUpdateValidationFailures(t *testing.T) {
	ctx := context.Background()
	live := domain.BranchFreeze{ID: 40, RepositoryID: 1, Branch: "main", ScheduleID: int64Ptr(7)}
	freezes := &fakeFreezeStore{
		activeByBranch: map[branchKey]domain.BranchFreeze{{RepositoryID: 1, Branch: "main"}: live},
		materialized:   []domain.BranchFreeze{live},
		updateErr:      freeze.ValidationError{Message: "freeze is no longer an active materialized freeze"},
	}
	materializer := NewMaterializer(
		&fakeScheduleSource{coverages: []schedule.Coverage{weeklyCoverage(7, "main", "")}},
		freezes, fixedClock{now: decideNow}, nil)

	if err := materializer.RunOnce(ctx); err != nil {
		t.Fatalf("attribution update races must be skipped, got %v", err)
	}
}

func TestMaterializerEndsOrphanedMaterializedFreeze(t *testing.T) {
	ctx := context.Background()
	orphan := domain.BranchFreeze{ID: 40, RepositoryID: 1, Branch: "main", ScheduleID: int64Ptr(7)}
	freezes := &fakeFreezeStore{
		activeByBranch: map[branchKey]domain.BranchFreeze{{RepositoryID: 1, Branch: "main"}: orphan},
		materialized:   []domain.BranchFreeze{orphan},
	}
	// The schedule is gone (paused or deleted): no coverages at all.
	materializer := NewMaterializer(&fakeScheduleSource{}, freezes, fixedClock{now: decideNow}, nil)

	if err := materializer.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(freezes.ended) != 1 || freezes.ended[0] != 40 {
		t.Fatalf("expected orphan 40 ended, got %+v", freezes.ended)
	}
	if len(freezes.created) != 0 {
		t.Fatalf("expected no creates, got %+v", freezes.created)
	}
}

func TestMaterializerSkipsValidationFailuresWithoutError(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeStore{createErr: freeze.ValidationError{Message: "enforcement is not active"}}
	materializer := NewMaterializer(
		&fakeScheduleSource{coverages: []schedule.Coverage{weeklyCoverage(7, "main", "")}},
		freezes, fixedClock{now: decideNow}, nil)

	if err := materializer.RunOnce(ctx); err != nil {
		t.Fatalf("validation failures must be skipped, got %v", err)
	}
}

func TestMaterializerReportsListFailure(t *testing.T) {
	ctx := context.Background()
	materializer := NewMaterializer(&fakeScheduleSource{err: errors.New("db locked")}, &fakeFreezeStore{}, fixedClock{now: decideNow}, nil)
	if err := materializer.RunOnce(ctx); err == nil {
		t.Fatal("expected list failure to surface")
	}
}
