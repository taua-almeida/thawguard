package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
)

// serviceTestNow pins the service clock to a Monday noon so the Monday
// business-hours rule below always contains "now" and every expected
// suppression instant is a fixed constant.
var serviceTestNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

var serviceTestActor = domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

func newTestService(database *sql.DB) *Service {
	service := NewService(database)
	service.now = func() time.Time { return serviceTestNow }
	return service
}

// createScheduleWithMondayRule creates a paused schedule whose single weekly
// rule (Mon 09:00–17:00 UTC) covers serviceTestNow.
func createScheduleWithMondayRule(t *testing.T, ctx context.Context, service *Service, repositoryID int64) domain.Schedule {
	t.Helper()
	created, err := service.Create(ctx, CreateParams{
		RepositoryID: repositoryID,
		Branch:       "main",
		Name:         "Nightly release lock",
		Kind:         domain.ScheduleKindWeekly,
		Timezone:     "UTC",
		Reason:       "Release window",
	}, serviceTestActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddRules(ctx, AddRulesParams{
		ScheduleID: created.ID,
		Weekdays:   []time.Weekday{time.Monday},
		StartTime:  "09:00",
		EndTime:    "17:00",
		EndDayMode: EndDaySame,
	}, serviceTestActor); err != nil {
		t.Fatal(err)
	}
	return created
}

func createLinkedFreeze(t *testing.T, ctx context.Context, database *sql.DB, repositoryID, scheduleID int64) domain.BranchFreeze {
	t.Helper()
	created, err := freeze.NewService(database).CreateActive(ctx, freeze.CreateParams{
		RepositoryID: repositoryID,
		Branch:       "main",
		Reason:       "Release window",
		ScheduleID:   &scheduleID,
	}, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func TestServiceActivateAndPauseRecordAuditAndRejectNoOps(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := newTestService(database)
	created := createScheduleWithMondayRule(t, ctx, service, repo.ID)

	activated, err := service.Activate(ctx, created.ID, serviceTestActor)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Active {
		t.Fatalf("expected active schedule, got %+v", activated)
	}
	assertLatestScheduleAudit(t, ctx, database, audit.ActionScheduleActivated, activated)

	if _, err := service.Activate(ctx, created.ID, serviceTestActor); !IsValidationError(err) || err.Error() != "schedule is already active" {
		t.Fatalf("expected already-active validation error, got %v", err)
	}

	paused, err := service.Pause(ctx, created.ID, serviceTestActor)
	if err != nil {
		t.Fatal(err)
	}
	if paused.Active {
		t.Fatalf("expected paused schedule, got %+v", paused)
	}
	assertLatestScheduleAudit(t, ctx, database, audit.ActionSchedulePaused, paused)

	if _, err := service.Pause(ctx, created.ID, serviceTestActor); !IsValidationError(err) || err.Error() != "schedule is already paused" {
		t.Fatalf("expected already-paused validation error, got %v", err)
	}
}

func TestServiceActivationTransitionsClearSuppression(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := newTestService(database)
	created := createScheduleWithMondayRule(t, ctx, service, repo.ID)

	if _, err := service.Activate(ctx, created.ID, serviceTestActor); err != nil {
		t.Fatal(err)
	}
	suppressed, err := NewStore(database).Suppress(ctx, created.ID, serviceTestNow.Add(5*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if suppressed.SuppressedUntil == nil {
		t.Fatal("expected suppression to persist")
	}

	paused, err := service.Pause(ctx, created.ID, serviceTestActor)
	if err != nil {
		t.Fatal(err)
	}
	if paused.SuppressedUntil != nil {
		t.Fatalf("expected pause to clear suppression, got %+v", paused.SuppressedUntil)
	}
}

func TestServicePauseEndsLinkedFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := newTestService(database)
	created := createScheduleWithMondayRule(t, ctx, service, repo.ID)
	if _, err := service.Activate(ctx, created.ID, serviceTestActor); err != nil {
		t.Fatal(err)
	}
	linked := createLinkedFreeze(t, ctx, database, repo.ID, created.ID)

	if _, err := service.Pause(ctx, created.ID, serviceTestActor); err != nil {
		t.Fatal(err)
	}

	closed, err := freeze.NewStore(database).Get(ctx, linked.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected linked freeze ended on pause, got %+v", closed)
	}
}

func TestServiceDeleteEndsLinkedFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := newTestService(database)
	created := createScheduleWithMondayRule(t, ctx, service, repo.ID)
	if _, err := service.Activate(ctx, created.ID, serviceTestActor); err != nil {
		t.Fatal(err)
	}
	linked := createLinkedFreeze(t, ctx, database, repo.ID, created.ID)

	if _, err := service.Delete(ctx, created.ID, serviceTestActor); err != nil {
		t.Fatal(err)
	}

	closed, err := freeze.NewStore(database).Get(ctx, linked.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected linked freeze ended on delete, got %+v", closed)
	}
}

func TestServiceEndMaterializedFreezeSuppressesCoveringSchedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := newTestService(database)
	created := createScheduleWithMondayRule(t, ctx, service, repo.ID)
	if _, err := service.Activate(ctx, created.ID, serviceTestActor); err != nil {
		t.Fatal(err)
	}
	linked := createLinkedFreeze(t, ctx, database, repo.ID, created.ID)

	ended, err := service.EndMaterializedFreeze(ctx, linked.ID, serviceTestActor)
	if err != nil {
		t.Fatal(err)
	}
	if ended.ID != linked.ID {
		t.Fatalf("expected ended freeze %d, got %+v", linked.ID, ended)
	}

	closed, err := freeze.NewStore(database).Get(ctx, linked.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected freeze ended, got %+v", closed)
	}

	// The Monday rule's current window ends 17:00; the schedule stays quiet
	// until then and resumes the following Monday 09:00.
	windowEnd := time.Date(2026, 7, 20, 17, 0, 0, 0, time.UTC)
	nextWindow := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	suppressed, err := service.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if suppressed.SuppressedUntil == nil || !suppressed.SuppressedUntil.Equal(windowEnd) {
		t.Fatalf("expected suppression until %v, got %+v", windowEnd, suppressed.SuppressedUntil)
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].Action != audit.ActionScheduleSuppressed {
		t.Fatalf("expected schedule.suppressed as the latest audit event, got %+v", events)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["ended_freeze_id"] != strconv.FormatInt(linked.ID, 10) {
		t.Fatalf("expected ended_freeze_id %d, got %s", linked.ID, events[0].DetailsJSON)
	}
	if details["suppressed_until"] != windowEnd.Format(time.RFC3339Nano) {
		t.Fatalf("expected suppressed_until %q, got %s", windowEnd.Format(time.RFC3339Nano), events[0].DetailsJSON)
	}
	if details["resumes_at"] != nextWindow.Format(time.RFC3339Nano) {
		t.Fatalf("expected resumes_at %q, got %s", nextWindow.Format(time.RFC3339Nano), events[0].DetailsJSON)
	}
}

func TestServiceEndMaterializedFreezeRejectsManualFreezeAndRollsBack(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := newTestService(database)

	manual, err := freeze.NewService(database).CreateActive(ctx, freeze.CreateParams{
		RepositoryID: repo.ID,
		Branch:       "main",
		Reason:       "Manual freeze",
	}, serviceTestActor)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.EndMaterializedFreeze(ctx, manual.ID, serviceTestActor)
	if !IsValidationError(err) || err.Error() != "freeze was not created by a recurring schedule" {
		t.Fatalf("expected unlinked-freeze validation error, got %v", err)
	}

	still, err := freeze.NewStore(database).Get(ctx, manual.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.Status != domain.BranchFreezeStatusActive {
		t.Fatalf("expected the manual freeze to stay active after rollback, got %+v", still)
	}
}
