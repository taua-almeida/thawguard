package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	// The store validates timezones with time.LoadLocation; embedding the
	// zone database keeps these tests independent of the host's zoneinfo.
	_ "time/tzdata"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreCreatesPausedScheduleShell(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.Create(ctx, CreateParams{
		RepositoryID: repo.ID,
		Branch:       " main ",
		Name:         " Nightly release lock ",
		Kind:         domain.ScheduleKindWeekly,
		Timezone:     "America/Sao_Paulo",
		Reason:       " Weekend release freeze ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected schedule id")
	}
	if created.Branch != "main" || created.Name != "Nightly release lock" || created.Reason != "Weekend release freeze" {
		t.Fatalf("expected trimmed fields, got %+v", created)
	}
	if created.Kind != domain.ScheduleKindWeekly || created.Timezone != "America/Sao_Paulo" {
		t.Fatalf("unexpected schedule: %+v", created)
	}
	if created.Active {
		t.Fatal("a new schedule must be created paused")
	}

	loaded, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != created {
		t.Fatalf("expected Get to round-trip the schedule, got %+v want %+v", loaded, created)
	}
}

func TestStoreListsSchedulesOrderedByBranchAndName(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	for _, name := range []string{"Christmas shutdown", "Nightly release lock"} {
		if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: name, Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}); err != nil {
			t.Fatal(err)
		}
	}
	schedules, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(schedules) != 2 || schedules[0].Name != "Christmas shutdown" || schedules[1].Name != "Nightly release lock" {
		t.Fatalf("expected two schedules ordered by name, got %+v", schedules)
	}
}

func TestStoreRejectsInvalidScheduleParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	valid := CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}

	cases := []struct {
		name    string
		mutate  func(CreateParams) CreateParams
		message string
	}{
		{"missing name", func(p CreateParams) CreateParams { p.Name = "  "; return p }, "missing required fields: name"},
		{"missing timezone", func(p CreateParams) CreateParams { p.Timezone = ""; return p }, "missing required fields: timezone"},
		{"invalid kind", func(p CreateParams) CreateParams { p.Kind = "monthly"; return p }, "schedule kind must be weekly or dated"},
		{"invalid timezone", func(p CreateParams) CreateParams { p.Timezone = "Not/AZone"; return p }, "timezone must be a valid IANA timezone name"},
		{"local timezone", func(p CreateParams) CreateParams { p.Timezone = "Local"; return p }, "timezone must be a valid IANA timezone name"},
		{"over-long name", func(p CreateParams) CreateParams { p.Name = strings.Repeat("n", 101); return p }, "schedule name must be 100 characters or fewer"},
		{"control characters in name", func(p CreateParams) CreateParams { p.Name = "line\nbreak"; return p }, "schedule name contains unsupported control characters"},
		{"over-long reason", func(p CreateParams) CreateParams { p.Reason = strings.Repeat("r", 501); return p }, "freeze reason must be 500 characters or fewer"},
		{"control characters in reason", func(p CreateParams) CreateParams { p.Reason = "line\nbreak"; return p }, "freeze reason contains unsupported control characters"},
		{"unmanaged branch", func(p CreateParams) CreateParams { p.Branch = "release/9.9"; return p }, domain.BranchNotManagedMessage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.Create(ctx, tc.mutate(valid))
			if !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
			if err.Error() != tc.message {
				t.Fatalf("expected message %q, got %q", tc.message, err.Error())
			}
		})
	}
}

func TestStoreAcceptsScheduleWithoutReason(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)

	created, err := NewStore(database).Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindDated, Timezone: "Europe/Berlin"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Reason != "" {
		t.Fatalf("expected empty reason to persist, got %q", created.Reason)
	}
}

func TestStoreRejectsDuplicateScheduleNamePerBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	params := CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}
	if _, err := store.Create(ctx, params); err != nil {
		t.Fatal(err)
	}
	_, err := store.Create(ctx, params)
	if !IsValidationError(err) || err.Error() != "a schedule with this name already exists for this branch" {
		t.Fatalf("expected duplicate-name validation error, got %v", err)
	}
}

func TestStoreRequiresEnforcementActiveRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewStore(database).Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"})
	if !IsValidationError(err) || err.Error() != domain.EnforcementNotActiveMessage {
		t.Fatalf("expected enforcement validation error, got %v", err)
	}
}

func TestStoreDeleteReturnsDeletedScheduleAndNotFound(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := store.Delete(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.ID != created.ID {
		t.Fatalf("expected deleted schedule %d, got %+v", created.ID, deleted)
	}
	if _, err := store.Get(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if _, err := store.Delete(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on double delete, got %v", err)
	}
}

func TestServiceRecordsAuditEventsForCreateAndDelete(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	created, err := service.Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/Sao_Paulo"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestScheduleAudit(t, ctx, database, audit.ActionScheduleCreated, created)

	deleted, err := service.Delete(ctx, created.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestScheduleAudit(t, ctx, database, audit.ActionScheduleDeleted, deleted)
}

func TestServiceDeleteOfMissingScheduleRecordsNoAudit(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	createTestRepository(t, ctx, database)

	if _, err := NewService(database).Delete(ctx, 12345, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == audit.ActionScheduleDeleted {
			t.Fatalf("expected no schedule.deleted audit event, got %+v", event)
		}
	}
}

func TestTimezonesStartWithUTCAndAllResolve(t *testing.T) {
	zones := Timezones()
	if len(zones) == 0 || zones[0] != "UTC" {
		t.Fatalf("expected UTC-first timezone list, got %d entries", len(zones))
	}
	for _, zone := range zones {
		if !ValidTimezone(zone) {
			t.Fatalf("listed timezone %q does not resolve", zone)
		}
	}
}

func assertLatestScheduleAudit(t *testing.T, ctx context.Context, database *sql.DB, action string, schedule domain.Schedule) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	event := events[0]
	if event.Action != action || event.SubjectType != audit.SubjectTypeSchedule || event.SubjectID != strconv.FormatInt(schedule.ID, 10) {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["repository_id"] != strconv.FormatInt(schedule.RepositoryID, 10) || details["branch"] != schedule.Branch ||
		details["name"] != schedule.Name || details["kind"] != string(schedule.Kind) ||
		details["timezone"] != schedule.Timezone || details["reason"] != schedule.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
	}
}

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err = repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
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
