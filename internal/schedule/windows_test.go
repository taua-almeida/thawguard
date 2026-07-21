package schedule

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestStoreAddWindowInsertsAndListsOrderedByStart(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	store := NewStore(database)

	later, alreadyStarted, err := store.AddWindow(ctx, AddWindowParams{
		ScheduleID: created.ID,
		Name:       "New Year change lock",
		StartsAt:   "2030-12-24T08:00",
		EndsAt:     "2031-01-02T08:00",
	})
	if err != nil {
		t.Fatal(err)
	}
	if alreadyStarted {
		t.Fatalf("expected a future window not to report already started")
	}
	if later.ID == 0 || later.ScheduleID != created.ID || later.StartsAt != "2030-12-24T08:00" || later.EndsAt != "2031-01-02T08:00" {
		t.Fatalf("window not persisted as submitted: %+v", later)
	}
	earlier, _, err := store.AddWindow(ctx, AddWindowParams{
		ScheduleID: created.ID,
		Name:       "Independence day",
		StartsAt:   "2030-09-07T00:00",
		EndsAt:     "2030-09-08T00:00",
	})
	if err != nil {
		t.Fatal(err)
	}

	windows, err := store.ListWindows(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 2 {
		t.Fatalf("expected 2 windows, got %d", len(windows))
	}
	if windows[0].ID != earlier.ID || windows[1].ID != later.ID {
		t.Fatalf("expected start-time order, got %+v", windows)
	}
}

func TestStoreAddWindowValidation(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	store := NewStore(database)

	valid := AddWindowParams{
		ScheduleID: created.ID,
		Name:       "Year-end freeze",
		StartsAt:   "2030-12-24T08:00",
		EndsAt:     "2031-01-02T08:00",
	}
	cases := []struct {
		name    string
		mutate  func(params AddWindowParams) AddWindowParams
		message string
	}{
		{"missing schedule", func(p AddWindowParams) AddWindowParams { p.ScheduleID = 0; return p }, "missing required fields: schedule"},
		{"missing everything", func(p AddWindowParams) AddWindowParams { p.Name = ""; p.StartsAt = " "; p.EndsAt = ""; return p }, "missing required fields: end, name, start"},
		{"long name", func(p AddWindowParams) AddWindowParams {
			for len(p.Name) <= nameMaxLength {
				p.Name += "x"
			}
			return p
		}, "window name must be 100 characters or fewer"},
		{"control characters", func(p AddWindowParams) AddWindowParams { p.Name = "bad\nname"; return p }, "window name contains unsupported control characters"},
		{"invalid start", func(p AddWindowParams) AddWindowParams { p.StartsAt = "2030-12-24 08:00"; return p }, "start must be a valid date and time"},
		{"impossible start date", func(p AddWindowParams) AddWindowParams { p.StartsAt = "2030-02-30T08:00"; return p }, "start must be a valid date and time"},
		{"invalid end", func(p AddWindowParams) AddWindowParams { p.EndsAt = "2031-01-02T8:00"; return p }, "end must be a valid date and time"},
		{"end before start", func(p AddWindowParams) AddWindowParams { p.EndsAt = "2030-12-24T07:00"; return p }, "a window's end must be after its start"},
		{"end equals start", func(p AddWindowParams) AddWindowParams { p.EndsAt = p.StartsAt; return p }, "a window's end must be after its start"},
		{"already ended", func(p AddWindowParams) AddWindowParams {
			p.StartsAt = "2020-12-24T08:00"
			p.EndsAt = "2021-01-02T08:00"
			return p
		}, "this window has already ended, so it would never freeze anything"},
	}
	for _, tc := range cases {
		_, _, err := store.AddWindow(ctx, tc.mutate(valid))
		if !IsValidationError(err) {
			t.Fatalf("%s: expected validation error, got %v", tc.name, err)
		}
		if err.Error() != tc.message {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.message, err.Error())
		}
	}

	// The valid submission still passes after every rejection above.
	if _, _, err := store.AddWindow(ctx, valid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddWindow(ctx, valid); !IsValidationError(err) {
		t.Fatalf("expected duplicate-name validation error, got %v", err)
	} else if err.Error() != "a window with this name already exists on this schedule" {
		t.Fatalf("unexpected duplicate message: %q", err.Error())
	}
}

func TestStoreAddWindowAcceptsAlreadyStartedWindow(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	store := NewStore(database)

	// Started in 2020, ends in 2030: still coverable, so accepted, and the
	// same clock reading that accepted it reports it as already started so
	// the caller can surface the "coverage begins immediately" note.
	window, alreadyStarted, err := store.AddWindow(ctx, AddWindowParams{
		ScheduleID: created.ID,
		Name:       "Long maintenance moratorium",
		StartsAt:   "2020-01-01T00:00",
		EndsAt:     "2030-01-01T00:00",
	})
	if err != nil {
		t.Fatal(err)
	}
	if window.ID == 0 {
		t.Fatalf("window not persisted: %+v", window)
	}
	if !alreadyStarted {
		t.Fatalf("expected an in-progress window to report already started")
	}
}

func TestStoreAddWindowRequiresExistingDatedSchedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewStore(database)

	if _, _, err := store.AddWindow(ctx, AddWindowParams{ScheduleID: 999, Name: "Nowhere", StartsAt: "2030-12-24T08:00", EndsAt: "2031-01-02T08:00"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	weekly := createTestWeeklySchedule(t, ctx, database)
	_, _, err := store.AddWindow(ctx, AddWindowParams{ScheduleID: weekly.ID, Name: "Wrong kind", StartsAt: "2030-12-24T08:00", EndsAt: "2031-01-02T08:00"})
	if !IsValidationError(err) || err.Error() != "date windows can only be added to a dated schedule" {
		t.Fatalf("expected kind validation error, got %v", err)
	}
}

func TestStoreDeleteWindowIsScopedToItsSchedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	other := createTestDatedScheduleNamed(t, ctx, database, created.RepositoryID, "Other dated lock")
	store := NewStore(database)

	window, _, err := store.AddWindow(ctx, AddWindowParams{
		ScheduleID: created.ID,
		Name:       "Year-end freeze",
		StartsAt:   "2030-12-24T08:00",
		EndsAt:     "2031-01-02T08:00",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.DeleteWindow(ctx, other.ID, window.ID); !errors.Is(err, ErrWindowNotFound) {
		t.Fatalf("expected ErrWindowNotFound through another schedule, got %v", err)
	}
	deleted, err := store.DeleteWindow(ctx, created.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.ID != window.ID || deleted.Name != "Year-end freeze" {
		t.Fatalf("unexpected deleted window: %+v", deleted)
	}
	windows, err := store.ListWindows(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 0 {
		t.Fatalf("expected no windows after delete, got %+v", windows)
	}
}

func TestScheduleDeleteCascadesWindows(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	store := NewStore(database)

	if _, _, err := store.AddWindow(ctx, AddWindowParams{
		ScheduleID: created.ID,
		Name:       "Year-end freeze",
		StartsAt:   "2030-12-24T08:00",
		EndsAt:     "2031-01-02T08:00",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM schedule_dated_windows`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected windows to cascade with their schedule, got %d rows", count)
	}
}

func TestServiceAddWindowRecordsOneAuditEventPerSubmission(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	added, _, err := service.AddWindow(ctx, AddWindowParams{
		ScheduleID: created.ID,
		Name:       "Year-end freeze",
		StartsAt:   "2030-12-24T08:00",
		EndsAt:     "2031-01-02T08:00",
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	details := assertSingleRuleAuditEvent(t, ctx, database, audit.ActionScheduleWindowAdded, created.ID)
	if details["window_name"] != "Year-end freeze" || details["starts_at"] != "2030-12-24T08:00" || details["ends_at"] != "2031-01-02T08:00" || details["name"] != created.Name {
		t.Fatalf("unexpected window_added details: %+v", details)
	}

	if _, err := service.DeleteWindow(ctx, created.ID, added.ID, actor); err != nil {
		t.Fatal(err)
	}
	details = assertSingleRuleAuditEvent(t, ctx, database, audit.ActionScheduleWindowRemoved, created.ID)
	if details["window_name"] != "Year-end freeze" {
		t.Fatalf("unexpected window_removed details: %+v", details)
	}
}

func TestServiceRejectedWindowSubmissionRecordsNoAudit(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestDatedSchedule(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	if _, _, err := service.AddWindow(ctx, AddWindowParams{ScheduleID: created.ID, Name: "Backwards", StartsAt: "2031-01-02T08:00", EndsAt: "2030-12-24T08:00"}, actor); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == audit.ActionScheduleWindowAdded {
			t.Fatalf("expected no window_added audit event, got %+v", event)
		}
	}
}

func TestServiceActivateRequiresCoverageDefinition(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	weekly := createTestWeeklySchedule(t, ctx, database)
	if _, err := service.Activate(ctx, weekly.ID, actor); !IsValidationError(err) || err.Error() != "add at least one rule before activating" {
		t.Fatalf("expected empty-weekly activation rejection, got %v", err)
	}

	dated := createTestDatedScheduleNamed(t, ctx, database, weekly.RepositoryID, "Holiday locks")
	if _, err := service.Activate(ctx, dated.ID, actor); !IsValidationError(err) || err.Error() != "add at least one date window before activating" {
		t.Fatalf("expected empty-dated activation rejection, got %v", err)
	}

	if _, _, err := NewStore(database).AddWindow(ctx, AddWindowParams{
		ScheduleID: dated.ID,
		Name:       "Year-end freeze",
		StartsAt:   "2030-12-24T08:00",
		EndsAt:     "2031-01-02T08:00",
	}); err != nil {
		t.Fatal(err)
	}
	activated, err := service.Activate(ctx, dated.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Active {
		t.Fatalf("expected schedule to activate with one window: %+v", activated)
	}
}

func TestWindowBoundsResolvesDSTTransitions(t *testing.T) {
	schedule := domain.Schedule{ID: 1, Timezone: "America/New_York"}

	// Plain resolution: EST is UTC-5.
	start, end, err := WindowBounds(schedule, domain.ScheduleDatedWindow{Name: "plain", StartsAt: "2027-01-10T08:00", EndsAt: "2027-01-12T17:00"})
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(time.Date(2027, 1, 10, 13, 0, 0, 0, time.UTC)) || !end.Equal(time.Date(2027, 1, 12, 22, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected plain bounds: %v → %v", start, end)
	}

	// Spring forward 2027-03-14: 02:30 does not exist; the boundary shifts
	// forward to 03:00 EDT (07:00 UTC).
	start, _, err = WindowBounds(schedule, domain.ScheduleDatedWindow{Name: "nonexistent", StartsAt: "2027-03-14T02:30", EndsAt: "2027-03-15T08:00"})
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(time.Date(2027, 3, 14, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected nonexistent start to shift to 07:00 UTC, got %v", start)
	}

	// Fall back 2027-11-07: 01:30 occurs twice. A start uses the first
	// occurrence (EDT, UTC-4); an end uses the second (EST, UTC-5), so the
	// window is never shortened.
	start, end, err = WindowBounds(schedule, domain.ScheduleDatedWindow{Name: "repeated", StartsAt: "2027-11-07T01:30", EndsAt: "2027-11-07T01:45"})
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(time.Date(2027, 11, 7, 5, 30, 0, 0, time.UTC)) {
		t.Fatalf("expected repeated start at first occurrence 05:30 UTC, got %v", start)
	}
	if !end.Equal(time.Date(2027, 11, 7, 6, 45, 0, 0, time.UTC)) {
		t.Fatalf("expected repeated end at second occurrence 06:45 UTC, got %v", end)
	}
}

func TestParseWallDateTime(t *testing.T) {
	year, month, day, minutes, ok := parseWallDateTime("2030-12-24T08:30")
	if !ok || year != 2030 || month != time.December || day != 24 || minutes != 8*60+30 {
		t.Fatalf("expected 2030-12-24 510min, got %d-%d-%d %d ok=%v", year, month, day, minutes, ok)
	}
	invalid := []string{
		"", "2030-12-24", "2030-12-24 08:30", "2030-12-24T8:30", "2030-13-01T08:30",
		"2030-00-10T08:30", "2030-02-30T08:30", "2030-12-24T24:00", "203x-12-24T08:30",
		"2030/12/24T08:30", "2030-12-24T08:30:00",
	}
	for _, value := range invalid {
		if _, _, _, _, ok := parseWallDateTime(value); ok {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func createTestDatedSchedule(t *testing.T, ctx context.Context, database *sql.DB) domain.Schedule {
	t.Helper()
	repo := createTestRepository(t, ctx, database)
	return createTestDatedScheduleNamed(t, ctx, database, repo.ID, "Holiday change locks")
}

func createTestDatedScheduleNamed(t *testing.T, ctx context.Context, database *sql.DB, repositoryID int64, name string) domain.Schedule {
	t.Helper()
	created, err := NewStore(database).Create(ctx, CreateParams{
		RepositoryID: repositoryID,
		Branch:       "main",
		Name:         name,
		Kind:         domain.ScheduleKindDated,
		Timezone:     "America/New_York",
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}
