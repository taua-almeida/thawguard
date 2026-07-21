package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

func wallClock(t time.Time) string {
	return t.UTC().Format(wallDateTimeFormat)
}

func TestScheduleDetailDatedShowsEmptyStateAndDisabledActivate(t *testing.T) {
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Christmas maintenance", Kind: domain.ScheduleKindDated, Timezone: "UTC"}}}
	server := scheduleTestServer(store)
	admin := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleAdmin})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/scheduled-freezes/schedules/3", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d body=%q", recorder.Code, body)
	}
	for _, want := range []string{
		"Date windows",
		"No upcoming windows",
		"Past windows are not kept here; see Activity for what was frozen.",
		"Add at least one date window before activating.",
		"Add a window",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dated detail body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "Weekly rules") || strings.Contains(body, "Coverage preview") {
		t.Fatalf("expected no rules card or preview for an empty dated schedule, got %q", body)
	}
	// The Activate button must be present but disabled, with no working form.
	if !strings.Contains(body, "Activate schedule") || strings.Contains(body, `action="/scheduled-freezes/schedules/3/activate"`) {
		t.Fatalf("expected a disabled activate affordance without a form, got %q", body)
	}
}

func TestScheduleDetailDatedHidesPastWindowsAndMarksStarted(t *testing.T) {
	now := time.Now()
	store := &fakeScheduleStore{
		schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Christmas maintenance", Kind: domain.ScheduleKindDated, Timezone: "UTC"}},
		windows: map[int64][]domain.ScheduleDatedWindow{3: {
			{ID: 201, ScheduleID: 3, Name: "Ended window", StartsAt: wallClock(now.Add(-48 * time.Hour)), EndsAt: wallClock(now.Add(-24 * time.Hour))},
			{ID: 202, ScheduleID: 3, Name: "Running window", StartsAt: wallClock(now.Add(-time.Hour)), EndsAt: wallClock(now.Add(3 * time.Hour))},
			{ID: 203, ScheduleID: 3, Name: "Future window", StartsAt: wallClock(now.Add(24 * time.Hour)), EndsAt: wallClock(now.Add(48 * time.Hour))},
		}},
	}
	server := scheduleTestServer(store)

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes/schedules/3", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d body=%q", recorder.Code, body)
	}
	if strings.Contains(body, "Ended window") {
		t.Fatalf("expected the past window to be hidden, got %q", body)
	}
	for _, want := range []string{
		"Running window", "Future window", "already started",
		"/scheduled-freezes/schedules/3/windows/202/delete",
		"/scheduled-freezes/schedules/3/windows/203/delete",
		"Coverage preview",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dated detail body to contain %q, got %q", want, body)
		}
	}
	if strings.Count(body, "already started") != 1 {
		t.Fatalf("expected exactly one already-started marker, got %d", strings.Count(body, "already started"))
	}
}

func TestScheduleWindowAddAllowsFreezerRejectsViewerAndPreservesFormOnValidationError(t *testing.T) {
	now := time.Now()
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Christmas maintenance", Kind: domain.ScheduleKindDated, Timezone: "UTC"}}}
	server := scheduleTestServer(store)

	futureStart, futureEnd := wallClock(now.Add(24*time.Hour)), wallClock(now.Add(48*time.Hour))
	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	form := url.Values{"name": {"Christmas"}, "starts_at": {futureStart}, "ends_at": {futureEnd}, csrfFormField: {viewer.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.addedWindows) != 0 {
		t.Fatalf("expected viewer window add to be forbidden, status=%d added=%d", recorder.Code, len(store.addedWindows))
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	form.Set(csrfFormField, freezer.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=window-added" {
		t.Fatalf("expected window add redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.addedWindows) != 1 || store.addedWindows[0] != (schedule.AddWindowParams{ScheduleID: 3, Name: "Christmas", StartsAt: futureStart, EndsAt: futureEnd}) {
		t.Fatalf("unexpected add-window params: %+v", store.addedWindows)
	}

	// A window whose start is already past is accepted, with the explicit
	// coverage-begins-immediately notice.
	form.Set("name", "Running")
	form.Set("starts_at", wallClock(now.Add(-time.Hour)))
	form.Set("ends_at", wallClock(now.Add(3*time.Hour)))
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=window-added-started" {
		t.Fatalf("expected already-started notice redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}

	store.addWindowErr = schedule.ValidationError{Message: "this window has already ended, so it would never freeze anything"}
	form.Set("name", "Ended")
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected validation error re-render, status=%d", recorder.Code)
	}
	for _, want := range []string{"this window has already ended, so it would never freeze anything", `value="Ended"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected validation re-render to contain %q, got %q", want, body)
		}
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/999/windows", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for window add on unknown schedule, got %d", recorder.Code)
	}
}

func TestScheduleWindowDeleteRedirectsAndUnknownWindowIs404(t *testing.T) {
	now := time.Now()
	store := &fakeScheduleStore{
		schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Christmas maintenance", Kind: domain.ScheduleKindDated, Timezone: "UTC"}},
		windows: map[int64][]domain.ScheduleDatedWindow{3: {
			{ID: 201, ScheduleID: 3, Name: "Christmas", StartsAt: wallClock(now.Add(24 * time.Hour)), EndsAt: wallClock(now.Add(48 * time.Hour))},
		}},
	}
	server := scheduleTestServer(store)

	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	form := url.Values{csrfFormField: {viewer.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows/201/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.removedWindows) != 0 {
		t.Fatalf("expected viewer window delete to be forbidden, status=%d removed=%d", recorder.Code, len(store.removedWindows))
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	form.Set(csrfFormField, freezer.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows/999/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown window, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/windows/201/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=window-removed" {
		t.Fatalf("expected window delete redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.removedWindows) != 1 || store.removedWindows[0] != 201 {
		t.Fatalf("unexpected removed windows: %+v", store.removedWindows)
	}
}

func TestScheduleNextLabel(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC) // a Tuesday
	weekly := domain.Schedule{ID: 1, Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}
	dated := domain.Schedule{ID: 2, Kind: domain.ScheduleKindDated, Timezone: "UTC"}
	rule := domain.ScheduleWeeklyRule{ID: 101, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "08:00"}
	activeRule := domain.ScheduleWeeklyRule{ID: 102, ScheduleID: 1, StartWeekday: time.Tuesday, StartTime: "08:00", EndWeekday: time.Tuesday, EndTime: "18:00"}

	cases := []struct {
		name    string
		sched   domain.Schedule
		rules   []domain.ScheduleWeeklyRule
		windows []domain.ScheduleDatedWindow
		want    string
	}{
		{name: "weekly without rules", sched: weekly, want: "Next: — · no rules yet"},
		{name: "weekly upcoming", sched: weekly, rules: []domain.ScheduleWeeklyRule{rule}, want: "Next: Mon 18:00 → Tue 08:00"},
		{name: "weekly covering now", sched: weekly, rules: []domain.ScheduleWeeklyRule{activeRule}, want: "Next: now → Tue 18:00"},
		{name: "dated without windows", sched: dated, want: "Next: — · no upcoming dates"},
		{
			name:  "dated with only past windows",
			sched: dated,
			windows: []domain.ScheduleDatedWindow{
				{ID: 201, ScheduleID: 2, Name: "Done", StartsAt: "2026-07-01T08:00", EndsAt: "2026-07-02T08:00"},
			},
			want: "Next: — · no upcoming dates",
		},
		{
			name:  "dated upcoming beyond the strip horizon",
			sched: dated,
			windows: []domain.ScheduleDatedWindow{
				{ID: 202, ScheduleID: 2, Name: "Christmas", StartsAt: "2026-12-21T08:00", EndsAt: "2026-12-30T08:00"},
			},
			want: "Next: 21 Dec 08:00",
		},
		{
			name:  "dated covering now",
			sched: dated,
			windows: []domain.ScheduleDatedWindow{
				{ID: 203, ScheduleID: 2, Name: "Running", StartsAt: "2026-07-21T08:00", EndsAt: "2026-07-23T08:00"},
			},
			want: "Next: now → 23 Jul 08:00",
		},
	}
	for _, tc := range cases {
		if got := scheduleNextLabel(tc.sched, tc.rules, tc.windows, now); got != tc.want {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.want, got)
		}
	}
}

// TestScheduleContextViewFromNamesHandoversWithoutCoverageGaps is the brief's
// Wednesday-holiday shape: weekly Tue/Wed evening rules plus a dated Wednesday
// window make one continuous block whose label changes at the window's edges,
// with zero thaw gaps.
func TestScheduleContextViewFromNamesHandoversWithoutCoverageGaps(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC) // Tue Jul 21
	weekly := domain.Schedule{ID: 1, RepositoryID: 1, Branch: "main", Name: "Work week lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC", Active: true, CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	dated := domain.Schedule{ID: 2, RepositoryID: 1, Branch: "main", Name: "Wednesday holiday", Kind: domain.ScheduleKindDated, Timezone: "UTC", Active: true, CreatedAt: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)}
	coverages := []schedule.Coverage{
		{Schedule: weekly, Rules: []domain.ScheduleWeeklyRule{
			{ID: 101, ScheduleID: 1, StartWeekday: time.Tuesday, StartTime: "18:00", EndWeekday: time.Wednesday, EndTime: "08:00"},
			{ID: 102, ScheduleID: 1, StartWeekday: time.Wednesday, StartTime: "18:00", EndWeekday: time.Thursday, EndTime: "08:00"},
		}},
		{Schedule: dated, Windows: []domain.ScheduleDatedWindow{
			{ID: 201, ScheduleID: 2, Name: "Wednesday holiday", StartsAt: "2026-07-22T00:00", EndsAt: "2026-07-23T00:00"},
		}},
	}

	view, err := scheduleContextViewFrom(dated, []domain.Schedule{weekly, dated}, coverages, now)
	if err != nil {
		t.Fatal(err)
	}
	if view.BranchLabel != "main" || len(view.Blocks) == 0 {
		t.Fatalf("expected context blocks for main, got %+v", view)
	}
	block := view.Blocks[0]
	if block.RangeLabel != "Tue 21 Jul 18:00 → Thu 23 Jul 08:00" {
		t.Fatalf("expected one unbroken block, got %q", block.RangeLabel)
	}
	if len(block.Names) != 3 ||
		block.Names[0].Name != "Work week lock" || block.Names[0].RangeLabel != "Tue 21 Jul 18:00 → Wed 22 Jul 00:00" ||
		block.Names[1].Name != "Wednesday holiday" || block.Names[1].RangeLabel != "Wed 22 Jul 00:00 → Thu 23 Jul 00:00" ||
		block.Names[2].Name != "Work week lock" || block.Names[2].RangeLabel != "Thu 23 Jul 00:00 → Thu 23 Jul 08:00" {
		t.Fatalf("expected weekly → dated → weekly naming spans, got %+v", block.Names)
	}
	if block.NameSummary != "Work week lock, then Wednesday holiday, then Work week lock" {
		t.Fatalf("unexpected name summary: %q", block.NameSummary)
	}
	if len(block.Sources) != 3 {
		t.Fatalf("expected three contributing sources, got %+v", block.Sources)
	}
	for _, source := range block.Sources {
		if source.Name == "Wednesday holiday" && !source.Current {
			t.Fatalf("expected the dated source marked as this schedule, got %+v", block.Sources)
		}
		if source.Name == "Work week lock" && source.Current {
			t.Fatalf("expected the weekly source not marked current, got %+v", block.Sources)
		}
	}
}

func TestScheduleDetailShowsCombinedCoverageOnlyWithActivePeers(t *testing.T) {
	now := time.Now()
	weekly := domain.Schedule{ID: 1, RepositoryID: 1, Branch: "main", Name: "Work week lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC", Active: true, CreatedAt: now.Add(-48 * time.Hour)}
	dated := domain.Schedule{ID: 2, RepositoryID: 1, Branch: "main", Name: "Wednesday holiday", Kind: domain.ScheduleKindDated, Timezone: "UTC", Active: true, CreatedAt: now.Add(-24 * time.Hour)}
	store := &fakeScheduleStore{
		schedules: []domain.Schedule{weekly, dated},
		rules: map[int64][]domain.ScheduleWeeklyRule{1: {
			{ID: 101, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "08:00"},
		}},
		windows: map[int64][]domain.ScheduleDatedWindow{2: {
			{ID: 201, ScheduleID: 2, Name: "Wednesday holiday", StartsAt: wallClock(now.Add(24 * time.Hour)), EndsAt: wallClock(now.Add(48 * time.Hour))},
		}},
	}
	server := scheduleTestServer(store)

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes/schedules/2", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, "Combined coverage on main") {
		t.Fatalf("expected combined coverage with two active peers, status=%d body=%q", recorder.Code, body)
	}

	// Pause the weekly peer: with a single active schedule there is no
	// precedence to explain, so the section disappears.
	store.schedules[0].Active = false
	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes/schedules/2", nil))
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "Combined coverage") {
		t.Fatalf("expected no combined coverage with one active schedule, status=%d", recorder.Code)
	}
}
