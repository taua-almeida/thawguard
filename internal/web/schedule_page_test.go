package web

import (
	"context"
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

type fakeScheduleStore struct {
	schedules []domain.Schedule
	created   []schedule.CreateParams
	deleted   []int64
	createErr error
}

func (s *fakeScheduleStore) List(ctx context.Context) ([]domain.Schedule, error) {
	return s.schedules, nil
}

func (s *fakeScheduleStore) Get(ctx context.Context, id int64) (domain.Schedule, error) {
	for _, item := range s.schedules {
		if item.ID == id {
			return item, nil
		}
	}
	return domain.Schedule{}, schedule.ErrNotFound
}

func (s *fakeScheduleStore) Create(ctx context.Context, params schedule.CreateParams, actor domain.Actor) (domain.Schedule, error) {
	if s.createErr != nil {
		return domain.Schedule{}, s.createErr
	}
	s.created = append(s.created, params)
	return domain.Schedule{ID: 11, RepositoryID: params.RepositoryID, Branch: params.Branch, Name: params.Name, Kind: params.Kind, Timezone: params.Timezone, Reason: params.Reason, CreatedAt: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}, nil
}

func (s *fakeScheduleStore) Delete(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	item, err := s.Get(ctx, id)
	if err != nil {
		return domain.Schedule{}, err
	}
	s.deleted = append(s.deleted, id)
	return item, nil
}

func scheduleTestServer(store *fakeScheduleStore) *Server {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	return NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		ScheduledFreezeStore: &fakeFreezeStore{},
		ScheduleStore:        store,
	})
}

func TestScheduledFreezesPageShowsScheduleRegionOnlyWhenStoreConfigured(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	withoutStore := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: &fakeFreezeStore{}})
	recorder := httptest.NewRecorder()
	withoutStore.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes", nil))
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "Recurring schedules") {
		t.Fatalf("expected schedules region hidden without a store, status=%d", recorder.Code)
	}

	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/Sao_Paulo"}}}
	recorder = httptest.NewRecorder()
	scheduleTestServer(store).Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes", nil))
	body := recorder.Body.String()
	for _, want := range []string{"Recurring schedules", "Nightly release lock", "Paused", "taua-almeida/thawguard", "America/Sao_Paulo", `href="/scheduled-freezes/schedules/3"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected schedules region to contain %q, got %q", want, body)
		}
	}
}

func TestScheduleCreateAllowsFreezerRejectsViewerAndPreservesFormOnValidationError(t *testing.T) {
	store := &fakeScheduleStore{}
	server := scheduleTestServer(store)

	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	form := url.Values{"repository_id": {"1"}, "branch": {"main"}, "name": {"Nightly release lock"}, "kind": {"weekly"}, "timezone": {"America/Sao_Paulo"}, "reason": {"quiet hours"}, csrfFormField: {viewer.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/new", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.created) != 0 {
		t.Fatalf("expected viewer create to be forbidden, status=%d created=%d", recorder.Code, len(store.created))
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	form.Set(csrfFormField, freezer.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/new", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/11?notice=created" {
		t.Fatalf("expected create redirect to detail, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.created) != 1 || store.created[0].Name != "Nightly release lock" || store.created[0].Kind != domain.ScheduleKindWeekly || store.created[0].Timezone != "America/Sao_Paulo" {
		t.Fatalf("unexpected create params: %+v", store.created)
	}

	store.createErr = schedule.ValidationError{Message: "a schedule named \"Nightly release lock\" already exists for this branch"}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/new", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected validation error re-render, status=%d", recorder.Code)
	}
	for _, want := range []string{"already exists for this branch", `value="Nightly release lock"`, "New recurring schedule"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected validation re-render to contain %q, got %q", want, body)
		}
	}
}

func TestScheduleDetailRendersPausedTruthAndUnknownIDIs404(t *testing.T) {
	created := time.Date(2026, 7, 18, 9, 30, 0, 0, time.UTC)
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/Sao_Paulo", Reason: "quiet hours", CreatedAt: created}}}
	server := scheduleTestServer(store)

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes/schedules/3", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d body=%q", recorder.Code, body)
	}
	for _, want := range []string{"Nightly release lock", "Paused", "never freezes its branch", "Weekly", "America/Sao_Paulo", "quiet hours", "No weekly rules yet", "2026-07-18 09:30 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected detail body to contain %q, got %q", want, body)
		}
	}

	for _, path := range []string{"/scheduled-freezes/schedules/999", "/scheduled-freezes/schedules/not-a-number"} {
		recorder = httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", path, recorder.Code)
		}
	}
}

func TestScheduleDeleteAllowsFreezerRejectsViewerAndRedirectsWithNotice(t *testing.T) {
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}}}
	server := scheduleTestServer(store)

	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	form := url.Values{csrfFormField: {viewer.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.deleted) != 0 {
		t.Fatalf("expected viewer delete to be forbidden, status=%d deleted=%d", recorder.Code, len(store.deleted))
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	form.Set(csrfFormField, freezer.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes?notice=recurring-schedule-deleted" {
		t.Fatalf("expected delete redirect with notice, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.deleted) != 1 || store.deleted[0] != 3 {
		t.Fatalf("unexpected deletes: %+v", store.deleted)
	}
}

func TestScheduleMutationsAllowAdminWithoutFreezerRole(t *testing.T) {
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}}}
	server := scheduleTestServer(store)
	admin := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleAdmin})

	form := url.Values{"repository_id": {"1"}, "branch": {"main"}, "name": {"Weekend lock"}, "kind": {"weekly"}, "timezone": {"UTC"}, csrfFormField: {admin.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/new", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || len(store.created) != 1 {
		t.Fatalf("expected admin create to succeed, status=%d created=%d", recorder.Code, len(store.created))
	}

	form = url.Values{csrfFormField: {admin.CSRFToken}}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || len(store.deleted) != 1 || store.deleted[0] != 3 {
		t.Fatalf("expected admin delete to succeed, status=%d deleted=%+v", recorder.Code, store.deleted)
	}
}

func TestTimezoneOffsetLabel(t *testing.T) {
	at := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "UTC", want: "UTC"},
		{name: "America/Sao_Paulo", want: "America/Sao_Paulo (UTC-03:00)"},
		{name: "Asia/Kolkata", want: "Asia/Kolkata (UTC+05:30)"},
		{name: "Not/AZone", want: "Not/AZone"},
	} {
		if got := timezoneOffsetLabel(test.name, at); got != test.want {
			t.Fatalf("timezoneOffsetLabel(%q) = %q, want %q", test.name, got, test.want)
		}
	}
}
