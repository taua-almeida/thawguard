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
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

type fakeScheduleStore struct {
	schedules      []domain.Schedule
	created        []schedule.CreateParams
	deleted        []int64
	activated      []int64
	paused         []int64
	createErr      error
	transitionErr  error
	rules          map[int64][]domain.ScheduleWeeklyRule
	addedRules     []schedule.AddRulesParams
	addRulesErr    error
	removedRules   []int64
	windows        map[int64][]domain.ScheduleDatedWindow
	addedWindows   []schedule.AddWindowParams
	addWindowErr   error
	removedWindows []int64
}

func (s *fakeScheduleStore) List(ctx context.Context) ([]domain.Schedule, error) {
	return s.ListForScope(ctx, repositoryscope.All())
}

func (s *fakeScheduleStore) ListForScope(ctx context.Context, scope repositoryscope.ReadScope) ([]domain.Schedule, error) {
	visible := make([]domain.Schedule, 0, len(s.schedules))
	for _, item := range s.schedules {
		if fakeScopeAllows(scope, item.RepositoryID) {
			visible = append(visible, item)
		}
	}
	return visible, nil
}

func (s *fakeScheduleStore) Get(ctx context.Context, id int64) (domain.Schedule, error) {
	return s.GetForScope(ctx, repositoryscope.All(), id)
}

func (s *fakeScheduleStore) GetForScope(ctx context.Context, scope repositoryscope.ReadScope, id int64) (domain.Schedule, error) {
	for _, item := range s.schedules {
		if item.ID == id && fakeScopeAllows(scope, item.RepositoryID) {
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

func (s *fakeScheduleStore) Activate(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	item, err := s.Get(ctx, id)
	if err != nil {
		return domain.Schedule{}, err
	}
	if s.transitionErr != nil {
		return domain.Schedule{}, s.transitionErr
	}
	s.activated = append(s.activated, id)
	item.Active = true
	return item, nil
}

func (s *fakeScheduleStore) Pause(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	item, err := s.Get(ctx, id)
	if err != nil {
		return domain.Schedule{}, err
	}
	if s.transitionErr != nil {
		return domain.Schedule{}, s.transitionErr
	}
	s.paused = append(s.paused, id)
	item.Active = false
	return item, nil
}

func (s *fakeScheduleStore) ListRules(ctx context.Context, scheduleID int64) ([]domain.ScheduleWeeklyRule, error) {
	return s.rules[scheduleID], nil
}

func (s *fakeScheduleStore) AddRules(ctx context.Context, params schedule.AddRulesParams, actor domain.Actor) ([]domain.ScheduleWeeklyRule, error) {
	if _, err := s.Get(ctx, params.ScheduleID); err != nil {
		return nil, err
	}
	if s.addRulesErr != nil {
		return nil, s.addRulesErr
	}
	s.addedRules = append(s.addedRules, params)
	if s.rules == nil {
		s.rules = map[int64][]domain.ScheduleWeeklyRule{}
	}
	added := make([]domain.ScheduleWeeklyRule, 0, len(params.Weekdays))
	for i, weekday := range params.Weekdays {
		end := weekday
		switch params.EndDayMode {
		case schedule.EndDayNext:
			end = (weekday + 1) % 7
		case schedule.EndDaySpecific:
			end = params.EndWeekday
		}
		added = append(added, domain.ScheduleWeeklyRule{
			ID:           int64(100 + len(s.rules[params.ScheduleID]) + i + 1),
			ScheduleID:   params.ScheduleID,
			StartWeekday: weekday,
			StartTime:    params.StartTime,
			EndWeekday:   end,
			EndTime:      params.EndTime,
		})
	}
	s.rules[params.ScheduleID] = append(s.rules[params.ScheduleID], added...)
	return added, nil
}

func (s *fakeScheduleStore) DeleteRule(ctx context.Context, scheduleID, ruleID int64, actor domain.Actor) (domain.ScheduleWeeklyRule, error) {
	rules := s.rules[scheduleID]
	for i, rule := range rules {
		if rule.ID == ruleID {
			s.rules[scheduleID] = append(rules[:i:i], rules[i+1:]...)
			s.removedRules = append(s.removedRules, ruleID)
			return rule, nil
		}
	}
	return domain.ScheduleWeeklyRule{}, schedule.ErrRuleNotFound
}

func (s *fakeScheduleStore) ListWindows(ctx context.Context, scheduleID int64) ([]domain.ScheduleDatedWindow, error) {
	return s.windows[scheduleID], nil
}

func (s *fakeScheduleStore) AddWindow(ctx context.Context, params schedule.AddWindowParams, actor domain.Actor) (domain.ScheduleDatedWindow, bool, error) {
	sched, err := s.Get(ctx, params.ScheduleID)
	if err != nil {
		return domain.ScheduleDatedWindow{}, false, err
	}
	if s.addWindowErr != nil {
		return domain.ScheduleDatedWindow{}, false, s.addWindowErr
	}
	s.addedWindows = append(s.addedWindows, params)
	if s.windows == nil {
		s.windows = map[int64][]domain.ScheduleDatedWindow{}
	}
	added := domain.ScheduleDatedWindow{
		ID:         int64(200 + len(s.windows[params.ScheduleID]) + 1),
		ScheduleID: params.ScheduleID,
		Name:       params.Name,
		StartsAt:   params.StartsAt,
		EndsAt:     params.EndsAt,
	}
	s.windows[params.ScheduleID] = append(s.windows[params.ScheduleID], added)
	alreadyStarted := false
	if start, _, err := schedule.WindowBounds(sched, added); err == nil && !start.After(time.Now()) {
		alreadyStarted = true
	}
	return added, alreadyStarted, nil
}

func (s *fakeScheduleStore) DeleteWindow(ctx context.Context, scheduleID, windowID int64, actor domain.Actor) (domain.ScheduleDatedWindow, error) {
	windows := s.windows[scheduleID]
	for i, window := range windows {
		if window.ID == windowID {
			s.windows[scheduleID] = append(windows[:i:i], windows[i+1:]...)
			s.removedWindows = append(s.removedWindows, windowID)
			return window, nil
		}
	}
	return domain.ScheduleDatedWindow{}, schedule.ErrWindowNotFound
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
	recorder := getPageWithRoles(t, withoutStore, "/scheduled-freezes", auth.RoleSet{auth.RoleFreezer})
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "Recurring schedules") {
		t.Fatalf("expected schedules region hidden without a store, status=%d", recorder.Code)
	}

	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/Sao_Paulo"}}}
	server := scheduleTestServer(store)
	recorder = getPageWithRoles(t, server, "/scheduled-freezes", auth.RoleSet{auth.RoleFreezer})
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

	recorder := getPageWithRoles(t, server, "/scheduled-freezes/schedules/3", auth.RoleSet{auth.RoleFreezer})
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
		recorder = getPageWithRoles(t, server, path, auth.RoleSet{auth.RoleFreezer})
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

func TestScheduleActivateAndPauseAllowFreezerRejectViewerAndRedirect(t *testing.T) {
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}}}
	server := scheduleTestServer(store)

	postTransition := func(sessionID, token, path string) *httptest.ResponseRecorder {
		form := url.Values{csrfFormField: {token}}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
		server.Routes().ServeHTTP(recorder, request)
		return recorder
	}

	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	recorder := postTransition(viewer.ID, viewer.CSRFToken, "/scheduled-freezes/schedules/3/activate")
	if recorder.Code != http.StatusForbidden || len(store.activated) != 0 {
		t.Fatalf("expected viewer activate to be forbidden, status=%d activated=%+v", recorder.Code, store.activated)
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	recorder = postTransition(freezer.ID, freezer.CSRFToken, "/scheduled-freezes/schedules/3/activate")
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=activated" {
		t.Fatalf("expected activate redirect with notice, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.activated) != 1 || store.activated[0] != 3 {
		t.Fatalf("unexpected activations: %+v", store.activated)
	}

	recorder = postTransition(freezer.ID, freezer.CSRFToken, "/scheduled-freezes/schedules/3/pause")
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=paused" {
		t.Fatalf("expected pause redirect with notice, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.paused) != 1 || store.paused[0] != 3 {
		t.Fatalf("unexpected pauses: %+v", store.paused)
	}

	// A double submit races the page state; the store's validation error
	// redirects silently back to the detail page, which shows the truth.
	store.transitionErr = schedule.ValidationError{Message: "schedule is already active"}
	recorder = postTransition(freezer.ID, freezer.CSRFToken, "/scheduled-freezes/schedules/3/activate")
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3" {
		t.Fatalf("expected silent redirect on double submit, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}

	store.transitionErr = nil
	for _, path := range []string{"/scheduled-freezes/schedules/999/activate", "/scheduled-freezes/schedules/not-a-number/pause"} {
		recorder = postTransition(freezer.ID, freezer.CSRFToken, path)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", path, recorder.Code)
		}
	}
}

func TestScheduleDetailRendersActiveBadgeAndSuppressionCallout(t *testing.T) {
	suppressedUntil := time.Date(2030, 1, 5, 17, 0, 0, 0, time.UTC)
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC", Active: true, SuppressedUntil: &suppressedUntil, CreatedAt: time.Date(2026, 7, 18, 9, 30, 0, 0, time.UTC)}}}
	server := scheduleTestServer(store)

	recorder := getPageWithRoles(t, server, "/scheduled-freezes/schedules/3", auth.RoleSet{auth.RoleFreezer})
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d", recorder.Code)
	}
	for _, want := range []string{"Active", "ended manually", "2030-01-05 17:00 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected suppressed detail body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "never freezes its branch") {
		t.Fatal("active schedule must not render the paused callout")
	}
}

func TestScheduleMutationsRejectAdminWithoutFreezerRole(t *testing.T) {
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}}}
	server := scheduleTestServer(store)
	admin := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleAdmin})

	form := url.Values{"repository_id": {"1"}, "branch": {"main"}, "name": {"Weekend lock"}, "kind": {"weekly"}, "timezone": {"UTC"}, csrfFormField: {admin.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/new", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.created) != 0 {
		t.Fatalf("expected Admin without scoped Freezer to be rejected, status=%d created=%d", recorder.Code, len(store.created))
	}

	form = url.Values{csrfFormField: {admin.CSRFToken}}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.deleted) != 0 {
		t.Fatalf("expected Admin without scoped Freezer to be rejected, status=%d deleted=%+v", recorder.Code, store.deleted)
	}
}

func TestScheduleRuleAddAllowsFreezerRejectsViewerAndPreservesFormOnValidationError(t *testing.T) {
	store := &fakeScheduleStore{schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/Sao_Paulo"}}}
	server := scheduleTestServer(store)

	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	form := url.Values{"days": {"1", "2"}, "start_time": {"18:00"}, "end_time": {"08:00"}, "end_day_mode": {"next"}, "end_weekday": {"1"}, csrfFormField: {viewer.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/rules", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.addedRules) != 0 {
		t.Fatalf("expected viewer rule add to be forbidden, status=%d added=%d", recorder.Code, len(store.addedRules))
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	form.Set(csrfFormField, freezer.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/rules", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=rules-added" {
		t.Fatalf("expected rule add redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.addedRules) != 1 {
		t.Fatalf("expected one add-rules call, got %+v", store.addedRules)
	}
	params := store.addedRules[0]
	if params.ScheduleID != 3 || len(params.Weekdays) != 2 || params.Weekdays[0] != time.Monday || params.Weekdays[1] != time.Tuesday ||
		params.StartTime != "18:00" || params.EndTime != "08:00" || params.EndDayMode != schedule.EndDayNext {
		t.Fatalf("unexpected add-rules params: %+v", params)
	}

	store.addRulesErr = schedule.ValidationError{Message: "an identical rule already exists on this schedule"}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/rules", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected validation error re-render, status=%d", recorder.Code)
	}
	for _, want := range []string{"an identical rule already exists on this schedule", `value="18:00"`, `value="08:00"`, `value="1" checked`, `value="2" checked`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected validation re-render to contain %q, got %q", want, body)
		}
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/999/rules", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for rules on unknown schedule, got %d", recorder.Code)
	}
}

func TestScheduleDetailRendersRulesAndPreview(t *testing.T) {
	store := &fakeScheduleStore{
		schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/Sao_Paulo"}},
		rules: map[int64][]domain.ScheduleWeeklyRule{3: {
			{ID: 101, ScheduleID: 3, StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "08:00"},
		}},
	}
	server := scheduleTestServer(store)

	recorder := getPageWithRoles(t, server, "/scheduled-freezes/schedules/3", auth.RoleSet{auth.RoleFreezer})
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d body=%q", recorder.Code, body)
	}
	for _, want := range []string{
		"Mon 18:00 → Tue 08:00", "next day",
		"/scheduled-freezes/schedules/3/rules/101/delete",
		"Coverage preview", "none of this happens yet", "Freeze periods as text",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected detail body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "No weekly rules yet") {
		t.Fatalf("expected the rules empty state to be replaced, got %q", body)
	}
}

func TestScheduleRuleDeleteRedirectsAndUnknownRuleIs404(t *testing.T) {
	store := &fakeScheduleStore{
		schedules: []domain.Schedule{{ID: 3, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}},
		rules: map[int64][]domain.ScheduleWeeklyRule{3: {
			{ID: 101, ScheduleID: 3, StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "08:00"},
		}},
	}
	server := scheduleTestServer(store)

	viewer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleViewer})
	form := url.Values{csrfFormField: {viewer.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/rules/101/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.removedRules) != 0 {
		t.Fatalf("expected viewer rule delete to be forbidden, status=%d removed=%d", recorder.Code, len(store.removedRules))
	}

	freezer := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleFreezer})
	form.Set(csrfFormField, freezer.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/rules/999/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown rule, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/scheduled-freezes/schedules/3/rules/101/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: freezer.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/scheduled-freezes/schedules/3?notice=rule-removed" {
		t.Fatalf("expected rule delete redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(store.removedRules) != 1 || store.removedRules[0] != 101 {
		t.Fatalf("unexpected removed rules: %+v", store.removedRules)
	}
}

func TestSchedulePreviewFromClipsBlocksPerDayAndKeepsTrueStartsInText(t *testing.T) {
	sched := domain.Schedule{ID: 3, Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"}
	rules := []domain.ScheduleWeeklyRule{{ID: 101, ScheduleID: 3, StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "06:00"}}
	// 2026-07-22 is a Wednesday: the window starts mid-week, after this
	// week's Monday rule already ended.
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

	preview, err := schedulePreviewFrom(sched, schedule.Coverage{Schedule: sched, Rules: rules}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Days) != 14 {
		t.Fatalf("expected 14 preview days, got %d", len(preview.Days))
	}
	if !preview.Days[0].Today || preview.Days[0].NowPercent != "50.00" {
		t.Fatalf("expected day 0 to be today at 50%%, got %+v", preview.Days[0])
	}
	// Mon Jul 27: block from 18:00 to midnight = left 75%, width 25%.
	monday := preview.Days[5]
	if monday.Label != "Mon 27" || len(monday.Blocks) != 1 || monday.Blocks[0].LeftPercent != "75.00" || monday.Blocks[0].WidthPercent != "25.00" {
		t.Fatalf("unexpected Monday cell: %+v", monday)
	}
	// Tue Jul 28: continuation block from midnight to 06:00 = left 0%, width 25%.
	tuesday := preview.Days[6]
	if tuesday.Label != "Tue 28" || len(tuesday.Blocks) != 1 || tuesday.Blocks[0].LeftPercent != "0.00" || tuesday.Blocks[0].WidthPercent != "25.00" {
		t.Fatalf("unexpected Tuesday cell: %+v", tuesday)
	}
	if len(preview.Segments) != 2 || preview.Segments[0] != "Mon 27 Jul 18:00 → Tue 28 Jul 06:00" {
		t.Fatalf("unexpected segment text: %+v", preview.Segments)
	}
	if len(preview.Notes) != 0 {
		t.Fatalf("expected no DST notes in a stable zone, got %+v", preview.Notes)
	}
}

func TestSchedulePreviewFromReportsSpringForwardNote(t *testing.T) {
	sched := domain.Schedule{ID: 3, Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "America/New_York"}
	rules := []domain.ScheduleWeeklyRule{{ID: 101, ScheduleID: 3, StartWeekday: time.Sunday, StartTime: "02:30", EndWeekday: time.Sunday, EndTime: "06:00"}}
	// Window covers Sunday 2026-03-08, when 02:30 EST does not exist.
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

	preview, err := schedulePreviewFrom(sched, schedule.Coverage{Schedule: sched, Rules: rules}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Notes) != 1 || preview.Notes[0].Tone != "warning" {
		t.Fatalf("expected one warning note, got %+v", preview.Notes)
	}
	want := "2026-03-08 02:30 does not exist (clocks move forward). Coverage starts at 03:00 that day."
	if preview.Notes[0].Message != want {
		t.Fatalf("expected note %q, got %q", want, preview.Notes[0].Message)
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
