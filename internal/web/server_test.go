package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

func TestRepositoriesPageShowsManualSetupContext(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}}}})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if sessionCookie := sessionCookieFromRecorder(t, recorder); sessionCookie.Value == "" {
		t.Fatal("expected session cookie value")
	}
	body := recorder.Body.String()
	if token := csrfTokenFromBody(t, body); token == "" {
		t.Fatal("expected CSRF token in repository form")
	}
	if !strings.Contains(body, domain.RequiredStatusContext) {
		t.Fatalf("expected body to mention required context %s", domain.RequiredStatusContext)
	}
	if !strings.Contains(body, "taua-almeida/thawguard") {
		t.Fatalf("expected body to include repository full name, got %q", body)
	}
}

func TestCreateRepositoryPostsToStore(t *testing.T) {
	store := &fakeRepositoryStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := repositoryCreateForm()
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.created) != 1 {
		t.Fatalf("expected 1 created repository, got %d", len(store.created))
	}
	if store.created[0].Owner != "taua-almeida" || store.created[0].Name != "thawguard" {
		t.Fatalf("unexpected create params: %+v", store.created[0])
	}
	if len(store.actors) != 1 {
		t.Fatalf("expected 1 actor, got %d", len(store.actors))
	}
	if store.actors[0].Kind != domain.ActorKindBootstrapAdmin || store.actors[0].Role != "admin" {
		t.Fatalf("unexpected actor: %+v", store.actors[0])
	}
}

func TestCreateRepositoryRejectsMissingCSRFSession(t *testing.T) {
	store := &fakeRepositoryStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := repositoryCreateForm()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.created) != 0 {
		t.Fatalf("expected no created repositories, got %d", len(store.created))
	}
}

func TestCreateRepositoryRejectsInvalidCSRFToken(t *testing.T) {
	store := &fakeRepositoryStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := repositoryCreateForm()
	cookie, _ := getRepositoryForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.created) != 0 {
		t.Fatalf("expected no created repositories, got %d", len(store.created))
	}
}

func TestRepositoriesPageShowsSetupHealthResults(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	checkedAt := time.Date(2026, 6, 29, 14, 0, 0, 0, time.UTC)
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		SetupCheckStore: &fakeSetupCheckStore{checks: map[int64][]setupcheck.Check{
			repo.ID: {
				{RepositoryID: repo.ID, Branch: "main", Result: setupcheck.Result{Name: "Bot can post statuses", Status: setupcheck.StatusOK, Description: "Thawguard can post statuses."}, CheckedAt: checkedAt},
				{RepositoryID: repo.ID, Branch: "main", Result: setupcheck.Result{Name: "Pull request webhook configured", Status: setupcheck.StatusFailed, Description: "Webhook missing.", Remediation: "Configure a pull_request webhook."}, CheckedAt: checkedAt},
			},
		}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Bot can post statuses", "ok", "Pull request webhook configured", "failed", "Record local setup placeholder", "placeholders until live Forgejo/Codeberg verification"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
}

func TestRunRepositorySetupCheckPostsToRunner(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	runner := &fakeSetupCheckRunner{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, SetupCheckRunner: runner})
	form := url.Values{"repository_id": {"1"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/setup-check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(runner.repositories) != 1 || runner.repositories[0].ID != repo.ID {
		t.Fatalf("expected setup check for repository %d, got %+v", repo.ID, runner.repositories)
	}
}

func TestRunRepositorySetupCheckRejectsMissingCSRFSession(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	runner := &fakeSetupCheckRunner{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, SetupCheckRunner: runner})
	form := url.Values{"repository_id": {"1"}}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/setup-check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(runner.repositories) != 0 {
		t.Fatalf("expected no setup check runs, got %d", len(runner.repositories))
	}
}

func TestRunRepositorySetupCheckRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	runner := &fakeSetupCheckRunner{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, SetupCheckRunner: runner})
	form := url.Values{"repository_id": {"1"}}
	cookie, _ := getRepositoryForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/setup-check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(runner.repositories) != 0 {
		t.Fatalf("expected no setup check runs, got %d", len(runner.repositories))
	}
}

func TestRunRepositorySetupCheckReportsRunnerError(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	runner := &fakeSetupCheckRunner{err: errors.New("setup check failed")}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, SetupCheckRunner: runner})
	form := url.Values{"repository_id": {"1"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/setup-check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway status, got %d", recorder.Code)
	}
}

func repositoryCreateForm() url.Values {
	return url.Values{
		"forge":          {"forgejo"},
		"base_url":       {"https://codeberg.org"},
		"owner":          {"taua-almeida"},
		"name":           {"thawguard"},
		"default_branch": {"main"},
	}
}

func getRepositoryForm(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected repository form status 200, got %d", recorder.Code)
	}
	return sessionCookieFromRecorder(t, recorder), csrfTokenFromBody(t, recorder.Body.String())
}

func sessionCookieFromRecorder(t *testing.T, recorder *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	t.Fatalf("expected %s cookie", sessionCookieName)
	return nil
}

func csrfTokenFromBody(t *testing.T, body string) string {
	t.Helper()
	matches := csrfInputPattern.FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("expected CSRF token field in body: %q", body)
	}
	return matches[1]
}

var csrfInputPattern = regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]+)"`)

type fakeRepositoryStore struct {
	repositories []domain.Repository
	created      []repository.CreateParams
	actors       []domain.Actor
}

type fakeSetupCheckStore struct {
	checks map[int64][]setupcheck.Check
}

func (s *fakeSetupCheckStore) ListByRepository(ctx context.Context, repositoryID int64) ([]setupcheck.Check, error) {
	return s.checks[repositoryID], nil
}

type fakeSetupCheckRunner struct {
	repositories []domain.Repository
	err          error
}

func (r *fakeSetupCheckRunner) Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.repositories = append(r.repositories, repo)
	return setupcheck.Evaluate(setupcheck.Report{}), nil
}

func (s *fakeRepositoryStore) List(ctx context.Context) ([]domain.Repository, error) {
	return s.repositories, nil
}

func (s *fakeRepositoryStore) Create(ctx context.Context, params repository.CreateParams, actor domain.Actor) (domain.Repository, error) {
	s.created = append(s.created, params)
	s.actors = append(s.actors, actor)
	repo := domain.Repository{ID: int64(len(s.repositories) + 1), Forge: params.Forge, BaseURL: params.BaseURL, Owner: params.Owner, Name: params.Name, DefaultBranch: params.DefaultBranch, Active: true}
	s.repositories = append(s.repositories, repo)
	return repo, nil
}
