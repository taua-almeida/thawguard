package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

func TestRepositoriesPageShowsManualSetupContext(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", HasWebhookSecret: true}}}, RepositorySecretEncryptionConfigured: true})
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
	for _, want := range []string{"Webhook secret", "configured", "Save webhook secret"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
}

func TestRepositoriesPageDisablesWebhookSecretFormWithoutEncryptionKey(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}}}})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Webhook secret storage is disabled", "THAWGUARD_SECRET_KEY</code> to save webhook secrets"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "Save webhook secret") || strings.Contains(body, `name="webhook_secret"`) {
		t.Fatalf("expected webhook secret form to be hidden, got %q", body)
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

func TestSetRepositoryWebhookSecretPostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, RepositorySecretEncryptionConfigured: true})
	form := url.Values{"repository_id": {"1"}, "webhook_secret": {"super-secret-value"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/webhook-secret", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.webhookSecrets) != 1 || store.webhookSecrets[0].repositoryID != repo.ID || store.webhookSecrets[0].secret != "super-secret-value" {
		t.Fatalf("expected webhook secret update, got %+v", store.webhookSecrets)
	}
	if len(store.webhookSecretActors) != 1 || store.webhookSecretActors[0].Kind != domain.ActorKindBootstrapAdmin || store.webhookSecretActors[0].Role != "admin" {
		t.Fatalf("unexpected actors: %+v", store.webhookSecretActors)
	}
}

func TestSetRepositoryWebhookSecretRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, RepositorySecretEncryptionConfigured: true})
	form := url.Values{"repository_id": {"1"}, "webhook_secret": {"super-secret-value"}}
	cookie, _ := getRepositoryForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/webhook-secret", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.webhookSecrets) != 0 {
		t.Fatalf("expected no webhook secret updates, got %+v", store.webhookSecrets)
	}
}

func TestSetRepositoryWebhookSecretDoesNotLeakInvalidSecret(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}, webhookSecretErr: repositorysetup.ValidationError{Message: "webhook secret must be at least 16 characters"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, RepositorySecretEncryptionConfigured: true})
	form := url.Values{"repository_id": {"1"}, "webhook_secret": {"short-secret"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/webhook-secret", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "short-secret") {
		t.Fatalf("expected submitted secret not to be rendered, got %q", body)
	}
	if !strings.Contains(body, "webhook secret must be at least 16 characters") {
		t.Fatalf("expected validation error, got %q", body)
	}
}

func TestSetRepositoryWebhookSecretReportsMissingEncryptionKey(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}, webhookSecretErr: repositorysetup.ConfigurationError{Message: "webhook secret encryption key is not configured"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := url.Values{"repository_id": {"1"}, "webhook_secret": {"super-secret-value"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/webhook-secret", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "super-secret-value") {
		t.Fatalf("expected submitted secret not to be rendered, got %q", body)
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

func TestFreezesPageShowsRepositoriesAndActiveFreezes(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "dev"}
	activeFreeze := domain.BranchFreeze{ID: 1, RepositoryID: repo.ID, Branch: "dev", Status: domain.BranchFreezeStatusActive, Active: true, Reason: "QA freeze"}
	auditEvent := audit.Event{
		Action:      audit.ActionBranchFreezeCreated,
		SubjectType: audit.SubjectTypeBranchFreeze,
		SubjectID:   "1",
		DetailsJSON: `{"actor_kind":"bootstrap_admin","actor_role":"admin","repository_id":"1","branch":"dev","status":"active","reason":"QA freeze"}`,
		CreatedAt:   time.Date(2026, 6, 29, 15, 30, 0, 0, time.UTC),
	}
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		FreezeStore:     &fakeFreezeStore{freezes: []domain.BranchFreeze{activeFreeze}},
		AuditStore:      &fakeAuditStore{events: []audit.Event{auditEvent}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if sessionCookie := sessionCookieFromRecorder(t, recorder); sessionCookie.Value == "" {
		t.Fatal("expected session cookie value")
	}
	body := recorder.Body.String()
	if token := csrfTokenFromBody(t, body); token == "" {
		t.Fatal("expected CSRF token in freeze form")
	}
	for _, want := range []string{"Create active freeze", "taua-almeida/thawguard", "default dev", "QA freeze", "Freeze branch", "End freeze", "Cancel", "Recent freeze audit events", "branch_freeze.created", "bootstrap_admin (admin)", "2026-06-29 15:30 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
}

func TestFreezesPageHidesNonFreezeAuditEvents(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		FreezeStore:     &fakeFreezeStore{},
		AuditStore: &fakeAuditStore{events: []audit.Event{
			{Action: audit.ActionRepositoryCreated, SubjectType: audit.SubjectTypeRepository, SubjectID: "1", DetailsJSON: `{"owner":"taua-almeida","name":"thawguard"}`, CreatedAt: time.Date(2026, 6, 29, 15, 30, 0, 0, time.UTC)},
		}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, audit.ActionRepositoryCreated) {
		t.Fatalf("expected repository audit events to be hidden, got %q", body)
	}
	if !strings.Contains(body, "No freeze audit events yet.") {
		t.Fatalf("expected empty freeze audit state, got %q", body)
	}
}

func TestFreezesPageHidesUnknownFreezeAuditActions(t *testing.T) {
	server := NewServer(Config{
		AppName:     "Thawguard",
		FreezeStore: &fakeFreezeStore{},
		AuditStore: &fakeAuditStore{events: []audit.Event{
			{Action: "branch_freeze.internal", SubjectType: audit.SubjectTypeBranchFreeze, SubjectID: "1", DetailsJSON: `{"branch":"main"}`, CreatedAt: time.Date(2026, 6, 29, 15, 30, 0, 0, time.UTC)},
		}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "branch_freeze.internal") {
		t.Fatalf("expected unknown freeze action to be hidden, got %q", body)
	}
	if !strings.Contains(body, "No freeze audit events yet.") {
		t.Fatalf("expected empty freeze audit state, got %q", body)
	}
}

func TestFreezesPageDoesNotRenderRawAuditJSON(t *testing.T) {
	server := NewServer(Config{
		AppName:     "Thawguard",
		FreezeStore: &fakeFreezeStore{},
		AuditStore: &fakeAuditStore{events: []audit.Event{
			{Action: audit.ActionBranchFreezeCreated, SubjectType: audit.SubjectTypeBranchFreeze, SubjectID: "1", DetailsJSON: `not-json-with-secret-token`, CreatedAt: time.Date(2026, 6, 29, 15, 30, 0, 0, time.UTC)},
		}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, "not-json") {
		t.Fatalf("expected raw audit JSON to be hidden, got %q", body)
	}
	if !strings.Contains(body, audit.ActionBranchFreezeCreated) {
		t.Fatalf("expected audit action to still render, got %q", body)
	}
}

func TestCreateFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCreateForm()
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.created) != 1 {
		t.Fatalf("expected 1 freeze creation, got %d", len(store.created))
	}
	if store.created[0].RepositoryID != repo.ID || store.created[0].Branch != "main" || store.created[0].Reason != "release window" {
		t.Fatalf("unexpected freeze params: %+v", store.created[0])
	}
	if len(store.actors) != 1 || store.actors[0].Kind != domain.ActorKindBootstrapAdmin || store.actors[0].Role != "admin" {
		t.Fatalf("unexpected actors: %+v", store.actors)
	}
}

func TestCreateFreezeRejectsMissingCSRFSession(t *testing.T) {
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", FreezeStore: store})
	form := freezeCreateForm()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.created) != 0 {
		t.Fatalf("expected no created freezes, got %d", len(store.created))
	}
}

func TestCreateFreezeRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCreateForm()
	cookie, _ := getFreezeForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.created) != 0 {
		t.Fatalf("expected no created freezes, got %d", len(store.created))
	}
}

func TestCreateFreezeShowsValidationError(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{err: freeze.ValidationError{Message: "branch is already frozen"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCreateForm()
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request status, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "branch is already frozen") {
		t.Fatalf("expected validation message in body, got %q", recorder.Body.String())
	}
}

func TestEndFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{freezes: []domain.BranchFreeze{{ID: 9, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true, Reason: "release"}}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCloseForm(9)
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/end", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.ended) != 1 || store.ended[0] != 9 {
		t.Fatalf("expected freeze 9 to end, got %+v", store.ended)
	}
	if len(store.actors) != 1 || store.actors[0].Kind != domain.ActorKindBootstrapAdmin || store.actors[0].Role != "admin" {
		t.Fatalf("unexpected actors: %+v", store.actors)
	}
}

func TestCancelFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{freezes: []domain.BranchFreeze{{ID: 9, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true, Reason: "mistake"}}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCloseForm(9)
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/cancel", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.cancelled) != 1 || store.cancelled[0] != 9 {
		t.Fatalf("expected freeze 9 to cancel, got %+v", store.cancelled)
	}
}

func TestEndFreezeRejectsMissingCSRFSession(t *testing.T) {
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", FreezeStore: store})
	form := freezeCloseForm(9)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/end", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.ended) != 0 {
		t.Fatalf("expected no ended freezes, got %d", len(store.ended))
	}
}

func TestEndFreezeRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCloseForm(9)
	cookie, _ := getFreezeForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/end", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.ended) != 0 {
		t.Fatalf("expected no ended freezes, got %d", len(store.ended))
	}
}

func TestCancelFreezeRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCloseForm(9)
	cookie, _ := getFreezeForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/cancel", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.cancelled) != 0 {
		t.Fatalf("expected no cancelled freezes, got %d", len(store.cancelled))
	}
}

func TestEndFreezeShowsValidationError(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{err: freeze.ValidationError{Message: "freeze is not active"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCloseForm(9)
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/end", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request status, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "freeze is not active") {
		t.Fatalf("expected validation message in body, got %q", recorder.Body.String())
	}
}

func TestEndFreezeHidesInternalErrorDetails(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeFreezeStore{err: errors.New("database failed with secret-token")}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCloseForm(9)
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes/end", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal server error status, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("expected generic error body, got %q", recorder.Body.String())
	}
}

func TestDecisionsPageShowsFormAndRecentResults(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	createdAt := time.Date(2026, 6, 29, 16, 30, 0, 0, time.UTC)
	result := statusresult.Result{ID: 1, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", CreatedAt: createdAt}
	server := NewServer(Config{
		AppName:             "Thawguard",
		RepositoryStore:     &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		StatusDecisionStore: &fakeStatusDecisionStore{results: []statusresult.Result{result}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/decisions", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if sessionCookie := sessionCookieFromRecorder(t, recorder); sessionCookie.Value == "" {
		t.Fatal("expected session cookie value")
	}
	body := recorder.Body.String()
	if token := csrfTokenFromBody(t, body); token == "" {
		t.Fatal("expected CSRF token in decision form")
	}
	for _, want := range []string{"Compute PR decision", "local preview only", "taua-almeida/thawguard", "Target branch", "main", "thawguard/freeze", "failure", "Branch is frozen", "2026-06-29 16:30 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
}

func TestDecisionsPageRequiresStatusDecisionStore(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/decisions", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable status, got %d", recorder.Code)
	}
}

func TestCreateDecisionPostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeStatusDecisionStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	cookie, csrfToken := getDecisionForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.runs) != 1 {
		t.Fatalf("expected 1 local decision run, got %d", len(store.runs))
	}
	run := store.runs[0]
	if run.RepositoryID != repo.ID || run.PullRequestIndex != 42 || run.TargetBranch != "main" || run.HeadSHA != "abc123" {
		t.Fatalf("unexpected local decision params: %+v", run)
	}
}

func TestCreateDecisionRejectsMissingCSRFSession(t *testing.T) {
	store := &fakeStatusDecisionStore{}
	server := NewServer(Config{AppName: "Thawguard", StatusDecisionStore: store})
	form := decisionCreateForm()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.runs) != 0 {
		t.Fatalf("expected no local decision runs, got %d", len(store.runs))
	}
}

func TestCreateDecisionRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeStatusDecisionStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	cookie, _ := getDecisionForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.runs) != 0 {
		t.Fatalf("expected no local decision runs, got %d", len(store.runs))
	}
}

func TestCreateDecisionShowsValidationError(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeStatusDecisionStore{err: statusresult.ValidationError{Message: "missing required local decision fields: head SHA"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	cookie, csrfToken := getDecisionForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request status, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "missing required local decision fields") {
		t.Fatalf("expected validation message in body, got %q", recorder.Body.String())
	}
}

func TestCreateDecisionHidesInternalErrorDetails(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeStatusDecisionStore{err: errors.New("database failed with secret-token")}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	cookie, csrfToken := getDecisionForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal server error status, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("expected generic error body, got %q", recorder.Body.String())
	}
}

func TestPublicationsPageShowsRecentPublicationIntents(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	createdAt := time.Date(2026, 6, 29, 17, 30, 0, 0, time.UTC)
	publication := statuspublication.Publication{ID: 1, StatusResultID: 7, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", DeliveryMode: statuspublication.DeliveryModeLocalRecord, CreatedAt: createdAt, UpdatedAt: createdAt}
	attempt := statuspublication.Attempt{ID: 1, PublicationID: publication.ID, StatusResultID: publication.StatusResultID, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", Mode: statuspublication.AttemptModeDryRun, Result: statuspublication.AttemptResultPlanned, AttemptedAt: createdAt.Add(time.Minute)}
	server := NewServer(Config{
		AppName:                "Thawguard",
		RepositoryStore:        &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		StatusPublicationStore: &fakeStatusPublicationStore{publications: []statuspublication.Publication{publication}, attempts: []statuspublication.Attempt{attempt}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/publications", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if sessionCookie := sessionCookieFromRecorder(t, recorder); sessionCookie.Value == "" {
		t.Fatal("expected session cookie value")
	}
	body := recorder.Body.String()
	for _, want := range []string{"Status publication intents", "No status has been posted", "Recent dry-run publication attempts", "do not call Forgejo/Codeberg", "taua-almeida/thawguard", "#42", "main", "abc123", "thawguard/freeze", "failure", "local_record", "dry_run", "planned", "Branch is frozen", "2026-06-29 17:30 UTC", "2026-06-29 17:31 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
}

func TestPublicationsPageRequiresStatusPublicationStore(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/publications", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable status, got %d", recorder.Code)
	}
}

func TestPublicationsPageHidesInternalErrorDetails(t *testing.T) {
	store := &fakeStatusPublicationStore{err: errors.New("database failed with secret-token")}
	server := NewServer(Config{AppName: "Thawguard", StatusPublicationStore: store})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/publications", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal server error status, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("expected generic error body, got %q", recorder.Body.String())
	}
}

func TestWebhooksPageShowsRecentDeliveries(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	receivedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	claimedAt := receivedAt.Add(30 * time.Second)
	processedAt := receivedAt.Add(time.Minute)
	deliveries := []webhook.Delivery{
		{ID: 1, RepositoryID: repo.ID, DeliveryID: "delivery-processed", Event: "pull_request", Action: "opened", ReceivedAt: receivedAt, Verified: true, ProcessedAt: &processedAt},
		{ID: 2, RepositoryID: repo.ID, DeliveryID: "delivery-retry", Event: "pull_request", Action: "synchronized", ReceivedAt: receivedAt.Add(2 * time.Minute), Verified: true, Error: "webhook processing failed"},
		{ID: 3, RepositoryID: repo.ID, DeliveryID: "delivery-processing", Event: "pull_request", ReceivedAt: receivedAt.Add(3 * time.Minute), Verified: true, ProcessingStartedAt: &claimedAt},
	}
	server := NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore: &fakeWebhookDeliveryStore{listed: deliveries},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if sessionCookie := sessionCookieFromRecorder(t, recorder); sessionCookie.Value == "" {
		t.Fatal("expected session cookie value")
	}
	body := recorder.Body.String()
	for _, want := range []string{"Webhook deliveries", "sanitized local delivery metadata", "taua-almeida/thawguard", "delivery-processed", "pull_request", "opened", "verified", "processed", "delivery-retry", "synchronized", "retryable failure", "webhook processing failed", "delivery-processing", "processing", "2026-06-30 12:00 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "raw webhook payload:") || strings.Contains(body, "X-Hub-Signature") {
		t.Fatalf("expected page not to render raw webhook details, got %q", body)
	}
}

func TestWebhooksPageRequiresDeliveryStore(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable status, got %d", recorder.Code)
	}
}

func TestWebhooksPageHidesInternalErrorDetails(t *testing.T) {
	store := &fakeWebhookDeliveryStore{listErr: errors.New("database failed with secret-token")}
	server := NewServer(Config{AppName: "Thawguard", WebhookDeliveryStore: store})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal server error status, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("expected generic error body, got %q", recorder.Body.String())
	}
}

func TestForgejoWebhookProcessesValidSignedPullRequest(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-1"))

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted\n" {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(processor.bodies) != 1 || string(processor.bodies[0]) != body {
		t.Fatalf("expected processor to receive body once, got %+v", processor.bodies)
	}
	if len(deliveryStore.records) != 1 || deliveryStore.records[0].RepositoryID != repo.ID || deliveryStore.records[0].DeliveryID != "delivery-1" || !deliveryStore.records[0].Verified {
		t.Fatalf("unexpected delivery records: %+v", deliveryStore.records)
	}
	if len(deliveryStore.processed) != 1 || deliveryStore.processed[0].params.Error != "" || deliveryStore.processed[0].params.Action != "opened" {
		t.Fatalf("unexpected processed deliveries: %+v", deliveryStore.processed)
	}
}

func TestForgejoWebhookRejectsInvalidSignatureGenerically(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "wrong-secret-value", "delivery-1"))

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted\n" {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(processor.bodies) != 0 || len(deliveryStore.records) != 0 {
		t.Fatalf("expected no processing or delivery record, processor=%d records=%d", len(processor.bodies), len(deliveryStore.records))
	}
	if strings.Contains(recorder.Body.String(), "super-secret-value") || strings.Contains(recorder.Body.String(), "signature") {
		t.Fatalf("expected response not to leak verification details, got %q", recorder.Body.String())
	}
}

func TestForgejoWebhookReturnsGenericResponseForUnknownRepository(t *testing.T) {
	repositoryStore := &fakeWebhookRepositoryStore{found: false}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-1"))

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted\n" {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(processor.bodies) != 0 || len(deliveryStore.records) != 0 {
		t.Fatalf("expected no processing or delivery record, processor=%d records=%d", len(processor.bodies), len(deliveryStore.records))
	}
}

func TestForgejoWebhookIgnoresDuplicateDeliveryID(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")

	for range 2 {
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-1"))
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	}
	if len(processor.bodies) != 1 || len(deliveryStore.records) != 1 || len(deliveryStore.processed) != 1 {
		t.Fatalf("expected duplicate not to reprocess, processor=%d records=%d processed=%d", len(processor.bodies), len(deliveryStore.records), len(deliveryStore.processed))
	}
}

func TestForgejoWebhookRetriesPreviouslyUnprocessedDuplicateDelivery(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	if _, err := deliveryStore.Record(context.Background(), webhook.DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: "delivery-unprocessed", Event: "pull_request", Action: "opened", Verified: true}); err != nil {
		t.Fatal(err)
	}
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-unprocessed"))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(processor.bodies) != 1 || len(deliveryStore.records) != 1 || len(deliveryStore.processed) != 1 {
		t.Fatalf("expected unprocessed duplicate retry, processor=%d records=%d processed=%d", len(processor.bodies), len(deliveryStore.records), len(deliveryStore.processed))
	}
}

func TestForgejoWebhookRecordsProcessorErrorWithoutLeakingDetails(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{err: errors.New("database failed with secret-token")}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-failing"))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal server error response for retryable processing failure, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("expected generic error body, got %q", recorder.Body.String())
	}
	if len(deliveryStore.failed) != 1 || deliveryStore.failed[0].message != "webhook processing failed" {
		t.Fatalf("expected sanitized processing failure delivery, processed=%+v failed=%+v", deliveryStore.processed, deliveryStore.failed)
	}
	if len(deliveryStore.processed) != 0 {
		t.Fatalf("expected retryable processing failure not to be terminally processed, got %+v", deliveryStore.processed)
	}
}

func TestForgejoWebhookRecordsUnsupportedVerifiedPullRequestAction(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("assigned")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-unsupported"))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(processor.bodies) != 0 {
		t.Fatalf("expected unsupported action not to process, got %d calls", len(processor.bodies))
	}
	if len(deliveryStore.records) != 1 || len(deliveryStore.processed) != 1 || deliveryStore.processed[0].params.Error != "unsupported pull_request action" {
		t.Fatalf("expected verified unsupported action delivery error, records=%+v processed=%+v", deliveryStore.records, deliveryStore.processed)
	}
}

func TestForgejoWebhookIgnoresUnsupportedEventHeader(t *testing.T) {
	repo := domain.Repository{ID: 1, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main", HasWebhookSecret: true}
	repositoryStore := &fakeWebhookRepositoryStore{repo: repo, secret: "super-secret-value", found: true, secretFound: true}
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: repositoryStore, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor})
	body := pullRequestWebhookBody("opened")
	request := signedWebhookRequest(t, body, "super-secret-value", "delivery-push")
	request.Header.Set("X-Gitea-Event", "push")

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(processor.bodies) != 0 || len(deliveryStore.records) != 0 {
		t.Fatalf("expected unsupported event not to process or record, processor=%d records=%d", len(processor.bodies), len(deliveryStore.records))
	}
}

func TestForgejoWebhookRejectsOversizedPayload(t *testing.T) {
	deliveryStore := newFakeWebhookDeliveryStore()
	processor := &fakePullRequestWebhookProcessor{}
	server := NewServer(Config{AppName: "Thawguard", WebhookRepositoryStore: &fakeWebhookRepositoryStore{}, WebhookDeliveryStore: deliveryStore, PullRequestWebhookProcessor: processor, WebhookMaxBodyBytes: 8})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, pullRequestWebhookBody("opened"), "super-secret-value", "delivery-large"))

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected payload too large status, got %d", recorder.Code)
	}
	if len(processor.bodies) != 0 || len(deliveryStore.records) != 0 {
		t.Fatalf("expected oversized payload not to process or record, processor=%d records=%d", len(processor.bodies), len(deliveryStore.records))
	}
}

func decisionCreateForm() url.Values {
	return url.Values{
		"repository_id":      {"1"},
		"pull_request_index": {"42"},
		"target_branch":      {"main"},
		"head_sha":           {"abc123"},
	}
}

func freezeCloseForm(id int64) url.Values {
	return url.Values{"freeze_id": {strconv.FormatInt(id, 10)}}
}

func freezeCreateForm() url.Values {
	return url.Values{
		"repository_id": {"1"},
		"branch":        {"main"},
		"reason":        {"release window"},
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

func getFreezeForm(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected freeze form status 200, got %d", recorder.Code)
	}
	return sessionCookieFromRecorder(t, recorder), csrfTokenFromBody(t, recorder.Body.String())
}

func getDecisionForm(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/decisions", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected decision form status 200, got %d", recorder.Code)
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

func pullRequestWebhookBody(action string) string {
	return strings.ReplaceAll(`{
  "action": "{{ACTION}}",
  "repository": {
    "owner": { "login": "example-owner" },
    "name": "example-repo",
    "full_name": "example-owner/example-repo",
    "clone_url": "https://codeberg.org/example-owner/example-repo.git"
  },
  "pull_request": {
    "number": 42,
    "title": "Example bug fix",
    "state": "open",
    "html_url": "https://codeberg.org/example-owner/example-repo/pulls/42",
    "base": { "ref": "main" },
    "head": { "sha": "0123456789abcdef0123456789abcdef01234567" }
  }
}`, "{{ACTION}}", action)
}

func signedWebhookRequest(t *testing.T, body string, secret string, deliveryID string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/webhooks/forgejo", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Gitea-Event", "pull_request")
	request.Header.Set("X-Gitea-Signature", "sha256="+webhookSignature(body, secret))
	if deliveryID != "" {
		request.Header.Set("X-Gitea-Delivery", deliveryID)
	}
	return request
}

func webhookSignature(body string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

type fakeWebhookRepositoryStore struct {
	repo         domain.Repository
	secret       string
	found        bool
	secretFound  bool
	findErr      error
	secretErr    error
	remoteParams []repository.RemoteParams
}

func (s *fakeWebhookRepositoryStore) FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error) {
	s.remoteParams = append(s.remoteParams, params)
	if s.findErr != nil {
		return domain.Repository{}, false, s.findErr
	}
	return s.repo, s.found, nil
}

func (s *fakeWebhookRepositoryStore) WebhookSecret(ctx context.Context, repositoryID int64) (string, bool, error) {
	if s.secretErr != nil {
		return "", false, s.secretErr
	}
	return s.secret, s.secretFound, nil
}

type fakePullRequestWebhookProcessor struct {
	bodies [][]byte
	err    error
}

func (p *fakePullRequestWebhookProcessor) Process(ctx context.Context, body []byte) (webhook.PullRequestProcessResult, error) {
	copyBody := make([]byte, len(body))
	copy(copyBody, body)
	p.bodies = append(p.bodies, copyBody)
	if p.err != nil {
		return webhook.PullRequestProcessResult{}, p.err
	}
	return webhook.PullRequestProcessResult{}, nil
}

type fakeWebhookDeliveryStore struct {
	nextID       int64
	records      []webhook.DeliveryRecordParams
	claims       []int64
	processed    []fakeWebhookProcessedDelivery
	failed       []fakeWebhookFailedDelivery
	listed       []webhook.Delivery
	listErr      error
	deliveries   map[int64]webhook.Delivery
	deliveryByID map[string]int64
}

type fakeWebhookProcessedDelivery struct {
	id     int64
	params webhook.DeliveryProcessParams
}

type fakeWebhookFailedDelivery struct {
	id      int64
	message string
}

func newFakeWebhookDeliveryStore() *fakeWebhookDeliveryStore {
	return &fakeWebhookDeliveryStore{deliveries: make(map[int64]webhook.Delivery), deliveryByID: make(map[string]int64)}
}

func (s *fakeWebhookDeliveryStore) ListRecent(ctx context.Context, limit int) ([]webhook.Delivery, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	if limit > 0 && len(s.listed) > limit {
		return s.listed[:limit], nil
	}
	return s.listed, nil
}

func (s *fakeWebhookDeliveryStore) Record(ctx context.Context, params webhook.DeliveryRecordParams) (webhook.Delivery, error) {
	key := fakeWebhookDeliveryKey(params.RepositoryID, params.DeliveryID)
	if existingID, found := s.deliveryByID[key]; found {
		return s.deliveries[existingID], webhook.ValidationError{Message: "webhook delivery already recorded"}
	}
	s.nextID++
	delivery := webhook.Delivery{ID: s.nextID, RepositoryID: params.RepositoryID, DeliveryID: params.DeliveryID, Event: params.Event, Action: params.Action, Verified: params.Verified}
	s.deliveryByID[key] = delivery.ID
	s.deliveries[delivery.ID] = delivery
	s.records = append(s.records, params)
	return delivery, nil
}

func (s *fakeWebhookDeliveryStore) ClaimForProcessing(ctx context.Context, id int64) (webhook.Delivery, bool, error) {
	delivery := s.deliveries[id]
	if delivery.ID == 0 {
		return webhook.Delivery{}, false, nil
	}
	if delivery.ProcessingStartedAt != nil || delivery.ProcessedAt != nil {
		return delivery, false, nil
	}
	now := time.Now().UTC()
	delivery.ProcessingStartedAt = &now
	delivery.Error = ""
	s.deliveries[id] = delivery
	s.claims = append(s.claims, id)
	return delivery, true, nil
}

func (s *fakeWebhookDeliveryStore) MarkProcessed(ctx context.Context, id int64, params webhook.DeliveryProcessParams) (webhook.Delivery, error) {
	delivery := s.deliveries[id]
	if delivery.ProcessingStartedAt == nil || params.ProcessingStartedAt == nil || !delivery.ProcessingStartedAt.Equal(*params.ProcessingStartedAt) {
		return webhook.Delivery{}, errors.New("delivery claim mismatch")
	}
	delivery.RepositoryID = params.RepositoryID
	delivery.Action = params.Action
	delivery.Error = params.Error
	processedAt := time.Now().UTC()
	delivery.ProcessingStartedAt = nil
	delivery.ProcessedAt = &processedAt
	s.deliveries[id] = delivery
	s.processed = append(s.processed, fakeWebhookProcessedDelivery{id: id, params: params})
	return delivery, nil
}

func (s *fakeWebhookDeliveryStore) MarkProcessingFailed(ctx context.Context, id int64, message string, processingStartedAt time.Time) (webhook.Delivery, error) {
	delivery := s.deliveries[id]
	if delivery.ProcessingStartedAt == nil || !delivery.ProcessingStartedAt.Equal(processingStartedAt) {
		return webhook.Delivery{}, errors.New("delivery claim mismatch")
	}
	delivery.ProcessingStartedAt = nil
	delivery.ProcessedAt = nil
	delivery.Error = message
	s.deliveries[id] = delivery
	s.failed = append(s.failed, fakeWebhookFailedDelivery{id: id, message: message})
	return delivery, nil
}

func fakeWebhookDeliveryKey(repositoryID int64, deliveryID string) string {
	return strconv.FormatInt(repositoryID, 10) + ":" + deliveryID
}

type fakeRepositoryStore struct {
	repositories        []domain.Repository
	created             []repository.CreateParams
	actors              []domain.Actor
	webhookSecrets      []webhookSecretUpdate
	webhookSecretActors []domain.Actor
	webhookSecretErr    error
}

type webhookSecretUpdate struct {
	repositoryID int64
	secret       string
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

type fakeStatusDecisionStore struct {
	results []statusresult.Result
	runs    []statusresult.LocalDecisionParams
	err     error
	listErr error
}

func (s *fakeStatusDecisionStore) ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	if limit > 0 && len(s.results) > limit {
		return s.results[:limit], nil
	}
	return s.results, nil
}

func (s *fakeStatusDecisionStore) RunLocal(ctx context.Context, params statusresult.LocalDecisionParams) (statusresult.Result, error) {
	if s.err != nil {
		return statusresult.Result{}, s.err
	}
	s.runs = append(s.runs, params)
	result := statusresult.Result{ID: int64(len(s.results) + 1), RepositoryID: params.RepositoryID, PullRequestIndex: params.PullRequestIndex, TargetBranch: params.TargetBranch, HeadSHA: params.HeadSHA, Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "No active freeze applies to this PR", CreatedAt: time.Now().UTC()}
	s.results = append(s.results, result)
	return result, nil
}

type fakeStatusPublicationStore struct {
	publications []statuspublication.Publication
	attempts     []statuspublication.Attempt
	err          error
	attemptErr   error
}

func (s *fakeStatusPublicationStore) ListRecent(ctx context.Context, limit int) ([]statuspublication.Publication, error) {
	if s.err != nil {
		return nil, s.err
	}
	if limit > 0 && len(s.publications) > limit {
		return s.publications[:limit], nil
	}
	return s.publications, nil
}

func (s *fakeStatusPublicationStore) ListRecentAttempts(ctx context.Context, limit int) ([]statuspublication.Attempt, error) {
	if s.attemptErr != nil {
		return nil, s.attemptErr
	}
	if s.err != nil {
		return nil, s.err
	}
	if limit > 0 && len(s.attempts) > limit {
		return s.attempts[:limit], nil
	}
	return s.attempts, nil
}

type fakeAuditStore struct {
	events               []audit.Event
	err                  error
	requestedSubjectType string
}

func (s *fakeAuditStore) ListBySubjectType(ctx context.Context, subjectType string, limit int) ([]audit.Event, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.requestedSubjectType = subjectType
	filtered := make([]audit.Event, 0, len(s.events))
	for _, event := range s.events {
		if event.SubjectType == subjectType {
			filtered = append(filtered, event)
		}
	}
	if limit > 0 && len(filtered) > limit {
		return filtered[:limit], nil
	}
	return filtered, nil
}

type fakeFreezeStore struct {
	freezes   []domain.BranchFreeze
	created   []freeze.CreateParams
	ended     []int64
	cancelled []int64
	actors    []domain.Actor
	err       error
}

func (s *fakeFreezeStore) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	return s.freezes, nil
}

func (s *fakeFreezeStore) CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.created = append(s.created, params)
	s.actors = append(s.actors, actor)
	created := domain.BranchFreeze{ID: int64(len(s.freezes) + 1), RepositoryID: params.RepositoryID, Branch: params.Branch, Status: domain.BranchFreezeStatusActive, Active: true, Reason: params.Reason}
	s.freezes = append(s.freezes, created)
	return created, nil
}

func (s *fakeFreezeStore) End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.ended = append(s.ended, id)
	s.actors = append(s.actors, actor)
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusEnded}, nil
}

func (s *fakeFreezeStore) Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.cancelled = append(s.cancelled, id)
	s.actors = append(s.actors, actor)
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusCancelled}, nil
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

func (s *fakeRepositoryStore) SetWebhookSecret(ctx context.Context, repositoryID int64, secret string, actor domain.Actor) (domain.Repository, error) {
	if s.webhookSecretErr != nil {
		return domain.Repository{}, s.webhookSecretErr
	}
	s.webhookSecrets = append(s.webhookSecrets, webhookSecretUpdate{repositoryID: repositoryID, secret: secret})
	s.webhookSecretActors = append(s.webhookSecretActors, actor)
	for index, repo := range s.repositories {
		if repo.ID == repositoryID {
			s.repositories[index].HasWebhookSecret = true
			return s.repositories[index], nil
		}
	}
	return domain.Repository{}, repositorysetup.ValidationError{Message: "repository not found"}
}
