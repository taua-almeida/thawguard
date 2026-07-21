package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge/forgejo"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/secrets"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statuspublisher"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

func TestRepositoriesPageShowsManualSetupContext(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true}}}, RepositorySecretEncryptionConfigured: true})
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
	for _, want := range []string{"webhook configured", "status token configured", "Rotate secret", "Rotate token", "Add repository", "Credential values are write-only", `<dialog id="connect-repository"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
}

func TestAuthRedirectsToFirstAdminSetupBeforeUsersExist(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	server := NewServer(Config{AppName: "Thawguard", AuthService: auth.NewService(database)})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/setup" {
		t.Fatalf("expected redirect to setup, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected setup form, got %d", recorder.Code)
	}
	namedCookieFromRecorder(t, recorder, setupCookieName)
	setupBody := recorder.Body.String()
	if !strings.Contains(setupBody, "#tg-i-icy-shield") || strings.Contains(setupBody, ">TG</span>") {
		t.Fatalf("expected setup page to use shield brand icon, body=%q", setupBody)
	}
	setupCSRF := csrfTokenFromBody(t, setupBody)

	form := url.Values{"email": {"admin@example.test"}, "display_name": {"Admin"}, "password": {"correct horse battery staple"}, csrfFormField: {setupCSRF}}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(&http.Cookie{Name: setupCookieName, Value: "stale-token"})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" {
		t.Fatalf("expected first admin setup redirect, status=%d location=%q body=%q", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	cookie := sessionCookieFromRecorder(t, recorder)

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "admin@example.test") {
		t.Fatalf("expected dashboard for configured admin, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestFirstAdminSetupRejectsMissingCSRFToken(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	server := NewServer(Config{AppName: "Thawguard", AuthService: auth.NewService(database)})
	form := url.Values{"email": {"admin@example.test"}, "display_name": {"Admin"}, "password": {"correct horse battery staple"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected setup without csrf to be forbidden, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Setup form expired") || !strings.Contains(body, "Create the first admin") {
		t.Fatalf("expected setup csrf failure to re-render setup form, body=%q", body)
	}
	if !strings.Contains(body, `value="admin@example.test"`) || !strings.Contains(body, `value="Admin"`) {
		t.Fatalf("expected setup csrf failure to preserve email and display name, body=%q", body)
	}
	refreshedCookie := namedCookieFromRecorder(t, recorder, setupCookieName)
	refreshedCSRF := csrfTokenFromBody(t, body)
	if refreshedCookie.Value != refreshedCSRF {
		t.Fatalf("expected refreshed setup cookie to match rendered csrf token")
	}
}

func TestFirstAdminSetupRejectsUnsignedInjectedCSRFToken(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{"email": {"admin@example.test"}, "display_name": {"Admin"}, "password": {"correct horse battery staple"}, csrfFormField: {"known-token"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(&http.Cookie{Name: setupCookieName, Value: "known-token"})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected unsigned injected csrf token to be forbidden, got %d", recorder.Code)
	}
	hasUsers, err := authService.HasUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hasUsers {
		t.Fatal("expected forged setup csrf to leave database without users")
	}
}

func TestFirstAdminSetupRefreshesCSRFAfterValidationError(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	server := NewServer(Config{AppName: "Thawguard", AuthService: auth.NewService(database)})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/setup", nil))
	setupCookie := namedCookieFromRecorder(t, recorder, setupCookieName)
	setupCSRF := csrfTokenFromBody(t, recorder.Body.String())

	form := url.Values{"email": {"admin@example.test"}, "display_name": {"Admin"}, "password": {"short"}, csrfFormField: {setupCSRF}}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(setupCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected validation error status, got %d", recorder.Code)
	}
	refreshedCookie := namedCookieFromRecorder(t, recorder, setupCookieName)
	refreshedCSRF := csrfTokenFromBody(t, recorder.Body.String())
	if refreshedCookie.Value != refreshedCSRF {
		t.Fatalf("expected refreshed setup cookie to match rendered csrf token")
	}

	form.Set("password", "correct horse battery staple")
	form.Set(csrfFormField, refreshedCSRF)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(refreshedCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected corrected setup to succeed, got %d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestLoginAndLogoutUsePersistentSessions(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	if _, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected unauthenticated redirect to login, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}

	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected login form, got %d", recorder.Code)
	}
	loginCookie := namedCookieFromRecorder(t, recorder, loginCookieName)
	loginCSRF := csrfTokenFromBody(t, recorder.Body.String())

	form := url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}, csrfFormField: {loginCSRF}}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(loginCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" {
		t.Fatalf("expected login redirect, status=%d location=%q body=%q", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	cookie := sessionCookieFromRecorder(t, recorder)

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected authenticated dashboard, got %d", recorder.Code)
	}
	csrfToken := csrfTokenFromBody(t, recorder.Body.String())
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "stale-session"})
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected authenticated dashboard with stale session cookie first, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(url.Values{csrfFormField: {csrfToken}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected logout redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if _, found, err := authService.SessionByID(ctx, cookie.Value); err != nil || found {
		t.Fatalf("expected session to be removed after logout, found=%v err=%v", found, err)
	}
}

func TestLoginRejectsCrossOriginSignedCSRFToken(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	if _, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	loginCSRF := csrfTokenFromBody(t, recorder.Body.String())

	form := url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}, csrfFormField: {loginCSRF}}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://attacker.example")
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin login post to be forbidden, got %d", recorder.Code)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			t.Fatalf("expected cross-origin login to avoid setting session cookie, got %q", cookie.Value)
		}
	}
}

func TestLoginRejectsMissingCSRFToken(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	if _, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected login without csrf to be forbidden, got %d", recorder.Code)
	}
}

func TestUsersPageCreatesUsersAndViewerCannotManageRepositories(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	adminSession, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeSetupCheckRunner{}
	repositoryStore := &fakeRepositoryStore{repositories: []domain.Repository{{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}}}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, RepositoryStore: repositoryStore, SetupCheckRunner: runner})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: adminSession.ID}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/users", nil)
	request.AddCookie(adminCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Users &amp; Roles") {
		t.Fatalf("expected users page for admin, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	csrfToken := csrfTokenFromBody(t, recorder.Body.String())

	form := url.Values{"email": {"viewer@example.test"}, "display_name": {"Viewer"}, "password": {"correct horse battery staple"}, "roles": {string(auth.RoleViewer)}, csrfFormField: {csrfToken}}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected user create redirect, got %d body=%q", recorder.Code, recorder.Body.String())
	}

	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	viewerCookie := &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/repositories", nil)
	request.AddCookie(viewerCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "Users &amp; Roles") {
		t.Fatalf("expected viewer to read repositories without admin nav, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "Run readiness checks") {
		t.Fatalf("expected viewer readiness evidence to be read-only, got %q", recorder.Body.String())
	}
	form = repositoryCreateForm()
	form.Set(csrfFormField, viewerSession.CSRFToken)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/repositories", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(viewerCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected viewer repository create to be forbidden, got %d", recorder.Code)
	}
	form = url.Values{"repository_id": {"1"}, csrfFormField: {viewerSession.CSRFToken}}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/repositories/setup-check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(viewerCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(runner.repositories) != 0 {
		t.Fatalf("expected viewer readiness run to be forbidden, status=%d runs=%d", recorder.Code, len(runner.repositories))
	}
}

func TestAdminRoleDoesNotImplyFreezeOrThawActions(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	if _, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authService.CreateUser(ctx, auth.CreateUserParams{Email: "admin-only@example.test", DisplayName: "Admin only", Password: "correct horse battery staple", Roles: []auth.Role{auth.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	adminOnlySession, err := authService.Login(ctx, auth.LoginParams{Email: "admin-only@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, FreezeStore: &fakeFreezeStore{}, StatusDecisionStore: &fakeStatusDecisionStore{}})
	adminOnlyCookie := &http.Cookie{Name: sessionCookieName, Value: adminOnlySession.ID}

	form := url.Values{"repository_id": {"1"}, "branch": {"main"}, "reason": {"release"}, csrfFormField: {adminOnlySession.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminOnlyCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected admin-only freeze create to be forbidden, got %d", recorder.Code)
	}

	form = url.Values{"repository_id": {"1"}, "pull_request_index": {"42"}, "target_branch": {"main"}, "head_sha": {"abc123"}, "reason": {"production fix"}, csrfFormField: {adminOnlySession.CSRFToken}}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminOnlyCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected admin-only thaw approval to be forbidden, got %d", recorder.Code)
	}
}

func TestRepositoriesPageKeepsConfiguredCredentialsHiddenByDefault(t *testing.T) {
	repo := domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, RepositorySecretEncryptionConfigured: true})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"Rotate webhook secret?",
		"Rotate status token?",
		`<dialog id="webhook-secret-7"`,
		`<dialog id="status-token-7"`,
		`aria-controls="webhook-secret-7"`,
		`aria-controls="status-token-7"`,
		`type="password" name="webhook_secret" minlength="16" maxlength="512" autocomplete="new-password" placeholder="New webhook secret" aria-label="New webhook secret for taua-almeida/thawguard" required`,
		`type="password" name="status_token" minlength="16" maxlength="1024" autocomplete="new-password" placeholder="New status token" aria-label="New status token for taua-almeida/thawguard" required`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `<dialog id="webhook-secret-7" open`) || strings.Contains(body, `<dialog id="status-token-7" open`) {
		t.Fatalf("expected credential dialogs to render closed, got %q", body)
	}
}

func TestRepositoriesPageShowsSetTokenActionWithoutStoredToken(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", HasWebhookSecret: true}}}, RepositorySecretEncryptionConfigured: true})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"webhook configured", "status token missing", "Rotate secret", "Set token", `name="status_token"`} {
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
	for _, want := range []string{"webhook missing", "status token missing", "THAWGUARD_SECRET_KEY</code> to save webhook secrets and status tokens"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "Set secret") || strings.Contains(body, "Rotate secret") || strings.Contains(body, `name="webhook_secret"`) || strings.Contains(body, "Set token") || strings.Contains(body, "Rotate token") || strings.Contains(body, `name="status_token"`) {
		t.Fatalf("expected secret/token forms to be hidden, got %q", body)
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

func TestSetRepositoryStatusTokenPostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, RepositorySecretEncryptionConfigured: true})
	form := url.Values{"repository_id": {"1"}, "status_token": {"super-status-token"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/status-token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.statusTokens) != 1 || store.statusTokens[0].repositoryID != repo.ID || store.statusTokens[0].token != "super-status-token" {
		t.Fatalf("expected status token update, got %+v", store.statusTokens)
	}
	if len(store.statusTokenActors) != 1 || store.statusTokenActors[0].Kind != domain.ActorKindBootstrapAdmin || store.statusTokenActors[0].Role != "admin" {
		t.Fatalf("unexpected actors: %+v", store.statusTokenActors)
	}
}

func TestSetRepositoryStatusTokenRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, RepositorySecretEncryptionConfigured: true})
	form := url.Values{"repository_id": {"1"}, "status_token": {"super-status-token"}}
	cookie, _ := getRepositoryForm(t, server)
	form.Set(csrfFormField, "not-the-session-token")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/status-token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", recorder.Code)
	}
	if len(store.statusTokens) != 0 {
		t.Fatalf("expected no status token updates, got %+v", store.statusTokens)
	}
}

func TestSetRepositoryStatusTokenDoesNotLeakInvalidToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}, statusTokenErr: repositorysetup.ValidationError{Message: "status token must be at least 16 characters"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, RepositorySecretEncryptionConfigured: true})
	form := url.Values{"repository_id": {"1"}, "status_token": {"short-token"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/status-token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "short-token") {
		t.Fatalf("expected submitted token not to be rendered, got %q", body)
	}
	if !strings.Contains(body, "status token must be at least 16 characters") {
		t.Fatalf("expected validation error, got %q", body)
	}
}

func TestSetRepositoryStatusTokenReportsMissingEncryptionKey(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	store := &fakeRepositoryStore{repositories: []domain.Repository{repo}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := url.Values{"repository_id": {"1"}, "status_token": {"super-status-token"}}
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/status-token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "super-status-token") {
		t.Fatalf("expected submitted token not to be rendered, got %q", body)
	}
}

func TestRepositoriesPageShowsSetupHealthResults(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	checkedAt := time.Date(2026, 6, 29, 14, 0, 0, 0, time.UTC)
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}, branches: map[int64][]domain.RepositoryBranch{repo.ID: {{RepositoryID: repo.ID, Name: "main", Protected: true, SetupStatus: "ok", LastCheckedAt: &checkedAt}}}},
		SetupCheckStore: &fakeSetupCheckStore{checks: map[int64][]setupcheck.Check{
			repo.ID: {
				{RepositoryID: repo.ID, Result: setupcheck.Result{Name: setupcheck.CheckStatusTokenConfigured, Status: setupcheck.StatusOK, Description: "Encrypted token exists."}, CheckedAt: checkedAt},
				{RepositoryID: repo.ID, Result: setupcheck.Result{Name: setupcheck.CheckRecentVerifiedPullRequestWebhook, Status: setupcheck.StatusWarning, Description: "Webhook is stale.", Remediation: "Deliver a current event."}, CheckedAt: checkedAt},
				{RepositoryID: repo.ID, Result: setupcheck.Result{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "Status posting is not tested until activation."}, CheckedAt: checkedAt},
				{RepositoryID: repo.ID, Branch: "main", Result: setupcheck.Result{Name: setupcheck.CheckBranchProtectionReadable, Status: setupcheck.StatusOK, Description: "Readable <unsafe>."}, CheckedAt: checkedAt},
				{RepositoryID: repo.ID, Branch: "main", Result: setupcheck.Result{Name: setupcheck.CheckRequiredThawguardFreezeContextConfigured, Status: setupcheck.StatusOK, Description: "Exact context exists."}, CheckedAt: checkedAt},
			},
		}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{setupcheck.CheckStatusTokenConfigured, "passed", setupcheck.CheckRecentVerifiedPullRequestWebhook, "Webhook is stale", setupcheck.CheckStatusPostingUntested, setupcheck.CheckBranchProtectionReadable, "Run readiness checks", "2026-06-29 14:00 UTC", "&lt;unsafe&gt;"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "<unsafe>") || strings.Contains(body, "Activate enforcement") {
		t.Fatalf("expected escaped evidence and no activation control, got %q", body)
	}
}

func TestRepositoriesPageKeepsHistoricalPlaceholderChecksReadable(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	checkedAt := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		SetupCheckStore: &fakeSetupCheckStore{checks: map[int64][]setupcheck.Check{
			repo.ID: {{RepositoryID: repo.ID, Branch: "main", Result: setupcheck.Result{Name: "Bot status permission not verified locally", Status: setupcheck.StatusWarning, Description: "Historical placeholder evidence."}, CheckedAt: checkedAt}},
		}},
	})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Historical placeholder evidence") {
		t.Fatalf("expected historical checks to remain readable, status=%d body=%q", recorder.Code, recorder.Body.String())
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

func TestRunRepositorySetupCheckPassesAuthenticatedAdminActor(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	adminSession, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	runner := &fakeSetupCheckRunner{}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, SetupCheckRunner: runner})
	cookie := &http.Cookie{Name: sessionCookieName, Value: adminSession.ID}

	page := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(page, request)
	if page.Code != http.StatusOK {
		t.Fatalf("expected repository form, got %d", page.Code)
	}
	form := url.Values{"repository_id": {"1"}, csrfFormField: {csrfTokenFromBody(t, page.Body.String())}}
	recorder := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/repositories/setup-check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther || len(runner.actors) != 1 {
		t.Fatalf("expected one attributed readiness run, status=%d actors=%+v", recorder.Code, runner.actors)
	}
	actor := runner.actors[0]
	if actor.UserID == nil || *actor.UserID != adminSession.User.ID || actor.Kind != domain.ActorKindUser || actor.Role != adminSession.User.Roles.String() {
		t.Fatalf("readiness runner received actor %+v, want authenticated admin user %d with roles %q", actor, adminSession.User.ID, adminSession.User.Roles.String())
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
	runner := &fakeSetupCheckRunner{err: errors.New("setup check failed: secret-token raw forge body")}
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
	if strings.Contains(recorder.Body.String(), "secret-token") || strings.Contains(recorder.Body.String(), "raw forge body") {
		t.Fatalf("expected generic operational error, got %q", recorder.Body.String())
	}
}

func TestFreezesPageShowsRepositoriesAndActiveFreezes(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "dev", EnforcementState: domain.EnforcementActive}
	plannedEndsAt := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	activeFreeze := domain.BranchFreeze{ID: 1, RepositoryID: repo.ID, Branch: "dev", Status: domain.BranchFreezeStatusActive, Active: true, Reason: "QA freeze", PlannedEndsAt: &plannedEndsAt}
	manualFreeze := domain.BranchFreeze{ID: 2, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true, Reason: `<script>alert("unsafe")</script>`}
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		FreezeStore:     &fakeFreezeStore{freezes: []domain.BranchFreeze{activeFreeze, manualFreeze}},
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
	for _, want := range []string{
		"Start a freeze",
		"Freeze impact",
		`id="freeze-impact"`,
		"How freezes work",
		"From webhook sync, not a live forge lookup.",
		`hx-get="/freezes/impact"`,
		"Active freezes",
		"taua-almeida/thawguard",
		"QA freeze",
		"Start freeze",
		`id="freezes-live"`,
		`id="active-freezes"`,
		`hx-post="/freezes" hx-target="#freezes-live" hx-swap="outerHTML" hx-push-url="false"`,
		"Planned unfreeze",
		`name="planned_ends_at"`,
		`name="timezone_offset_minutes"`,
		"Enabled when browser-local timezone conversion is available; stored as UTC.",
		"Planned unfreeze is unavailable without JavaScript",
		"data-local-datetime disabled",
		"2026-07-13 09:00 UTC",
		"No planned unfreeze",
		"&lt;script&gt;alert",
		"Frozen</span>",
		`<dialog id="lift-freeze-1"`,
		"Lift this freeze?",
		"records it as ended",
		`<form method="post" action="/freezes/end" hx-post="/freezes/end" hx-target="#active-freezes" hx-swap="outerHTML" hx-push-url="false">`,
		`name="freeze_id" value="1"`,
		`aria-controls="lift-freeze-1"`,
		`<dialog id="cancel-freeze-1"`,
		"Cancel this freeze?",
		"without completing it or recording it as ended",
		`<form method="post" action="/freezes/cancel" hx-post="/freezes/cancel" hx-target="#active-freezes" hx-swap="outerHTML" hx-push-url="false">`,
		`aria-controls="cancel-freeze-1"`,
		"Keep freeze",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `<script>alert("unsafe")</script>`) {
		t.Fatalf("expected freeze reason to be HTML escaped, got %q", body)
	}
	if strings.Contains(body, "window."+"confirm") {
		t.Fatalf("expected custom confirmation dialog instead of browser confirm, got %q", body)
	}
	for _, fictional := range []string{"3 open PRs", "#248", "Fix checkout tax rounding", "Live preview of PRs"} {
		if strings.Contains(body, fictional) {
			t.Fatalf("expected freezes page not to present fictional live data %q, got %q", fictional, body)
		}
	}
	// The aside warning callout is the single per-page positioning statement;
	// the old page-header badge must stay gone.
	if strings.Contains(body, "Cooperative enforcement — auditable, not a hard security gate") {
		t.Fatalf("expected freezes page not to repeat the positioning badge, got %q", body)
	}
}

func newFreezeImpactTestServer(pullRequests []domain.PullRequest) *Server {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	return NewServer(Config{
		AppName: "Thawguard",
		RepositoryStore: &fakeRepositoryStore{
			repositories: []domain.Repository{repo},
			branches: map[int64][]domain.RepositoryBranch{
				1: {{ID: 1, RepositoryID: 1, Name: "main"}, {ID: 2, RepositoryID: 1, Name: "release/1.8"}},
			},
		},
		FreezeStore:      &fakeFreezeStore{},
		PullRequestStore: &fakePullRequestStore{pullRequests: pullRequests},
	})
}

func freezeImpactPullRequests(count int) []domain.PullRequest {
	pullRequests := make([]domain.PullRequest, 0, count)
	for i := range count {
		pullRequests = append(pullRequests, domain.PullRequest{
			ID: int64(100 + i), RepositoryID: 1, Index: 200 + i, State: "open", TargetBranch: "main",
			Title: fmt.Sprintf("Impact fixture pull request %d", 200+i),
			URL:   fmt.Sprintf("https://forge.example.test/taua-almeida/thawguard/pulls/%d", 200+i),
		})
	}
	return pullRequests
}

func TestFreezeImpactFragmentListsOpenPullRequestsWithOverflow(t *testing.T) {
	server := newFreezeImpactTestServer(freezeImpactPullRequests(7))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/freezes/impact?repository_id=1&branch=main", nil)
	request.Header.Set("HX-Request", "true")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if vary := recorder.Header().Get("Vary"); !strings.Contains(vary, "HX-Request") {
		t.Fatalf("expected Vary to include HX-Request, got %q", vary)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected fragment without page shell, got %q", body)
	}
	for _, want := range []string{
		`id="freeze-impact"`,
		"taua-almeida/thawguard",
		"7 known open pull requests",
		domain.RequiredStatusContext,
		"#200",
		"#204",
		"Show all 7",
		"#205",
		"#206",
		`rel="noopener noreferrer"`,
		"From webhook sync, not a live forge lookup.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected impact fragment to contain %q, got %q", want, body)
		}
	}
}

func TestFreezeImpactFragmentRendersZeroStateForUnknownBranch(t *testing.T) {
	server := newFreezeImpactTestServer(freezeImpactPullRequests(2))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/freezes/impact?repository_id=1&branch=ghost", nil)
	request.Header.Set("HX-Request", "true")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "No known open pull requests target this branch right now.") {
		t.Fatalf("expected zero state for unknown branch, got %q", body)
	}
	if strings.Contains(body, "#200") {
		t.Fatalf("expected no pull request rows for unknown branch, got %q", body)
	}
}

func TestFreezeImpactRedirectsNonHXRequestsToFreezes(t *testing.T) {
	server := newFreezeImpactTestServer(nil)

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes/impact?repository_id=1&branch=main", nil))

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/freezes" {
		t.Fatalf("expected redirect to /freezes, got %q", location)
	}
	if vary := recorder.Header().Get("Vary"); !strings.Contains(vary, "HX-Request") {
		t.Fatalf("expected Vary to include HX-Request, got %q", vary)
	}
}

func TestRepositoriesPageShowsEnforcementState(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementSetupIncomplete}
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"setup incomplete", "cannot enforce freezes", "Enforcing"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	for _, stale := range []string{"Shadow", "shadow mode", "dry-run", "Activate enforcement</button>"} {
		if strings.Contains(body, stale) {
			t.Fatalf("expected repositories page not to contain %q", stale)
		}
	}
}

func newRepositoriesFindabilityServer() *Server {
	return NewServer(Config{
		AppName: "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{
			{ID: 1, Owner: "acme", Name: "alpha-active", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive},
			{ID: 2, Owner: "acme", Name: "beta-setup", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementSetupIncomplete},
			{ID: 3, Owner: "acme", Name: "gamma-unhealthy", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementUnhealthy},
			{ID: 4, Owner: "acme", Name: "delta-ready", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementReady},
		}},
	})
}

func TestRepositoriesPageOrdersByAttentionAndShowsFilters(t *testing.T) {
	server := newRepositoriesFindabilityServer()

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	previous := -1
	for _, fullName := range []string{"acme/gamma-unhealthy", "acme/beta-setup", "acme/delta-ready", "acme/alpha-active"} {
		index := strings.Index(body, fullName)
		if index == -1 {
			t.Fatalf("expected body to contain %q", fullName)
		}
		if index < previous {
			t.Fatalf("expected attention-first ordering, %q appeared too early", fullName)
		}
		previous = index
	}
	for _, want := range []string{
		`href="/repositories?state=active" aria-label="Show repositories with active enforcement"`,
		`href="/repositories?state=unhealthy"`,
		`href="/repositories?state=setup-incomplete"`,
		`href="/repositories?state=ready"`,
		`>All<span class="rounded-pill bg-neutral-soft px-1.5 text-[0.65rem] text-text-muted">4</span>`,
		`aria-label="Lifecycle"`,
		"text-xs font-semibold text-danger",
		`name="q"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q", want)
		}
	}
	if strings.Contains(body, "showing") {
		t.Fatalf("expected no filtered count without an active filter, got %q", body)
	}
}

func TestRepositoriesPageCollapsesHealthyRepositoriesToSummaryRows(t *testing.T) {
	server := newRepositoriesFindabilityServer()

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	// Only the ready and active repositories collapse to summary rows; the
	// unhealthy and setup-incomplete cards stay fully expanded.
	if got := strings.Count(body, "1 managed branch</span>"); got != 2 {
		t.Fatalf("expected exactly 2 compact summary rows (ready + active), got %d", got)
	}
	if strings.Contains(body, `class="group" open`) {
		t.Fatalf("expected compact rows to render closed on full page loads, got %q", body)
	}
}

func TestRepositoriesPageFiltersByState(t *testing.T) {
	server := newRepositoriesFindabilityServer()

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories?state=unhealthy", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"acme/gamma-unhealthy", "showing 1 of 4", `aria-current="true"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q", want)
		}
	}
	for _, hidden := range []string{"acme/alpha-active", "acme/beta-setup", "acme/delta-ready"} {
		if strings.Contains(body, hidden) {
			t.Fatalf("expected state filter to hide %q", hidden)
		}
	}
}

func TestRepositoriesPageIgnoresUnknownStateFilter(t *testing.T) {
	server := newRepositoriesFindabilityServer()

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories?state=bogus", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"acme/gamma-unhealthy", "acme/beta-setup", "acme/delta-ready", "acme/alpha-active"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected unknown state filter to be ignored, missing %q", want)
		}
	}
	if strings.Contains(body, "showing") {
		t.Fatalf("expected unknown state filter to be treated as no filter, got %q", body)
	}
}

func TestRepositoriesPageFiltersBySearchQuery(t *testing.T) {
	server := newRepositoriesFindabilityServer()

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories?q=DELTA", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"acme/delta-ready",
		"showing 1 of 4",
		`value="DELTA"`,
		`>All<span class="rounded-pill bg-neutral-soft px-1.5 text-[0.65rem] text-text-muted">1</span>`,
		`>Ready<span class="rounded-pill bg-neutral-soft px-1.5 text-[0.65rem] text-text-muted">1</span>`,
		"Rotating the status token or changing managed branches returns this repository to setup until it is re-verified.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q", want)
		}
	}
	for _, hidden := range []string{"acme/alpha-active", "acme/beta-setup", "acme/gamma-unhealthy"} {
		if strings.Contains(body, hidden) {
			t.Fatalf("expected search filter to hide %q", hidden)
		}
	}
}

func TestRepositoriesPageShowsFilteredEmptyState(t *testing.T) {
	server := newRepositoriesFindabilityServer()

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories?q=no-such-repository", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"No repositories match this filter", `href="/repositories">Clear filter</a>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q", want)
		}
	}
	if strings.Contains(body, "No repositories configured yet") {
		t.Fatalf("expected filtered empty state instead of the unconfigured empty state, got %q", body)
	}
}

func TestMutationPagesShowSetupRequiredWithoutEnforceableRepositories(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementSetupIncomplete}
	server := NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		FreezeStore:          &fakeFreezeStore{},
		ScheduledFreezeStore: &fakeFreezeStore{},
		AuditStore:           &fakeAuditStore{},
		StatusDecisionStore:  &fakeStatusDecisionStore{},
	})

	for path, expect := range map[string]struct{ formMarker, message string }{
		"/freezes":           {`<form method="post" action="/freezes" `, "No repository has active enforcement"},
		"/scheduled-freezes": {`<form method="post" action="/scheduled-freezes" `, "Repository enforcement is not active"},
		"/decisions":         {`<form method="post" action="/decisions" `, "Repository enforcement is not active"},
	} {
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: expected status 200, got %d", path, recorder.Code)
		}
		body := recorder.Body.String()
		if strings.Contains(body, expect.formMarker) {
			t.Fatalf("%s: expected mutation form to be omitted for setup-incomplete repositories", path)
		}
		if !strings.Contains(body, expect.message) {
			t.Fatalf("%s: expected setup-required message, got %q", path, body)
		}
	}
}

func TestFreezesPageHidesNonFreezeAuditEvents(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	if !strings.Contains(body, "No active freezes") {
		t.Fatalf("expected empty active freeze state, got %q", body)
	}
}

func TestFreezesPageDoesNotDependOnOrPresentAuditHistory(t *testing.T) {
	server := NewServer(Config{
		AppName:     "Thawguard",
		FreezeStore: &fakeFreezeStore{},
		AuditStore:  &fakeAuditStore{err: errors.New("audit unavailable")},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, unwanted := range []string{"Audit Log", "Audit history", "Recent activity"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected freezes page not to present duplicate audit history %q, got %q", unwanted, body)
		}
	}
	if !strings.Contains(body, "No active freezes") {
		t.Fatalf("expected empty active freeze state, got %q", body)
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
	if strings.Contains(body, audit.ActionBranchFreezeCreated) {
		t.Fatalf("expected freeze audit action not to render on freezes page, got %q", body)
	}
}

func TestCreateFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCreateForm()
	form.Set("planned_ends_at", "2026-07-13T09:00")
	form.Set("timezone_offset_minutes", "240")
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
	if store.created[0].RepositoryID != repo.ID || store.created[0].Branch != "main" || store.created[0].Reason != "release window" || store.created[0].PlannedEndsAt == nil || store.created[0].PlannedEndsAt.Format(time.RFC3339) != "2026-07-13T13:00:00Z" {
		t.Fatalf("unexpected freeze params: %+v", store.created[0])
	}
	if len(store.actors) != 1 || store.actors[0].Kind != domain.ActorKindBootstrapAdmin || store.actors[0].Role != "admin" {
		t.Fatalf("unexpected actors: %+v", store.actors)
	}
}

func TestCreateFreezeTreatsEmptyPlannedUnfreezeAsNil(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCreateForm()
	form.Set("planned_ends_at", "")
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || len(store.created) != 1 || store.created[0].PlannedEndsAt != nil {
		t.Fatalf("expected empty planned end to create nil value, status=%d params=%+v", recorder.Code, store.created)
	}
}

func TestCreateFreezeRejectsMalformedPlannedUnfreezeAndTimezoneOffset(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	for _, test := range []struct {
		name  string
		field string
		value string
		want  string
	}{
		{name: "malformed datetime", field: "planned_ends_at", value: "not-a-time", want: "planned unfreeze time is invalid"},
		{name: "invalid timezone", field: "timezone_offset_minutes", value: "841", want: "browser timezone offset is invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeFreezeStore{}
			server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
			form := freezeCreateForm()
			form.Set("planned_ends_at", "2026-07-13T09:00")
			form.Set(test.field, test.value)
			cookie, csrfToken := getFreezeForm(t, server)
			form.Set(csrfFormField, csrfToken)

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookie)
			server.Routes().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), test.want) || len(store.created) != 0 {
				t.Fatalf("expected safe validation error %q, status=%d body=%q created=%+v", test.want, recorder.Code, recorder.Body.String(), store.created)
			}
		})
	}
}

func TestCreateFreezeRendersPastPlannedUnfreezeValidation(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeFreezeStore{err: freeze.ValidationError{Message: "planned unfreeze time must be in the future"}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
	form := freezeCreateForm()
	form.Set("planned_ends_at", "2020-01-01T00:00")
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest || !strings.Contains(body, "planned unfreeze time must be in the future") {
		t.Fatalf("expected safe past-time validation, status=%d body=%q", recorder.Code, body)
	}
	for _, preserved := range []string{
		`<option value="1" selected>taua-almeida/thawguard</option>`,
		`<option value="main" data-repository="1" selected>main</option>`,
		`id="freeze-reason"`,
		`value="release window"`,
		`name="planned_ends_at" value="2020-01-01T00:00"`,
	} {
		if !strings.Contains(body, preserved) {
			t.Fatalf("expected validation render to preserve %q, got %q", preserved, body)
		}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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

func TestScheduledFreezesPageShowsFormAndWindows(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	startsAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Minute)
	plannedEndsAt := startsAt.Add(63 * time.Hour)
	endedAt := startsAt.Add(-time.Hour)
	store := &fakeFreezeStore{scheduled: []domain.BranchFreeze{
		{ID: 9, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: "Weekend release freeze", StartsAt: &startsAt, PlannedEndsAt: &plannedEndsAt},
		{ID: 10, RepositoryID: repo.ID, Branch: "release", Status: domain.BranchFreezeStatusEnded, Scheduled: true, Reason: "Completed freeze", StartsAt: &endedAt, EndsAt: &startsAt},
	}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Scheduled Freezes", "Schedule a freeze", "One-time windows", "How scheduling works", "cooperative enforcement", "taua-almeida/thawguard", "main", "Weekend release freeze", startsAt.Format("2006-01-02 15:04 UTC"), plannedEndsAt.Format("2006-01-02 15:04 UTC"), "upcoming", `action="/scheduled-freezes/edit"`, `action="/scheduled-freezes/start-now"`, `action="/scheduled-freezes/cancel"`, `id="start-scheduled-9"`, `id="cancel-scheduled-9"`, "Live enforcement begins immediately", "current open pull requests", "future planned unfreeze remains scheduled", `datetime="` + startsAt.Format(time.RFC3339) + `"`, "Times shown in UTC.", "data-timezone-note", `<span class="mt-1 block text-xs text-text-muted">Ended <time`, `data-utc-datetime="` + startsAt.Format(time.RFC3339) + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `name="freeze_id" value="10"`) {
		t.Fatalf("expected ended schedule to have no edit, Start Now, or cancel actions, got %q", body)
	}
	if strings.Contains(body, "window."+"confirm") {
		t.Fatalf("expected custom confirmation dialog instead of browser confirm, got %q", body)
	}
	if token := csrfTokenFromBody(t, body); token == "" {
		t.Fatal("expected CSRF token in scheduled freeze form")
	}
}

func TestScheduledFreezeActionsRespectRepositoryEnforcementAndRoles(t *testing.T) {
	startsAt := time.Now().UTC().Add(2 * time.Hour)
	for _, test := range []struct {
		name              string
		roles             auth.RoleSet
		enforcement       domain.EnforcementState
		wantEdit          bool
		wantStart         bool
		wantBlockedReason bool
	}{
		{name: "admin", roles: auth.RoleSet{auth.RoleAdmin}, enforcement: domain.EnforcementActive, wantEdit: true, wantStart: true},
		{name: "freezer", roles: auth.RoleSet{auth.RoleFreezer}, enforcement: domain.EnforcementActive, wantEdit: true, wantStart: true},
		{name: "viewer", roles: auth.RoleSet{auth.RoleViewer}, enforcement: domain.EnforcementActive},
		{name: "unhealthy", roles: auth.RoleSet{auth.RoleFreezer}, enforcement: domain.EnforcementUnhealthy, wantEdit: true, wantBlockedReason: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: test.enforcement}
			store := &fakeFreezeStore{scheduled: []domain.BranchFreeze{{ID: 9, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: "release", StartsAt: &startsAt}}}
			server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
			session := setWebSessionRoles(t, server, test.roles)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/scheduled-freezes", nil)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
			server.Routes().ServeHTTP(recorder, request)
			body := recorder.Body.String()
			if got := strings.Contains(body, `action="/scheduled-freezes/edit"`); got != test.wantEdit {
				t.Fatalf("edit visibility: want %v, got %v", test.wantEdit, got)
			}
			if got := strings.Contains(body, `action="/scheduled-freezes/start-now"`); got != test.wantStart {
				t.Fatalf("Start Now visibility: want %v, got %v", test.wantStart, got)
			}
			if got := strings.Contains(body, "activate repository enforcement first"); got != test.wantBlockedReason {
				t.Fatalf("blocked remediation visibility: want %v, got %v", test.wantBlockedReason, got)
			}
		})
	}
}

func TestEditAndStartNowAllowAdminOrFreezerButRejectViewer(t *testing.T) {
	for _, test := range []struct {
		name    string
		roles   auth.RoleSet
		allowed bool
	}{
		{name: "admin", roles: auth.RoleSet{auth.RoleAdmin}, allowed: true},
		{name: "freezer", roles: auth.RoleSet{auth.RoleFreezer}, allowed: true},
		{name: "viewer", roles: auth.RoleSet{auth.RoleViewer}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
			store := &fakeFreezeStore{}
			server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
			session := setWebSessionRoles(t, server, test.roles)
			cookie := &http.Cookie{Name: sessionCookieName, Value: session.ID}
			form := scheduledFreezeEditForm(9)
			form.Set(csrfFormField, session.CSRFToken)
			postScheduledFreezeForm(t, server, cookie, "/scheduled-freezes/edit", form, map[bool]int{true: http.StatusSeeOther, false: http.StatusForbidden}[test.allowed])

			form = freezeCloseForm(9)
			form.Set(csrfFormField, session.CSRFToken)
			postScheduledFreezeForm(t, server, cookie, "/scheduled-freezes/start-now", form, map[bool]int{true: http.StatusSeeOther, false: http.StatusForbidden}[test.allowed])
			wantCalls := 0
			if test.allowed {
				wantCalls = 1
			}
			if len(store.scheduledEdited) != wantCalls || len(store.scheduledStarted) != wantCalls {
				t.Fatalf("expected edit/start calls=%d, got edits=%d starts=%d", wantCalls, len(store.scheduledEdited), len(store.scheduledStarted))
			}
		})
	}
}

func TestEditScheduledFreezeUsesBrowserTimezoneClearsPlannedEndAndIgnoresTamperedTarget(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
	form := scheduledFreezeEditForm(9)
	form.Set("starts_at", "2099-07-08T16:50")
	form.Set("planned_ends_at", "")
	form.Set("timezone_offset_minutes", "240")
	form.Set("repository_id", "999")
	form.Set("branch", "tampered")
	cookie, csrfToken := getScheduledFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	postScheduledFreezeForm(t, server, cookie, "/scheduled-freezes/edit", form, http.StatusSeeOther)
	if len(store.scheduledEdited) != 1 {
		t.Fatalf("expected one edit, got %+v", store.scheduledEdited)
	}
	edited := store.scheduledEdited[0]
	if edited.ID != 9 || edited.Reason != "updated release" || edited.StartsAt.Format(time.RFC3339) != "2099-07-08T20:50:00Z" || edited.PlannedEndsAt != nil {
		t.Fatalf("unexpected edit params: %+v", edited)
	}
}

func TestEditScheduledFreezeValidationReopensCorrectFormWithSafeSubmittedValues(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	start := time.Now().UTC().Add(2 * time.Hour)
	store := &fakeFreezeStore{
		scheduled: []domain.BranchFreeze{
			{ID: 9, RepositoryID: 1, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: "first", StartsAt: &start},
			{ID: 10, RepositoryID: 1, Branch: "release", Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: "second", StartsAt: &start},
		},
		err: freeze.ValidationError{Message: "planned unfreeze time must be after the scheduled start"},
	}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
	form := scheduledFreezeEditForm(9)
	form.Set("reason", "Operator <note>")
	form.Set("starts_at", "2099-07-08T16:50")
	form.Set("planned_ends_at", "2099-07-08T16:40")
	cookie, csrfToken := getScheduledFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := postScheduledFreezeForm(t, server, cookie, "/scheduled-freezes/edit", form, http.StatusBadRequest)
	body := recorder.Body.String()
	for _, want := range []string{"planned unfreeze time must be after the scheduled start", `value="Operator &lt;note&gt;"`, `value="2099-07-08T16:50"`, `value="2099-07-08T16:40"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected validation response to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "Operator <note>") || strings.Count(body, `<details class="text-left" open>`) != 2 {
		t.Fatalf("expected escaped values and only schedule 9 open in desktop/mobile, got %q", body)
	}
}

func TestScheduledFreezeEditAndStartNowRejectMissingCSRF(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	for _, path := range []string{"/scheduled-freezes/edit", "/scheduled-freezes/start-now"} {
		store := &fakeFreezeStore{}
		server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
		cookie, _ := getScheduledFreezeForm(t, server)
		form := scheduledFreezeEditForm(9)
		if path == "/scheduled-freezes/start-now" {
			form = freezeCloseForm(9)
		}
		postScheduledFreezeForm(t, server, cookie, path, form, http.StatusForbidden)
		if len(store.scheduledEdited) != 0 || len(store.scheduledStarted) != 0 {
			t.Fatalf("expected no mutation without CSRF for %s", path)
		}
	}
}

func TestScheduledFreezeEditAndStartNowHideInternalErrors(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	for _, path := range []string{"/scheduled-freezes/edit", "/scheduled-freezes/start-now"} {
		store := &fakeFreezeStore{err: errors.New("database failed with secret-token")}
		server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
		cookie, csrfToken := getScheduledFreezeForm(t, server)
		form := scheduledFreezeEditForm(9)
		if path == "/scheduled-freezes/start-now" {
			form = freezeCloseForm(9)
		}
		form.Set(csrfFormField, csrfToken)
		recorder := postScheduledFreezeForm(t, server, cookie, path, form, http.StatusInternalServerError)
		if strings.Contains(recorder.Body.String(), "secret-token") {
			t.Fatalf("expected generic internal error for %s, got %q", path, recorder.Body.String())
		}
	}
}

func TestCreateScheduledFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeFreezeStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
	form := scheduledFreezeCreateForm()
	cookie, csrfToken := getScheduledFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.scheduledCreated) != 1 {
		t.Fatalf("expected one scheduled freeze creation, got %+v", store.scheduledCreated)
	}
	created := store.scheduledCreated[0]
	if created.RepositoryID != repo.ID || created.Branch != "main" || created.Reason != "weekend freeze" || created.StartsAt.Format(time.RFC3339) != "2026-07-10T18:00:00Z" || created.PlannedEndsAt == nil || created.PlannedEndsAt.Format(time.RFC3339) != "2026-07-13T09:00:00Z" {
		t.Fatalf("unexpected scheduled freeze params: %+v", created)
	}
	if len(store.actors) != 1 || store.actors[0].Kind != domain.ActorKindBootstrapAdmin || store.actors[0].Role != "admin" {
		t.Fatalf("unexpected actors: %+v", store.actors)
	}
}

func TestParseScheduledFreezeFormTimeUsesBrowserTimezoneOffset(t *testing.T) {
	parsed, err := parseScheduledFreezeFormTime("2026-07-08T16:50", 240)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := parsed.Format(time.RFC3339), "2026-07-08T20:50:00Z"; got != want {
		t.Fatalf("expected browser-local time to convert to UTC %s, got %s", want, got)
	}
}

func TestCancelScheduledFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeFreezeStore{scheduled: []domain.BranchFreeze{{ID: 9, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: "weekend"}}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})
	form := freezeCloseForm(9)
	cookie, csrfToken := getScheduledFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/scheduled-freezes/cancel", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.scheduledCancelled) != 1 || store.scheduledCancelled[0] != 9 {
		t.Fatalf("expected scheduled freeze 9 to cancel, got %+v", store.scheduledCancelled)
	}
}

func TestDecisionsPageShowsFormAndRecentResults(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	for _, want := range []string{"Thaw Requests", "Approve a thaw exception", "Approve auditable exceptions", "current forge head commit", "taua-almeida/thawguard", "Target branch", "main", "thawguard/freeze", "Freeze decisions", "Eligibility preview", "Blocked", "Branch is frozen", "2026-06-29 16:30 UTC"} {
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

func newThawEligibilityTestServer(pullRequests []domain.PullRequest, freezes []domain.BranchFreeze) *Server {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	return NewServer(Config{
		AppName:          "Thawguard",
		RepositoryStore:  &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		FreezeStore:      &fakeFreezeStore{freezes: freezes},
		PullRequestStore: &fakePullRequestStore{pullRequests: pullRequests},
	})
}

func TestThawEligibilityFragmentShowsFrozenTargetAndCompanions(t *testing.T) {
	sharedHead := "f00dfeed00c0ffee1122334455667788990011aa"
	server := newThawEligibilityTestServer(
		[]domain.PullRequest{
			{ID: 100, RepositoryID: 1, Index: 241, State: "open", TargetBranch: "main", HeadSHA: sharedHead, Title: "Fix retry backoff for status publication", URL: "https://forge.example.test/taua-almeida/thawguard/pulls/241"},
			{ID: 101, RepositoryID: 1, Index: 238, State: "open", TargetBranch: "release/1.8", HeadSHA: sharedHead, Title: "Backport retry backoff fix", URL: "https://forge.example.test/taua-almeida/thawguard/pulls/238"},
		},
		[]domain.BranchFreeze{{ID: 5, RepositoryID: 1, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}},
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/decisions/eligibility?repository_id=1&pull_request_index=241", nil)
	request.Header.Set("HX-Request", "true")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if vary := recorder.Header().Get("Vary"); !strings.Contains(vary, "HX-Request") {
		t.Fatalf("expected Vary to include HX-Request, got %q", vary)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected fragment without page shell, got %q", body)
	}
	for _, want := range []string{
		`id="thaw-eligibility"`,
		"taua-almeida/thawguard",
		"#241",
		"Fix retry backoff for status publication",
		"main is frozen — thaw required",
		"Shares head",
		"f00dfeed00",
		"#238",
		"Backport retry backoff fix",
		"Approval will pause for an explicit all-PRs confirmation.",
		"From webhook sync, not a live forge lookup.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected eligibility fragment to contain %q, got %q", want, body)
		}
	}
}

func TestThawEligibilityFragmentShowsNotFrozenWithoutCompanions(t *testing.T) {
	server := newThawEligibilityTestServer(
		[]domain.PullRequest{{ID: 100, RepositoryID: 1, Index: 241, State: "open", TargetBranch: "main", HeadSHA: "f00dfeed00c0ffee1122334455667788990011aa", Title: "Fix retry backoff for status publication"}},
		nil,
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/decisions/eligibility?repository_id=1&pull_request_index=241", nil)
	request.Header.Set("HX-Request", "true")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"is not frozen — approval would be rejected (no thaw needed).",
		"No other open pull request shares this head commit.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected eligibility fragment to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "thaw required") {
		t.Fatalf("expected no frozen badge for unfrozen branch, got %q", body)
	}
}

func TestThawEligibilityFragmentShowsCacheMissForUnknownIndex(t *testing.T) {
	server := newThawEligibilityTestServer(nil, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/decisions/eligibility?repository_id=1&pull_request_index=977", nil)
	request.Header.Set("HX-Request", "true")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"#977", "in the webhook-synced cache yet", "Approval fetches the live pull request from the forge"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected cache-miss fragment to contain %q, got %q", want, body)
		}
	}
}

func TestThawEligibilityFragmentPromptsWhenIncomplete(t *testing.T) {
	server := newThawEligibilityTestServer(nil, nil)

	for _, query := range []string{"", "?repository_id=1", "?pull_request_index=241", "?repository_id=99&pull_request_index=241", "?repository_id=abc&pull_request_index=-3"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/decisions/eligibility"+query, nil)
		request.Header.Set("HX-Request", "true")
		server.Routes().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status 200 for query %q, got %d", query, recorder.Code)
		}
		if body := recorder.Body.String(); !strings.Contains(body, "Pick a repository and enter a pull request number") {
			t.Fatalf("expected prompt state for query %q, got %q", query, body)
		}
	}
}

func TestDecisionsTableFiltersAndPaginates(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	other := domain.Repository{ID: 2, Owner: "taua-almeida", Name: "frost-api", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	createdAt := time.Date(2026, 6, 29, 16, 30, 0, 0, time.UTC)
	var results []statusresult.Result
	for i := range 25 {
		results = append(results, statusresult.Result{ID: int64(i + 1), RepositoryID: repo.ID, PullRequestIndex: 101 + i, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", CreatedAt: createdAt})
	}
	results = append(results, statusresult.Result{ID: 90, RepositoryID: other.ID, PullRequestIndex: 900, TargetBranch: "main", HeadSHA: "def456", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, CreatedAt: createdAt})
	server := NewServer(Config{
		AppName:             "Thawguard",
		RepositoryStore:     &fakeRepositoryStore{repositories: []domain.Repository{repo, other}},
		StatusDecisionStore: &fakeStatusDecisionStore{results: results},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/decisions?state=blocked&repo=1&page=2", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Showing 21–25 of 25 decisions", "#121", "#125", `hx-push-url="true"`, "25 decisions"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected filtered page 2 to contain %q, got %q", want, body)
		}
	}
	for _, unwanted := range []string{"#101", "#900"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected filtered page 2 to omit %q", unwanted)
		}
	}

	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/decisions?state=blocked&repo=1&page=99", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for out-of-range page, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "Showing 21–25 of 25 decisions") {
		t.Fatalf("expected out-of-range page to clamp to the last page, got %q", body)
	}

	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/decisions?state=blocked&repo=1&page=2", nil)
	request.Header.Set("HX-Request", "true")
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for HX request, got %d", recorder.Code)
	}
	fragment := recorder.Body.String()
	if strings.Contains(fragment, "<!doctype html>") {
		t.Fatalf("expected fragment without page shell, got %q", fragment)
	}
	if !strings.Contains(fragment, `id="decisions-live"`) || !strings.Contains(fragment, "#121") {
		t.Fatalf("expected fragment to swap #decisions-live with the filtered rows, got %q", fragment)
	}
}

func TestThawEligibilityRedirectsNonHXRequestsToDecisions(t *testing.T) {
	server := newThawEligibilityTestServer(nil, nil)

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/decisions/eligibility?repository_id=1&pull_request_index=241", nil))

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/decisions" {
		t.Fatalf("expected redirect to /decisions, got %q", location)
	}
	if vary := recorder.Header().Get("Vary"); !strings.Contains(vary, "HX-Request") {
		t.Fatalf("expected Vary to include HX-Request, got %q", vary)
	}
}

func TestCreateDecisionPostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
		t.Fatalf("expected 1 thaw approval, got %d", len(store.runs))
	}
	run := store.runs[0]
	if run.RepositoryID != repo.ID || run.PullRequestIndex != 42 || run.TargetBranch != "main" || run.Reason != "production fix" {
		t.Fatalf("unexpected thaw approval params: %+v", run)
	}
	if len(store.actors) != 1 || store.actors[0].Kind != domain.ActorKindBootstrapAdmin || store.actors[0].Role != "admin" {
		t.Fatalf("unexpected thaw approval actor: %+v", store.actors)
	}
}

func TestCreateDecisionParsesSharedHeadConfirmation(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeStatusDecisionStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	form.Set("confirm_shared_head", "true")
	form.Set("confirmed_head_sha", "abc123")
	form.Set("confirmed_affected_signature", strings.Repeat("a", 64))
	cookie, csrfToken := getDecisionForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther || len(store.runs) != 1 {
		t.Fatalf("expected confirmed decision redirect and one run, status=%d runs=%d", recorder.Code, len(store.runs))
	}
	confirmation := store.runs[0].Confirmation
	if confirmation == nil || confirmation.HeadSHA != "abc123" || confirmation.AffectedSignature != strings.Repeat("a", 64) {
		t.Fatalf("unexpected shared-head confirmation params: %+v", confirmation)
	}
}

func TestCreateDecisionReturnsConflictWhenSharedHeadConfirmationIsRequired(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeStatusDecisionStore{outcome: statusresult.ThawApprovalOutcome{
		ConfirmationRequired: true,
		Confirmation:         &statusresult.ThawApprovalConfirmation{HeadSHA: "abc123", AffectedSignature: strings.Repeat("a", 64)},
		AffectedPullRequests: []statusresult.ThawApprovalPullRequest{
			{Index: 42, Title: "Release fix", TargetBranch: "main", URL: "https://codeberg.org/example/repo/pulls/42", HeadSHA: "abc123"},
			{Index: 43, Title: "Other fix", TargetBranch: "main", URL: "https://codeberg.org/example/repo/pulls/43", HeadSHA: "abc123"},
		},
	}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	cookie, csrfToken := getDecisionForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusConflict || len(store.runs) != 1 {
		t.Fatalf("expected confirmation-required conflict and one run, status=%d runs=%d", recorder.Code, len(store.runs))
	}
}

func sharedHeadOutcome(titles ...string) statusresult.ThawApprovalOutcome {
	outcome := statusresult.ThawApprovalOutcome{
		ConfirmationRequired: true,
		Confirmation:         &statusresult.ThawApprovalConfirmation{HeadSHA: "abc123", AffectedSignature: strings.Repeat("a", 64)},
	}
	for i, title := range titles {
		outcome.AffectedPullRequests = append(outcome.AffectedPullRequests, statusresult.ThawApprovalPullRequest{Index: 42 + i, Title: title, TargetBranch: "main", URL: "https://codeberg.org/example/repo/pulls/42", HeadSHA: "abc123"})
	}
	return outcome
}

func postDecisionForm(t *testing.T, server *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	cookie, csrfToken := getDecisionForm(t, server)
	form.Set(csrfFormField, csrfToken)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func TestCreateDecisionSharedHeadConflictRendersConfirmationPanel(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeStatusDecisionStore{outcome: sharedHeadOutcome("Release fix", "Other fix")}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})

	recorder := postDecisionForm(t, server, decisionCreateForm())

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected conflict status, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"These pull requests share one commit SHA",
		"Forgejo applies commit statuses to the shared SHA, so approving this thaw will affect every pull request listed below.",
		"Nothing has been approved yet",
		"#42", "Release fix", "#43", "Other fix", "main",
		"Approve thaw for all 2 PRs",
		`name="repository_id" value="1"`,
		`name="pull_request_index" value="42"`,
		`name="target_branch" value="main"`,
		`name="reason" value="production fix"`,
		`name="confirm_shared_head" value="true"`,
		`name="confirmed_head_sha" value="abc123"`,
		`name="confirmed_affected_signature" value="` + strings.Repeat("a", 64) + `"`,
		`href="/decisions">Cancel</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected confirmation panel to contain %q, got %q", want, body)
		}
	}
	if token := csrfTokenFromBody(t, body); token == "" {
		t.Fatal("expected CSRF token in confirmation form")
	}
	if strings.Contains(body, `name="affected`) {
		t.Fatal("expected no client-submitted affected-PR form inputs")
	}
	if strings.Contains(body, strings.Repeat("a", 64)+"</") || strings.Contains(body, "<code>"+strings.Repeat("a", 64)) {
		t.Fatal("expected affected signature to stay out of visible page content")
	}
}

func TestCreateDecisionSharedHeadReconfirmationKeepsOriginalValues(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	outcome := sharedHeadOutcome("Release fix", "Other fix", "Third fix")
	outcome.Confirmation.HeadSHA = "def456"
	store := &fakeStatusDecisionStore{outcome: outcome}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})
	form := decisionCreateForm()
	form.Set("confirm_shared_head", "true")
	form.Set("confirmed_head_sha", "abc123")
	form.Set("confirmed_affected_signature", strings.Repeat("b", 64))

	recorder := postDecisionForm(t, server, form)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected conflict status for stale confirmation, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"Approve thaw for all 3 PRs",
		`name="confirmed_head_sha" value="def456"`,
		`name="confirmed_affected_signature" value="` + strings.Repeat("a", 64) + `"`,
		`name="reason" value="production fix"`,
		`name="pull_request_index" value="42"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected refreshed confirmation to contain %q, got %q", want, body)
		}
	}
}

func TestCreateDecisionSharedHeadConfirmationEscapesTitles(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeStatusDecisionStore{outcome: sharedHeadOutcome(`<script>alert("pwn")</script>`, "Other fix")}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: store})

	recorder := postDecisionForm(t, server, decisionCreateForm())

	body := recorder.Body.String()
	if strings.Contains(body, `<script>alert(`) {
		t.Fatal("expected PR title to be HTML-escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected escaped PR title in body, got %q", body)
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
		t.Fatalf("expected no thaw approvals, got %d", len(store.runs))
	}
}

func TestCreateDecisionRejectsInvalidCSRFToken(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
		t.Fatalf("expected no thaw approvals, got %d", len(store.runs))
	}
}

func TestCreateDecisionShowsValidationError(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	store := &fakeStatusDecisionStore{err: statusresult.ValidationError{Message: "missing required thaw approval fields: reason"}}
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
	if !strings.Contains(recorder.Body.String(), "missing required thaw approval fields") {
		t.Fatalf("expected validation message in body, got %q", recorder.Body.String())
	}
}

func TestCreateDecisionHidesInternalErrorDetails(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
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
	publication := statuspublication.Publication{ID: 1, StatusResultID: 7, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", DeliveryMode: statuspublication.DeliveryModeForgejoStatus, CreatedAt: createdAt, UpdatedAt: createdAt}
	attempt := statuspublication.Attempt{ID: 1, PublicationID: publication.ID, StatusResultID: publication.StatusResultID, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultFailed, Error: "permission denied", AttemptedAt: createdAt.Add(time.Minute)}
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
	for _, want := range []string{"Status diagnostics", "Status publishing", "Latest desired statuses", "Recent publication attempts", "taua-almeida/thawguard", "#42", "main", "abc123", "thawguard/freeze", "failure", "forgejo_status", "failed", "permission denied", "Branch is frozen", "2026-06-29 17:30 UTC", "2026-06-29 17:31 UTC", `datetime="2026-06-29T17:30:00Z"`, `datetime="2026-06-29T17:31:00Z"`, "data-timezone-note", "Publication errors are sanitized before storage", "bypass cooperative enforcement", "publications-repo-filter", `hx-target="#publications-live"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	for _, stale := range []string{"dry-run", "dry_run", "shadow mode", "Shadow", "would be posted", "what would publish", "Back to activity", "tg-responsive-table", "tg-mobile-card-list"} {
		if strings.Contains(body, stale) {
			t.Fatalf("expected publications page not to mention %q, got %q", stale, body)
		}
	}
}

func TestPublicationsPageShowsEmptyStatesPerTable(t *testing.T) {
	server := NewServer(Config{
		AppName:                "Thawguard",
		RepositoryStore:        &fakeRepositoryStore{},
		StatusPublicationStore: &fakeStatusPublicationStore{},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/publications", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"No desired statuses yet", "enforcement-active repository evaluates pull requests", "No publication attempts yet", "after status publication begins", "0 statuses", "0 attempts"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "data-timezone-note") {
		t.Fatalf("expected no timezone note without rows, got %q", body)
	}
}

func TestPublicationsPageShowsAttemptsEmptyStateAlone(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	createdAt := time.Date(2026, 6, 29, 17, 30, 0, 0, time.UTC)
	publication := statuspublication.Publication{ID: 1, StatusResultID: 7, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusPending, Description: "Thawguard is evaluating the freeze state for this head", DeliveryMode: statuspublication.DeliveryModeForgejoStatus, CreatedAt: createdAt}
	server := NewServer(Config{
		AppName:                "Thawguard",
		RepositoryStore:        &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		StatusPublicationStore: &fakeStatusPublicationStore{publications: []statuspublication.Publication{publication}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/publications", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"taua-almeida/thawguard", "pending", "No publication attempts yet", "2026-06-29 17:30 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "No desired statuses yet") {
		t.Fatalf("expected desired-statuses table to render rows, got %q", body)
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

func TestPublicationsPageFiltersAndPaginates(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	repo2 := domain.Repository{ID: 2, Owner: "taua-almeida", Name: "ice-station", Forge: "forgejo", DefaultBranch: "main"}
	createdAt := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	publications := make([]statuspublication.Publication, 0, 25)
	for i := range 22 {
		publications = append(publications, statuspublication.Publication{ID: int64(100 - i), RepositoryID: repo.ID, PullRequestIndex: 100 - i, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", DeliveryMode: statuspublication.DeliveryModeForgejoStatus, CreatedAt: createdAt, UpdatedAt: createdAt.Add(-time.Duration(i) * time.Minute)})
	}
	for i := range 3 {
		publications = append(publications, statuspublication.Publication{ID: int64(10 - i), RepositoryID: repo2.ID, PullRequestIndex: 10 - i, TargetBranch: "main", HeadSHA: "def456", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "No active freeze applies to this pull request", DeliveryMode: statuspublication.DeliveryModeForgejoStatus, CreatedAt: createdAt, UpdatedAt: createdAt.Add(-time.Duration(22+i) * time.Minute)})
	}
	attempts := []statuspublication.Attempt{
		{ID: 4, RepositoryID: repo.ID, PullRequestIndex: 100, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultPosted, AttemptedAt: createdAt},
		{ID: 3, RepositoryID: repo.ID, PullRequestIndex: 99, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultFailed, Error: "permission denied", AttemptedAt: createdAt.Add(-time.Minute)},
		{ID: 2, RepositoryID: repo2.ID, PullRequestIndex: 10, TargetBranch: "main", HeadSHA: "def456", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultPosted, AttemptedAt: createdAt.Add(-2 * time.Minute)},
		{ID: 1, RepositoryID: repo2.ID, PullRequestIndex: 9, TargetBranch: "main", HeadSHA: "def456", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultFailed, Error: "forge returned 500", AttemptedAt: createdAt.Add(-3 * time.Minute)},
	}
	server := NewServer(Config{
		AppName:                "Thawguard",
		RepositoryStore:        &fakeRepositoryStore{repositories: []domain.Repository{repo, repo2}},
		StatusPublicationStore: &fakeStatusPublicationStore{publications: publications, attempts: attempts},
	})

	get := func(target string) (int, string) {
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		return recorder.Code, recorder.Body.String()
	}

	code, body := get("/publications")
	if code != http.StatusOK || !strings.Contains(body, "25 statuses") || !strings.Contains(body, "Showing 1–20 of 25 statuses") {
		t.Fatalf("expected first desired-statuses page, status=%d body=%q", code, body)
	}
	if !strings.Contains(body, `href="/publications?dpage=2"`) {
		t.Fatalf("expected next-page link for the desired table, got %q", body)
	}
	if !strings.Contains(body, "4 attempts") || strings.Contains(body, "of 4 attempts") {
		t.Fatalf("expected single attempts page without pager, got %q", body)
	}

	code, body = get("/publications?dpage=2")
	if code != http.StatusOK || !strings.Contains(body, "Showing 21–25 of 25 statuses") {
		t.Fatalf("expected second desired-statuses page, status=%d body=%q", code, body)
	}
	if !strings.Contains(body, `href="/publications?dstate=failure"`) {
		t.Fatalf("expected state chip link to reset the desired page, got %q", body)
	}

	code, body = get("/publications?dpage=9")
	if code != http.StatusOK || !strings.Contains(body, "Showing 21–25 of 25 statuses") {
		t.Fatalf("expected out-of-range desired page to clamp to the last page, status=%d body=%q", code, body)
	}

	code, body = get("/publications?dstate=success")
	if code != http.StatusOK || !strings.Contains(body, "3 statuses") || !strings.Contains(body, "4 attempts") {
		t.Fatalf("expected desired filter to leave the attempts table alone, status=%d body=%q", code, body)
	}
	if !strings.Contains(body, `href="/publications?aresult=failed&amp;dstate=success"`) {
		t.Fatalf("expected attempt chip links to preserve the desired filter, got %q", body)
	}

	code, body = get("/publications?aresult=failed")
	if code != http.StatusOK || !strings.Contains(body, "2 attempts") || !strings.Contains(body, "25 statuses") {
		t.Fatalf("expected attempt filter to leave the desired table alone, status=%d body=%q", code, body)
	}

	code, body = get("/publications?repo=2")
	if code != http.StatusOK || !strings.Contains(body, "3 statuses") || !strings.Contains(body, "2 attempts") {
		t.Fatalf("expected repository filter to narrow both tables, status=%d body=%q", code, body)
	}
	if !strings.Contains(body, `<option value="2" selected>taua-almeida/ice-station</option>`) {
		t.Fatalf("expected repository select to mark the active repository, got %q", body)
	}
	if strings.Contains(body, "taua-almeida/thawguard</span>") {
		t.Fatalf("expected repository filter to hide other repositories' rows, got %q", body)
	}

	code, body = get("/publications?dstate=pending")
	if code != http.StatusOK || !strings.Contains(body, "No matching statuses") || !strings.Contains(body, "Switch filters to see other desired statuses.") {
		t.Fatalf("expected filtered empty state to keep the chips visible, status=%d body=%q", code, body)
	}

	code, body = get("/publications?dstate=bogus&aresult=bogus")
	if code != http.StatusOK || !strings.Contains(body, "25 statuses") || !strings.Contains(body, "4 attempts") {
		t.Fatalf("expected unknown filters to fall back to all, status=%d body=%q", code, body)
	}
}

func TestPublicationsPageServesHtmxFragment(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", StatusPublicationStore: &fakeStatusPublicationStore{}})

	request := httptest.NewRequest(http.MethodGet, "/publications?dstate=failure", nil)
	request.Header.Set("HX-Request", "true")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `id="publications-live"`) {
		t.Fatalf("expected htmx fragment, status=%d body=%q", recorder.Code, body)
	}
	if strings.Contains(body, "shell-nav-item") || strings.Contains(body, "<html") {
		t.Fatalf("expected fragment without the shell, got %q", body)
	}
	if vary := recorder.Header().Values("Vary"); !containsString(vary, "HX-Request") {
		t.Fatalf("expected Vary: HX-Request on publications responses, got %v", vary)
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
	for _, want := range []string{"Webhook deliveries", "Signed webhook deliveries", "3 deliveries", "Times shown in UTC.", "taua-almeida/thawguard", `title="delivery-processed"`, "pull_request · opened", "Verified", "Processed", `title="delivery-retry"`, "pull_request · synchronized", "Retryable failure", "webhook processing failed", `title="delivery-processing"`, "Processing", `aria-sort="descending"`, "2026-06-30 12:00 UTC", "cooperative enforcement", "does not store or render raw webhook payloads"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	for _, unwanted := range []string{"Webhook diagnostics", "Rows per page", "tg-table-toolbar", "tg-responsive-table"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected body not to contain %q, got %q", unwanted, body)
		}
	}
	if strings.Contains(body, "raw webhook payload:") || strings.Contains(body, "X-Hub-Signature") {
		t.Fatalf("expected page not to render raw webhook details, got %q", body)
	}
}

func TestWebhooksPageExcludesActivityAndStatusAttempts(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	createdAt := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	event := audit.Event{Action: audit.ActionThawExceptionApproved, SubjectType: audit.SubjectTypeThawException, SubjectID: "5", DetailsJSON: `{"repository_id":"1","pull_request_index":"42","reason":"activity-only-marker"}`, CreatedAt: createdAt}
	attempt := statuspublication.Attempt{ID: 9, PublicationID: 8, StatusResultID: 7, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "PR is explicitly thawed during an active freeze", Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultPosted, AttemptedAt: createdAt.Add(time.Minute)}
	server := NewServer(Config{
		AppName:                "Thawguard",
		RepositoryStore:        &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore:   &fakeWebhookDeliveryStore{},
		AuditStore:             &fakeAuditStore{events: []audit.Event{event}},
		StatusPublicationStore: &fakeStatusPublicationStore{attempts: []statuspublication.Attempt{attempt}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, unwanted := range []string{"System activity", "Status publication attempts", "activity-only-marker", "PR is explicitly thawed during an active freeze", "forgejo_status"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected webhook delivery page not to contain %q, got %q", unwanted, body)
		}
	}
	if !strings.Contains(body, "Webhook deliveries") || !strings.Contains(body, "No webhook deliveries yet") {
		t.Fatalf("expected dedicated webhook delivery page with empty state, got %q", body)
	}
}

func TestActivityMappingsCoverEveryKnownAuditAction(t *testing.T) {
	if len(activityActionDefinitions) != len(audit.KnownActions()) {
		t.Fatalf("expected %d activity definitions, got %d", len(audit.KnownActions()), len(activityActionDefinitions))
	}
	for _, action := range audit.KnownActions() {
		view := activityEventViewForEvent(nil, nil, audit.Event{Action: action, SubjectType: audit.SubjectTypeRepository, SubjectID: "1", DetailsJSON: `{}`})
		if view.ActionLabel == "Unrecognized activity" || view.ActionLabel == "" || view.Outcome == "" || view.Target == "" || view.Detail == "" {
			t.Fatalf("audit action %q lacks a complete curated activity mapping: %+v", action, view)
		}
	}
}

func TestActivityMappingCoversCurrentFamilies(t *testing.T) {
	repositories := map[int64]domain.Repository{1: {ID: 1, Owner: "taua-almeida", Name: "thawguard"}}
	users := map[int64]auth.User{42: {ID: 42, DisplayName: "Ada Operator"}}
	cases := []struct {
		name        string
		action      string
		subjectType string
		subjectID   string
		details     string
		outcome     string
		contains    []string
	}{
		{name: "repository creation", action: audit.ActionRepositoryCreated, subjectType: audit.SubjectTypeRepository, subjectID: "1", details: `{"default_branch":"main"}`, outcome: "Added", contains: []string{"taua-almeida/thawguard", "Default branch main"}},
		{name: "readiness check", action: audit.ActionRepositorySetupCheckRun, subjectType: audit.SubjectTypeRepository, subjectID: "1", details: `{"repository_id":1,"managed_branch_count":2,"ok_count":7,"warning_count":1,"failed_count":0,"webhook_evidence_fresh":true}`, outcome: "Checked", contains: []string{"7 passed", "2 managed branches", "webhook evidence fresh"}},
		{name: "enforcement success", action: audit.ActionRepositoryEnforcementActivated, subjectType: audit.SubjectTypeRepository, subjectID: "1", details: `{"repository_id":"1","open_pull_request_count":"3","statuses_posted":"2","statuses_failed":"0"}`, outcome: "Succeeded", contains: []string{"3 open PRs", "2 statuses posted"}},
		{name: "enforcement failure", action: audit.ActionRepositoryEnforcementActivateFail, subjectType: audit.SubjectTypeRepository, subjectID: "1", details: `{"repository_id":"1","reason":"status publication failed","enforcement_state":"unhealthy"}`, outcome: "Failed", contains: []string{"status publication failed", "state unhealthy"}},
		{name: "runtime failure", action: audit.ActionRepositoryRuntimeConvergenceFail, subjectType: audit.SubjectTypeRepository, subjectID: "1", details: `{"repository_id":"1","reason":"runtime enforcement convergence failed","enforcement_state":"unhealthy"}`, outcome: "Failed", contains: []string{"Automatic recovery remains pending"}},
		{name: "freeze create", action: audit.ActionBranchFreezeCreated, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "7", details: `{"repository_id":"1","branch":"main","reason":"release"}`, outcome: "Frozen", contains: []string{"main", "release"}},
		{name: "freeze create without reason", action: audit.ActionBranchFreezeCreated, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "7", details: `{"repository_id":"1","branch":"main","reason":""}`, outcome: "Frozen", contains: []string{"Reason: none."}},
		{name: "freeze lift", action: audit.ActionBranchFreezeEnded, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "7", details: `{"repository_id":"1","branch":"main","reason":"release"}`, outcome: "Lifted", contains: []string{"main"}},
		{name: "freeze cancel", action: audit.ActionBranchFreezeCancelled, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "7", details: `{"repository_id":"1","branch":"main","reason":"mistake"}`, outcome: "Cancelled", contains: []string{"mistake"}},
		{name: "schedule create", action: audit.ActionFreezeScheduleCreated, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "8", details: `{"repository_id":"1","branch":"release","starts_at":"2026-07-14T10:00:00Z","planned_ends_at":"2026-07-14T12:00:00Z","reason":"window"}`, outcome: "Scheduled", contains: []string{"2026-07-14 10:00 UTC", "window"}},
		{name: "schedule edit", action: audit.ActionFreezeScheduleUpdated, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "8", details: `{"repository_id":"1","branch":"release","reason_before":"before","reason_after":"after","starts_at_before":"2026-07-14T10:00:00Z","starts_at_after":"2026-07-14T11:00:00Z","planned_ends_at_before":"","planned_ends_at_after":"2026-07-14T13:00:00Z"}`, outcome: "Changed", contains: []string{"Reason before → after", "planned unfreeze none → 2026-07-14 13:00 UTC"}},
		{name: "schedule edit clearing the reason", action: audit.ActionFreezeScheduleUpdated, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "8", details: `{"repository_id":"1","branch":"release","reason_before":"before","reason_after":"","starts_at_before":"2026-07-14T10:00:00Z","starts_at_after":"2026-07-14T11:00:00Z","planned_ends_at_before":"","planned_ends_at_after":""}`, outcome: "Changed", contains: []string{"Reason before → none"}},
		{name: "automatic schedule activation", action: audit.ActionFreezeScheduleActivated, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "8", details: `{"repository_id":"1","branch":"release","starts_at":"2026-07-14T10:00:00Z","reason":"window"}`, outcome: "Started", contains: []string{"Started 2026-07-14 10:00 UTC"}},
		{name: "start now", action: audit.ActionFreezeScheduleStartedNow, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "8", details: `{"repository_id":"1","branch":"release","starts_at":"2026-07-13T10:00:00Z","planned_ends_at":"2026-07-14T13:00:00Z","reason":"window"}`, outcome: "Started", contains: []string{"planned unfreeze 2026-07-14 13:00 UTC"}},
		{name: "planned unfreeze", action: audit.ActionFreezeSchedulePlannedUnfreeze, subjectType: audit.SubjectTypeBranchFreeze, subjectID: "8", details: `{"repository_id":"1","branch":"release","planned_ends_at":"2026-07-14T13:00:00Z","reason":"window"}`, outcome: "Completed", contains: []string{"Planned unfreeze 2026-07-14 13:00 UTC"}},
		{name: "recurring schedule create", action: audit.ActionScheduleCreated, subjectType: audit.SubjectTypeSchedule, subjectID: "3", details: `{"repository_id":"1","branch":"main","name":"Nightly release lock","kind":"weekly","timezone":"America/Sao_Paulo","reason":"nightly deploy quiet hours"}`, outcome: "Created", contains: []string{"main", "Nightly release lock", "weekly", "America/Sao_Paulo", "nightly deploy quiet hours"}},
		{name: "recurring schedule create without reason", action: audit.ActionScheduleCreated, subjectType: audit.SubjectTypeSchedule, subjectID: "3", details: `{"repository_id":"1","branch":"main","name":"Weekend lock","kind":"dated","timezone":"UTC","reason":""}`, outcome: "Created", contains: []string{"Weekend lock", "dated", "Reason: none."}},
		{name: "recurring schedule delete", action: audit.ActionScheduleDeleted, subjectType: audit.SubjectTypeSchedule, subjectID: "3", details: `{"repository_id":"1","branch":"main","name":"Nightly release lock","kind":"weekly","timezone":"America/Sao_Paulo","reason":"nightly deploy quiet hours"}`, outcome: "Deleted", contains: []string{"Nightly release lock", "America/Sao_Paulo"}},
		{name: "recurring schedule rules added", action: audit.ActionScheduleRulesAdded, subjectType: audit.SubjectTypeSchedule, subjectID: "3", details: `{"repository_id":"1","branch":"main","name":"Nightly release lock","days":"Mon, Tue, Wed","start_time":"18:00","end_time":"08:00","end_day":"next day"}`, outcome: "Rules added", contains: []string{"Nightly release lock", "Mon, Tue, Wed", "18:00", "08:00", "next day"}},
		{name: "recurring schedule rule removed", action: audit.ActionScheduleRuleRemoved, subjectType: audit.SubjectTypeSchedule, subjectID: "3", details: `{"repository_id":"1","branch":"main","name":"Nightly release lock","days":"Mon","start_time":"18:00","end_time":"08:00","end_day":"next day"}`, outcome: "Rule removed", contains: []string{"Nightly release lock", "Mon", "18:00"}},
		{name: "single thaw", action: audit.ActionThawExceptionApproved, subjectType: audit.SubjectTypeThawException, subjectID: "9", details: `{"repository_id":"1","pull_request_index":"42","target_branch":"main","head_sha":"abcdef1234567890","reason":"production fix"}`, outcome: "Approved", contains: []string{"PR #42", "abcdef123456", "production fix"}},
		{name: "shared thaw", action: audit.ActionThawExceptionSharedHeadApproved, subjectType: audit.SubjectTypeThawException, subjectID: "1:abcdef", details: `{"repository_id":"1","created_pull_request_indexes":"42,43","already_covered_pull_request_indexes":"","created_pull_request_count":"2","already_covered_pull_request_count":"0","head_sha":"abcdef123456","reason":"shared fix"}`, outcome: "Approved", contains: []string{"shared head abcdef123456", "New exceptions: #42, #43", "Confirmation reason: shared fix"}},
		{name: "roles", action: audit.ActionUserRolesUpdated, subjectType: audit.SubjectTypeUser, subjectID: "42", details: `{"roles_before":"viewer","roles_after":"freezer,viewer"}`, outcome: "Changed", contains: []string{"Ada Operator (User #42)", "Viewer → Freezer, Viewer"}},
		{name: "disabled", action: audit.ActionUserDisabled, subjectType: audit.SubjectTypeUser, subjectID: "42", details: `{}`, outcome: "Disabled", contains: []string{"sessions revoked"}},
		{name: "enabled", action: audit.ActionUserEnabled, subjectType: audit.SubjectTypeUser, subjectID: "42", details: `{}`, outcome: "Enabled", contains: []string{"sessions were not restored"}},
		{name: "password changed", action: audit.ActionUserPasswordChanged, subjectType: audit.SubjectTypeUser, subjectID: "42", details: `{}`, outcome: "Changed", contains: []string{"Self-service password change"}},
		{name: "password reset", action: audit.ActionUserPasswordReset, subjectType: audit.SubjectTypeUser, subjectID: "42", details: `{}`, outcome: "Reset", contains: []string{"required at next login"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			view := activityEventViewForEvent(repositories, users, audit.Event{Action: test.action, SubjectType: test.subjectType, SubjectID: test.subjectID, DetailsJSON: test.details})
			if view.Outcome != test.outcome {
				t.Fatalf("expected outcome %q, got %+v", test.outcome, view)
			}
			visible := view.ActionLabel + " " + view.Target + " " + view.Detail
			for _, want := range test.contains {
				if !strings.Contains(visible, want) {
					t.Fatalf("expected mapping to contain %q, got %+v", want, view)
				}
			}
		})
	}
}

func TestActivityActorAndMissingTargetResolution(t *testing.T) {
	actorID := int64(42)
	users := map[int64]auth.User{42: {ID: 42, DisplayName: "Ada Operator"}}
	base := audit.Event{ActorUserID: &actorID, Action: audit.ActionRepositoryCreated, SubjectType: audit.SubjectTypeRepository, SubjectID: "99", DetailsJSON: `{}`}
	view := activityEventViewForEvent(nil, users, base)
	if view.Actor != "Ada Operator" || view.Target != "Repository #99" {
		t.Fatalf("unexpected current-user or missing-repository resolution: %+v", view)
	}

	missingActorID := int64(77)
	base.ActorUserID = &missingActorID
	base.Action = audit.ActionUserDisabled
	base.SubjectType = audit.SubjectTypeUser
	base.SubjectID = "88"
	view = activityEventViewForEvent(nil, users, base)
	if view.Actor != "User #77" || view.Target != "User #88" {
		t.Fatalf("unexpected missing-user fallbacks: %+v", view)
	}

	for _, test := range []struct {
		details string
		actor   string
	}{
		{details: `{"actor_kind":"bootstrap_admin"}`, actor: "Bootstrap admin"},
		{details: `{"actor_kind":"system","actor_role":"scheduler"}`, actor: "Scheduler"},
		{details: `{"actor_kind":"system","actor_role":"reconciliation_runner"}`, actor: "Reconciliation runner"},
		{details: `{"actor_kind":"system","actor_role":"runtime"}`, actor: "Runtime process"},
		{details: `{"actor_kind":"untrusted-actor","actor_role":"secret-token"}`, actor: "Unknown system actor"},
	} {
		view = activityEventViewForEvent(nil, nil, audit.Event{Action: audit.ActionRepositoryCreated, SubjectType: audit.SubjectTypeRepository, SubjectID: "1", DetailsJSON: test.details})
		if view.Actor != test.actor || strings.Contains(view.Actor, "secret-token") {
			t.Fatalf("unexpected allowlisted system actor for %s: %+v", test.details, view)
		}
	}
}

func TestActivityUnknownAndMalformedEventsFailSafely(t *testing.T) {
	actorID := int64(42)
	for _, event := range []audit.Event{
		{ActorUserID: &actorID, Action: "repository.future_secret_action", SubjectType: audit.SubjectTypeRepository, SubjectID: "7", DetailsJSON: `{"token":"raw-secret-marker"}`},
		{ActorUserID: &actorID, Action: audit.ActionRepositoryCreated, SubjectType: audit.SubjectTypeRepository, SubjectID: "7", DetailsJSON: `{"token":"raw-secret-marker"`},
	} {
		view := activityEventViewForEvent(nil, nil, event)
		visible := view.Actor + view.ActionLabel + view.Target + view.Outcome + view.Detail
		if view.ActionLabel != "Unrecognized activity" || view.Outcome != "Unknown" || view.Detail != "Stored audit details could not be displayed safely." || !strings.Contains(view.Target, "Repository #7") {
			t.Fatalf("expected safe fallback, got %+v", view)
		}
		for _, raw := range []string{"future_secret_action", "raw-secret-marker", event.DetailsJSON} {
			if strings.Contains(visible, raw) {
				t.Fatalf("safe fallback leaked %q in %q", raw, visible)
			}
		}
	}
}

func TestActivityPageRendersPrimaryChronologicalFeedWithoutDiagnostics(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard"}
	newest := audit.Event{ID: 2, Action: audit.ActionThawExceptionApproved, SubjectType: audit.SubjectTypeThawException, SubjectID: "9", DetailsJSON: `{"actor_kind":"bootstrap_admin","repository_id":"1","pull_request_index":"42","target_branch":"main","head_sha":"abcdef123456","reason":"fix <b>now</b>","token":"secret-token"}`, CreatedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)}
	older := audit.Event{ID: 1, Action: audit.ActionRepositoryCreated, SubjectType: audit.SubjectTypeRepository, SubjectID: "1", DetailsJSON: `{"actor_kind":"system","actor_role":"runtime","default_branch":"main"}`, CreatedAt: time.Date(2026, 7, 13, 11, 0, 0, 0, time.UTC)}
	auditStore := &fakeAuditStore{events: []audit.Event{newest, older}}
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		AuditStore:      auditStore,
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/activity", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected activity without diagnostic stores, status=%d body=%q", recorder.Code, body)
	}
	if auditStore.requestedLimit != activityPageSize {
		t.Fatalf("expected activity to request one page of %d events, got %d", activityPageSize, auditStore.requestedLimit)
	}
	for _, want := range []string{"Activity", "Chronological audit history", "Recent activity", "2 events", "Times shown in UTC.", "When", "Actor", "Event", "Target", "Details", "Bootstrap admin", "Single-PR thaw", "taua-almeida/thawguard → PR #42", "Approved", "fix &lt;b&gt;now&lt;/b&gt;", "Runtime process", "Repository added", "2026-07-13 12:00 UTC", `datetime="2026-07-13T12:00:00Z"`, "Freeze control", "collaborators with sufficient forge permissions can still bypass cooperative enforcement", `id="activity-live"`, `href="/activity"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected activity body to contain %q, got %q", want, body)
		}
	}
	if strings.Index(body, "Single-PR thaw") > strings.Index(body, "Repository added") {
		t.Fatalf("expected newest event first, got %q", body)
	}
	for _, unwanted := range []string{"secret-token", "raw webhook payload", "X-Hub-Signature", "repository.future_secret_action", "fix <b>now</b>", "Operational diagnostics"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("activity leaked or rendered unsafe value %q", unwanted)
		}
	}
}

func TestActivityFilterActionsGroupKnownActions(t *testing.T) {
	if actions := activityFilterActions("all"); actions != nil {
		t.Fatalf("expected no action filter for all, got %v", actions)
	}
	failures := activityFilterActions("failures")
	if len(failures) == 0 || !sort.StringsAreSorted(failures) {
		t.Fatalf("expected sorted non-empty failure actions, got %v", failures)
	}
	for _, action := range failures {
		if activityActionDefinitions[action].OutcomeClass != "failed" {
			t.Fatalf("failures chip includes non-failed action %q", action)
		}
	}
	prefixes := map[string][]string{
		"freeze":       {"branch_freeze.", "freeze_schedule.", "schedule.", "thaw_exception."},
		"repositories": {"repository."},
		"users":        {"user."},
	}
	for filter, allowed := range prefixes {
		actions := activityFilterActions(filter)
		if len(actions) == 0 {
			t.Fatalf("expected %s chip to cover known actions", filter)
		}
		for _, action := range actions {
			matched := false
			for _, prefix := range allowed {
				if strings.HasPrefix(action, prefix) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("%s chip includes out-of-family action %q", filter, action)
			}
		}
	}
}

func TestActivityPageFiltersAndPaginates(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard"}
	events := make([]audit.Event, 0, 25)
	for i := range 22 {
		events = append(events, audit.Event{ID: int64(100 - i), Action: audit.ActionRepositoryCreated, SubjectType: audit.SubjectTypeRepository, SubjectID: "1", DetailsJSON: `{"default_branch":"main"}`, CreatedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Minute)})
	}
	for i := range 3 {
		events = append(events, audit.Event{ID: int64(10 - i), Action: audit.ActionBranchFreezeCreated, SubjectType: audit.SubjectTypeBranchFreeze, SubjectID: "1", DetailsJSON: `{"repository_id":"1","branch":"main"}`, CreatedAt: time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Minute)})
	}
	server := NewServer(Config{
		AppName:         "Thawguard",
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		AuditStore:      &fakeAuditStore{events: events},
	})

	get := func(target string) (int, string) {
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		return recorder.Code, recorder.Body.String()
	}

	code, body := get("/activity?filter=repositories")
	if code != http.StatusOK || !strings.Contains(body, "22 events") || !strings.Contains(body, "Showing 1–20 of 22 events") {
		t.Fatalf("expected first repositories page, status=%d body=%q", code, body)
	}
	if !strings.Contains(body, `href="/activity?filter=repositories&amp;page=2"`) {
		t.Fatalf("expected next-page link preserving the filter, got %q", body)
	}
	if strings.Contains(body, "Branch freeze") {
		t.Fatalf("expected repositories filter to hide freeze events, got %q", body)
	}

	code, body = get("/activity?filter=repositories&page=2")
	if code != http.StatusOK || !strings.Contains(body, "Showing 21–22 of 22 events") {
		t.Fatalf("expected second repositories page, status=%d body=%q", code, body)
	}

	code, body = get("/activity?filter=repositories&page=9")
	if code != http.StatusOK || !strings.Contains(body, "Showing 21–22 of 22 events") {
		t.Fatalf("expected out-of-range page to clamp to the last page, status=%d body=%q", code, body)
	}

	code, body = get("/activity?filter=freeze")
	if code != http.StatusOK || !strings.Contains(body, "3 events") || strings.Contains(body, "Showing") {
		t.Fatalf("expected single freeze page without pager, status=%d body=%q", code, body)
	}

	code, body = get("/activity?filter=users")
	if code != http.StatusOK || !strings.Contains(body, "No matching events") || !strings.Contains(body, "Switch filters to see other recorded activity.") {
		t.Fatalf("expected filtered empty state to keep the chips visible, status=%d body=%q", code, body)
	}

	code, body = get("/activity?filter=nonsense")
	if code != http.StatusOK || !strings.Contains(body, "25 events") {
		t.Fatalf("expected unknown filter to fall back to all, status=%d body=%q", code, body)
	}
}

func TestActivityPageServesHtmxFragment(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", AuditStore: &fakeAuditStore{}})

	request := httptest.NewRequest(http.MethodGet, "/activity?filter=freeze", nil)
	request.Header.Set("HX-Request", "true")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `id="activity-live"`) {
		t.Fatalf("expected htmx fragment, status=%d body=%q", recorder.Code, body)
	}
	if strings.Contains(body, "shell-nav-item") || strings.Contains(body, "<html") {
		t.Fatalf("expected fragment without the shell, got %q", body)
	}
	if vary := recorder.Header().Values("Vary"); !containsString(vary, "HX-Request") {
		t.Fatalf("expected Vary: HX-Request on activity responses, got %v", vary)
	}
}

func TestPrimaryNavigationAndDashboardLinkToActivity(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `<a class="shell-nav-item" href="/activity"`) || !strings.Contains(body, `href="/activity">View all →</a>`) {
		t.Fatalf("expected primary navigation and dashboard activity rail to link to activity, status=%d body=%q", recorder.Code, body)
	}
}

func TestUnknownPathsRenderStyled404InsteadOfDashboard(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", FreezeStore: &fakeFreezeStore{}})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `aria-label="Dashboard summary"`) {
		t.Fatalf("expected the root path to keep rendering the dashboard, status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/freezes", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Start a freeze") {
		t.Fatalf("expected known routes to keep working, status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	for _, path := range []string{"/nope", "/freezes/"} {
		recorder = httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		body := recorder.Body.String()
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected GET %s to return 404, got %d", path, recorder.Code)
		}
		if !strings.Contains(body, "Page not found") || !strings.Contains(body, "HTTP 404") || !strings.Contains(body, "Back to dashboard") {
			t.Fatalf("expected the styled 404 card for %s, got %q", path, body)
		}
		if strings.Contains(body, `aria-label="Dashboard summary"`) {
			t.Fatalf("expected %s not to render the dashboard, got %q", path, body)
		}
	}
}

func TestUnknownPathsReturn404WithSignInActionWhenSignedOut(t *testing.T) {
	ctx := context.Background()
	server := NewServer(Config{AppName: "Thawguard", AuthService: auth.NewService(newWebTestDB(t, ctx))})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/nope", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected a signed-out unknown path to 404 rather than redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if !strings.Contains(body, "Page not found") || !strings.Contains(body, `href="/login"`) || !strings.Contains(body, "Sign in") {
		t.Fatalf("expected the styled 404 card with a sign-in action, got %q", body)
	}
}

func TestActivityPageRequiresAuditStoreAndHandlesEmptyAndFailureStates(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/activity", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected missing audit store to return 503, got %d", recorder.Code)
	}

	server = NewServer(Config{AppName: "Thawguard", AuditStore: &fakeAuditStore{}})
	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/activity", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "No activity yet") {
		t.Fatalf("expected clear empty state, status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	server = NewServer(Config{AppName: "Thawguard", AuditStore: &fakeAuditStore{err: errors.New("database failed with secret-token")}})
	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/activity", nil))
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("expected generic activity failure, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestActivityPageAllowsViewer(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	if _, err := authService.CreateUser(ctx, auth.CreateUserParams{Email: "viewer@example.test", DisplayName: "Viewer", Password: "correct horse battery staple", Roles: []auth.Role{auth.RoleViewer}}); err != nil {
		t.Fatal(err)
	}
	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, AuditStore: &fakeAuditStore{}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/activity", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: viewerSession.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Activity") {
		t.Fatalf("expected viewer activity access, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestWebhooksPageFiltersAndSortsDeliveries(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	receivedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	processedAt := receivedAt.Add(time.Minute)
	deliveries := []webhook.Delivery{
		{ID: 1, RepositoryID: repo.ID, DeliveryID: "delivery-processed", Event: "pull_request", Action: "opened", ReceivedAt: receivedAt, Verified: true, ProcessedAt: &processedAt},
		{ID: 2, RepositoryID: repo.ID, DeliveryID: "delivery-retry", Event: "pull_request", Action: "synchronized", ReceivedAt: receivedAt.Add(2 * time.Minute), Verified: true, Error: "webhook processing failed"},
	}
	server := NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore: &fakeWebhookDeliveryStore{listed: deliveries},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks?processing=retryable_failure&sort=processed&dir=asc", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{`aria-sort="ascending"`, "1 delivery", `title="delivery-retry"`, "Retryable failure", "webhook processing failed"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `title="delivery-processed"`) {
		t.Fatalf("expected processed delivery to be filtered out, got %q", body)
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

func TestWebhooksPageServesHtmxFragment(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", WebhookDeliveryStore: &fakeWebhookDeliveryStore{}})

	request := httptest.NewRequest(http.MethodGet, "/webhooks?processing=received", nil)
	request.Header.Set("HX-Request", "true")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `id="webhooks-live"`) {
		t.Fatalf("expected htmx fragment, status=%d body=%q", recorder.Code, body)
	}
	if strings.Contains(body, "shell-nav-item") || strings.Contains(body, "<html") {
		t.Fatalf("expected fragment without the shell, got %q", body)
	}
	if vary := recorder.Header().Values("Vary"); !containsString(vary, "HX-Request") {
		t.Fatalf("expected Vary: HX-Request on webhooks responses, got %v", vary)
	}
}

func TestWebhooksPageQueryMapsToStoreArguments(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want fakeWebhookListCall
	}{
		{
			name: "defaults",
			url:  "/webhooks",
			want: fakeWebhookListCall{order: webhook.DeliveryOrderReceivedDesc, limit: webhooksPageSize},
		},
		{
			name: "filters sort and page",
			url:  "/webhooks?processing=processed_with_error&repo=7&sort=processed&dir=asc&page=3",
			want: fakeWebhookListCall{processing: webhook.DeliveryProcessingProcessedWithError, repositoryID: 7, order: webhook.DeliveryOrderProcessedAsc, offset: 2 * webhooksPageSize, limit: webhooksPageSize},
		},
		{
			name: "invalid values fall back to defaults",
			url:  "/webhooks?processing=bogus&repo=-4&sort=bogus&dir=down&page=0",
			want: fakeWebhookListCall{order: webhook.DeliveryOrderReceivedDesc, limit: webhooksPageSize},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeWebhookDeliveryStore{}
			server := NewServer(Config{AppName: "Thawguard", WebhookDeliveryStore: store})
			recorder := httptest.NewRecorder()
			server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tc.url, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", recorder.Code)
			}
			if len(store.listCalls) != 1 || store.listCalls[0] != tc.want {
				t.Fatalf("expected one list call %+v, got %+v", tc.want, store.listCalls)
			}
		})
	}
}

func TestWebhooksPageClampsOutOfRangePageToLastPage(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	receivedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	deliveries := make([]webhook.Delivery, 0, 25)
	for i := range 25 {
		deliveries = append(deliveries, webhook.Delivery{
			ID:           int64(i + 1),
			RepositoryID: repo.ID,
			DeliveryID:   fmt.Sprintf("delivery-%02d", i+1),
			Event:        "pull_request",
			Action:       "opened",
			ReceivedAt:   receivedAt.Add(time.Duration(i) * time.Minute),
			Verified:     true,
		})
	}
	server := NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore: &fakeWebhookDeliveryStore{listed: deliveries},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks?page=9", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"25 deliveries", `title="delivery-01"`, `title="delivery-05"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected clamped last page to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `title="delivery-25"`) {
		t.Fatalf("expected newest delivery to stay off the clamped last page, got %q", body)
	}
}

func TestWebhooksPageRepositoryFilterFormPreservesSort(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	server := NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore: &fakeWebhookDeliveryStore{},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks?processing=processed&sort=processed&dir=asc", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		`<input type="hidden" name="processing" value="processed">`,
		`<input type="hidden" name="sort" value="processed">`,
		`<input type="hidden" name="dir" value="asc">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected repository filter form to carry %q, got %q", want, body)
		}
	}

	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	body = recorder.Body.String()
	if strings.Contains(body, `name="sort"`) || strings.Contains(body, `name="dir"`) {
		t.Fatalf("expected default sort to stay out of the repository filter form, got %q", body)
	}
}

func TestWebhooksPageRedirectsAnonymousToLogin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	if _, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, WebhookDeliveryStore: &fakeWebhookDeliveryStore{}})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected unauthenticated redirect to login, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}

	// The missing-store guard answers before authentication so operators see
	// the configuration problem instead of a login page.
	noStore := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	recorder = httptest.NewRecorder()
	noStore.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected missing-store 503 before the auth redirect, got %d", recorder.Code)
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

func TestForgejoWebhookSmokeWithSQLiteStoresPostsLiveStatus(t *testing.T) {
	ctx := context.Background()
	var postedAuth string
	var postedPath string
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postedAuth = r.Header.Get("Authorization")
		postedPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer forge.Close()

	database := newWebTestDB(t, ctx)
	secretStore, err := secrets.NewAESGCMStore(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forge.URL, Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetWebhookSecret(ctx, repo.ID, "super-secret-value", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release freeze"}, actor); err != nil {
		t.Fatal(err)
	}

	pullRequestStore := pullrequest.NewStore(database)
	statusStore := statusresult.NewStore(database)
	statusService := statusresult.NewService(statusStore, freezeService)
	publicationStore := statuspublication.NewStore(database)
	livePublisher := statuspublisher.NewForgejoStatusPublisher(publicationStore, publicationStore, repository.NewStore(database), repositorySetup, func(repo domain.Repository, token string) (statuspublisher.ForgeStatusClient, error) {
		return forgejo.New(repo.BaseURL, token), nil
	})
	deliveryStore := webhook.NewDeliveryStore(database)
	processor := webhook.NewPullRequestProcessor(repository.NewStore(database), pullRequestStore, statusService, livePublisher)
	server := NewServer(Config{
		AppName:                     "Thawguard",
		RepositoryStore:             repositorySetup,
		StatusPublicationStore:      publicationStore,
		WebhookRepositoryStore:      repositorySetup,
		WebhookDeliveryStore:        deliveryStore,
		PullRequestWebhookProcessor: processor,
	})

	body := strings.ReplaceAll(pullRequestWebhookBody("opened"), "https://codeberg.org", forge.URL)
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-smoke"))

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted\n" {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	deliveries, _, err := deliveryStore.ListPage(ctx, "", 0, webhook.DeliveryOrderReceivedDesc, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].DeliveryID != "delivery-smoke" || deliveries[0].RepositoryID != repo.ID || !deliveries[0].Verified || deliveries[0].Action != "opened" || deliveries[0].ProcessedAt == nil || deliveries[0].Error != "" {
		t.Fatalf("expected processed signed delivery, got %+v", deliveries)
	}
	cached, err := pullRequestStore.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if cached.TargetBranch != "main" || cached.HeadSHA != "0123456789abcdef0123456789abcdef01234567" || cached.State != "open" {
		t.Fatalf("expected cached PR from webhook, got %+v", cached)
	}
	results, err := statusStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].RepositoryID != repo.ID || results[0].PullRequestIndex != 42 || results[0].State != domain.CommitStatusFailure || !strings.Contains(results[0].Description, "Branch is frozen") {
		t.Fatalf("expected failing freeze status result, got %+v", results)
	}
	publications, err := publicationStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 1 || publications[0].StatusResultID != results[0].ID || publications[0].HeadSHA != results[0].HeadSHA || publications[0].DeliveryMode != statuspublication.DeliveryModeForgejoStatus {
		t.Fatalf("expected forgejo publication intent, got %+v", publications)
	}
	attempts, err := publicationStore.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].PublicationID != publications[0].ID || attempts[0].StatusResultID != results[0].ID || attempts[0].Mode != statuspublication.AttemptModeForgejoStatus || attempts[0].Result != statuspublication.AttemptResultPosted {
		t.Fatalf("expected posted forgejo publication attempt, got %+v", attempts)
	}
	if postedAuth != "token live-status-token-123" || !strings.Contains(postedPath, "/statuses/0123456789abcdef0123456789abcdef01234567") {
		t.Fatalf("expected live forge status post, auth=%q path=%q", postedAuth, postedPath)
	}

	webhooksPage := httptest.NewRecorder()
	server.Routes().ServeHTTP(webhooksPage, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	if webhooksPage.Code != http.StatusOK || !strings.Contains(webhooksPage.Body.String(), "delivery-smoke") || !strings.Contains(webhooksPage.Body.String(), "processed") {
		t.Fatalf("expected webhook delivery page to show processed delivery, status=%d body=%q", webhooksPage.Code, webhooksPage.Body.String())
	}
	publicationsPage := httptest.NewRecorder()
	server.Routes().ServeHTTP(publicationsPage, httptest.NewRequest(http.MethodGet, "/publications", nil))
	if publicationsPage.Code != http.StatusOK || !strings.Contains(publicationsPage.Body.String(), "posted") || !strings.Contains(publicationsPage.Body.String(), "Branch is frozen") {
		t.Fatalf("expected publications page to show posted attempt, status=%d body=%q", publicationsPage.Code, publicationsPage.Body.String())
	}
}

func TestForgejoWebhookForSetupIncompleteRepositoryRecordsEvidenceWithoutPublishing(t *testing.T) {
	ctx := context.Background()
	forgeCalls := 0
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forgeCalls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer forge.Close()

	database := newWebTestDB(t, ctx)
	secretStore, err := secrets.NewAESGCMStore(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forge.URL, Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetWebhookSecret(ctx, repo.ID, "super-secret-value", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", actor); err != nil {
		t.Fatal(err)
	}

	pullRequestStore := pullrequest.NewStore(database)
	statusStore := statusresult.NewStore(database)
	publicationStore := statuspublication.NewStore(database)
	livePublisher := statuspublisher.NewForgejoStatusPublisher(publicationStore, publicationStore, repository.NewStore(database), repositorySetup, func(repo domain.Repository, token string) (statuspublisher.ForgeStatusClient, error) {
		return forgejo.New(repo.BaseURL, token), nil
	})
	deliveryStore := webhook.NewDeliveryStore(database)
	processor := webhook.NewPullRequestProcessor(repository.NewStore(database), pullRequestStore, statusresult.NewService(statusStore, freeze.NewService(database)), livePublisher)
	server := NewServer(Config{
		AppName:                     "Thawguard",
		RepositoryStore:             repositorySetup,
		WebhookRepositoryStore:      repositorySetup,
		WebhookDeliveryStore:        deliveryStore,
		PullRequestWebhookProcessor: processor,
	})

	body := strings.ReplaceAll(pullRequestWebhookBody("opened"), "https://codeberg.org", forge.URL)
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-inactive"))

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted\n" {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	deliveries, _, err := deliveryStore.ListPage(ctx, "", 0, webhook.DeliveryOrderReceivedDesc, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || !deliveries[0].Verified || deliveries[0].ProcessedAt == nil || deliveries[0].Error != "" {
		t.Fatalf("expected verified processed delivery evidence, got %+v", deliveries)
	}
	cached, err := pullRequestStore.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if cached.HeadSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("expected PR cache evidence, got %+v", cached)
	}
	results, err := statusStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no status result for setup-incomplete repository, got %+v", results)
	}
	publications, err := publicationStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := publicationStore.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 0 || len(attempts) != 0 {
		t.Fatalf("expected no publication intent or attempt, got intents=%+v attempts=%+v", publications, attempts)
	}
	if forgeCalls != 0 {
		t.Fatalf("expected no forge status call, got %d", forgeCalls)
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
		"reason":             {"production fix"},
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

func scheduledFreezeCreateForm() url.Values {
	return url.Values{
		"repository_id":           {"1"},
		"branch":                  {"main"},
		"starts_at":               {"2026-07-10T18:00"},
		"planned_ends_at":         {"2026-07-13T09:00"},
		"reason":                  {"weekend freeze"},
		"timezone_offset_minutes": {"0"},
	}
}

func scheduledFreezeEditForm(id int64) url.Values {
	return url.Values{
		"freeze_id":               {strconv.FormatInt(id, 10)},
		"starts_at":               {"2099-07-10T18:00"},
		"planned_ends_at":         {"2099-07-13T09:00"},
		"reason":                  {"updated release"},
		"timezone_offset_minutes": {"0"},
	}
}

func setWebSessionRoles(t *testing.T, server *Server, roles auth.RoleSet) sessionState {
	t.Helper()
	session, err := server.sessions.create()
	if err != nil {
		t.Fatal(err)
	}
	session.Roles = roles
	if len(roles) > 0 {
		session.Role = roles[0]
	}
	server.sessions.mu.Lock()
	server.sessions.sessions[session.ID] = session
	server.sessions.mu.Unlock()
	return session
}

func postScheduledFreezeForm(t *testing.T, server *Server, cookie *http.Cookie, path string, form url.Values, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != wantStatus {
		t.Fatalf("%s: expected status %d, got %d body=%q", path, wantStatus, recorder.Code, recorder.Body.String())
	}
	return recorder
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

func getScheduledFreezeForm(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected scheduled freeze form status 200, got %d", recorder.Code)
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
	return namedCookieFromRecorder(t, recorder, sessionCookieName)
}

func namedCookieFromRecorder(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("expected %s cookie", name)
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

func newWebTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := db.LoadMigrations(webTestMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return database
}

func webTestMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
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
	listCalls    []fakeWebhookListCall
	deliveries   map[int64]webhook.Delivery
	deliveryByID map[string]int64
}

type fakeWebhookListCall struct {
	processing   string
	repositoryID int64
	order        webhook.DeliveryOrder
	offset       int
	limit        int
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

// fakeWebhookDeliveryProcessing mirrors the store's derived-state partition
// so handler tests can exercise the ?processing= filter against listed rows.
func fakeWebhookDeliveryProcessing(delivery webhook.Delivery) string {
	switch {
	case delivery.ProcessedAt != nil && delivery.Error == "":
		return webhook.DeliveryProcessingProcessed
	case delivery.ProcessedAt != nil:
		return webhook.DeliveryProcessingProcessedWithError
	case delivery.ProcessingStartedAt != nil:
		return webhook.DeliveryProcessingProcessing
	case delivery.Error != "":
		return webhook.DeliveryProcessingRetryableFailure
	default:
		return webhook.DeliveryProcessingReceived
	}
}

func (s *fakeWebhookDeliveryStore) ListPage(ctx context.Context, processing string, repositoryID int64, order webhook.DeliveryOrder, offset, limit int) ([]webhook.Delivery, int, error) {
	s.listCalls = append(s.listCalls, fakeWebhookListCall{processing: processing, repositoryID: repositoryID, order: order, offset: offset, limit: limit})
	if s.listErr != nil {
		return nil, 0, s.listErr
	}
	matches := make([]webhook.Delivery, 0, len(s.listed))
	for _, delivery := range s.listed {
		if repositoryID > 0 && delivery.RepositoryID != repositoryID {
			continue
		}
		if processing != "" && fakeWebhookDeliveryProcessing(delivery) != processing {
			continue
		}
		matches = append(matches, delivery)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		switch order {
		case webhook.DeliveryOrderReceivedAsc:
			if !a.ReceivedAt.Equal(b.ReceivedAt) {
				return a.ReceivedAt.Before(b.ReceivedAt)
			}
			return a.ID < b.ID
		case webhook.DeliveryOrderProcessedAsc, webhook.DeliveryOrderProcessedDesc:
			if (a.ProcessedAt == nil) != (b.ProcessedAt == nil) {
				return b.ProcessedAt == nil
			}
			if a.ProcessedAt != nil && !a.ProcessedAt.Equal(*b.ProcessedAt) {
				if order == webhook.DeliveryOrderProcessedAsc {
					return a.ProcessedAt.Before(*b.ProcessedAt)
				}
				return b.ProcessedAt.Before(*a.ProcessedAt)
			}
			if order == webhook.DeliveryOrderProcessedAsc {
				return a.ID < b.ID
			}
			return a.ID > b.ID
		default:
			if !a.ReceivedAt.Equal(b.ReceivedAt) {
				return b.ReceivedAt.Before(a.ReceivedAt)
			}
			return a.ID > b.ID
		}
	})
	total := len(matches)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return nil, total, nil
	}
	end := min(offset+limit, total)
	return matches[offset:end], total, nil
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
	statusTokens        []statusTokenUpdate
	statusTokenActors   []domain.Actor
	statusTokenErr      error
	branches            map[int64][]domain.RepositoryBranch
	branchAdds          []branchUpdate
	branchRemovals      []branchUpdate
	branchActors        []domain.Actor
	branchErr           error
}

type branchUpdate struct {
	repositoryID int64
	branch       string
}

type webhookSecretUpdate struct {
	repositoryID int64
	secret       string
}

type statusTokenUpdate struct {
	repositoryID int64
	token        string
}

type fakeSetupCheckStore struct {
	checks map[int64][]setupcheck.Check
}

func (s *fakeSetupCheckStore) ListByRepository(ctx context.Context, repositoryID int64) ([]setupcheck.Check, error) {
	return s.checks[repositoryID], nil
}

type fakeSetupCheckRunner struct {
	repositories []domain.Repository
	actors       []domain.Actor
	err          error
}

type fakeStatusDecisionStore struct {
	results []statusresult.Result
	runs    []statusresult.ThawApprovalParams
	actors  []domain.Actor
	outcome statusresult.ThawApprovalOutcome
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

func (s *fakeStatusDecisionStore) ListDecisionsPage(ctx context.Context, state domain.CommitStatusState, repositoryID int64, offset, limit int) ([]statusresult.Result, int, error) {
	if s.listErr != nil {
		return nil, 0, s.listErr
	}
	var matched []statusresult.Result
	for _, result := range s.results {
		if state != "" && result.State != state {
			continue
		}
		if repositoryID > 0 && result.RepositoryID != repositoryID {
			continue
		}
		matched = append(matched, result)
	}
	total := len(matched)
	if offset >= total {
		return []statusresult.Result{}, total, nil
	}
	matched = matched[offset:]
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, total, nil
}

func (s *fakeStatusDecisionStore) ApproveThaw(ctx context.Context, params statusresult.ThawApprovalParams, actor domain.Actor) (statusresult.ThawApprovalOutcome, error) {
	if s.err != nil {
		return statusresult.ThawApprovalOutcome{}, s.err
	}
	s.runs = append(s.runs, params)
	s.actors = append(s.actors, actor)
	if s.outcome.ConfirmationRequired {
		return s.outcome, nil
	}
	headSHA := params.HeadSHA
	if headSHA == "" {
		headSHA = "abc123"
	}
	result := statusresult.Result{ID: int64(len(s.results) + 1), RepositoryID: params.RepositoryID, PullRequestIndex: params.PullRequestIndex, TargetBranch: params.TargetBranch, HeadSHA: headSHA, Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "PR is explicitly thawed during an active freeze", CreatedAt: time.Now().UTC()}
	s.results = append(s.results, result)
	return statusresult.ThawApprovalOutcome{Result: &result}, nil
}

type fakeStatusPublicationStore struct {
	publications []statuspublication.Publication
	attempts     []statuspublication.Attempt
	err          error
	attemptErr   error
}

func (s *fakeStatusPublicationStore) ListPage(ctx context.Context, state string, repositoryID int64, offset, limit int) ([]statuspublication.Publication, int, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	filtered := make([]statuspublication.Publication, 0, len(s.publications))
	for _, publication := range s.publications {
		if state != "" && string(publication.State) != state {
			continue
		}
		if repositoryID > 0 && publication.RepositoryID != repositoryID {
			continue
		}
		filtered = append(filtered, publication)
	}
	return pageSlice(filtered, offset, limit), len(filtered), nil
}

func (s *fakeStatusPublicationStore) ListAttemptsPage(ctx context.Context, result string, repositoryID int64, offset, limit int) ([]statuspublication.Attempt, int, error) {
	if s.attemptErr != nil {
		return nil, 0, s.attemptErr
	}
	if s.err != nil {
		return nil, 0, s.err
	}
	filtered := make([]statuspublication.Attempt, 0, len(s.attempts))
	for _, attempt := range s.attempts {
		if result != "" && attempt.Result != result {
			continue
		}
		if repositoryID > 0 && attempt.RepositoryID != repositoryID {
			continue
		}
		filtered = append(filtered, attempt)
	}
	return pageSlice(filtered, offset, limit), len(filtered), nil
}

// pageSlice windows a filtered fake-store result the way the real stores'
// LIMIT/OFFSET queries do.
func pageSlice[T any](items []T, offset, limit int) []T {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return nil
	}
	items = items[offset:]
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

type fakeAuditStore struct {
	events         []audit.Event
	err            error
	requestedLimit int
}

func (s *fakeAuditStore) List(ctx context.Context, limit int) ([]audit.Event, error) {
	s.requestedLimit = limit
	if s.err != nil {
		return nil, s.err
	}
	if limit > 0 && len(s.events) > limit {
		return s.events[:limit], nil
	}
	return s.events, nil
}

func (s *fakeAuditStore) ListPage(ctx context.Context, actions []string, offset, limit int) ([]audit.Event, int, error) {
	s.requestedLimit = limit
	if s.err != nil {
		return nil, 0, s.err
	}
	matched := make([]audit.Event, 0, len(s.events))
	for _, event := range s.events {
		if len(actions) == 0 || slices.Contains(actions, event.Action) {
			matched = append(matched, event)
		}
	}
	total := len(matched)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	matched = matched[offset:]
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, total, nil
}

type fakePullRequestStore struct {
	pullRequests []domain.PullRequest
	err          error
}

func (s *fakePullRequestStore) ListOpenByTargetBranch(ctx context.Context, repositoryID int64, targetBranch string) ([]domain.PullRequest, error) {
	if s.err != nil {
		return nil, s.err
	}
	var matched []domain.PullRequest
	for _, pr := range s.pullRequests {
		if pr.RepositoryID == repositoryID && pr.TargetBranch == targetBranch && pr.IsOpen() {
			matched = append(matched, pr)
		}
	}
	return matched, nil
}

func (s *fakePullRequestStore) Get(ctx context.Context, repositoryID int64, index int) (domain.PullRequest, error) {
	if s.err != nil {
		return domain.PullRequest{}, s.err
	}
	for _, pr := range s.pullRequests {
		if pr.RepositoryID == repositoryID && pr.Index == index {
			return pr, nil
		}
	}
	return domain.PullRequest{}, fmt.Errorf("scan pull request cache: %w", sql.ErrNoRows)
}

func (s *fakePullRequestStore) ListOpenByHead(ctx context.Context, repositoryID int64, headSHA string) ([]domain.PullRequest, error) {
	if s.err != nil {
		return nil, s.err
	}
	headSHA = strings.ToLower(strings.TrimSpace(headSHA))
	var matched []domain.PullRequest
	for _, pr := range s.pullRequests {
		if pr.RepositoryID == repositoryID && strings.ToLower(pr.HeadSHA) == headSHA && pr.IsOpen() {
			matched = append(matched, pr)
		}
	}
	return matched, nil
}

type fakeFreezeStore struct {
	freezes            []domain.BranchFreeze
	scheduled          []domain.BranchFreeze
	created            []freeze.CreateParams
	scheduledCreated   []freeze.ScheduleParams
	scheduledEdited    []freeze.EditScheduleParams
	ended              []int64
	cancelled          []int64
	scheduledCancelled []int64
	scheduledStarted   []int64
	actors             []domain.Actor
	err                error
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
	created := domain.BranchFreeze{ID: int64(len(s.freezes) + 1), RepositoryID: params.RepositoryID, Branch: params.Branch, Status: domain.BranchFreezeStatusActive, Active: true, Reason: params.Reason, PlannedEndsAt: params.PlannedEndsAt}
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

func (s *fakeFreezeStore) ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if limit > 0 && len(s.scheduled) > limit {
		return s.scheduled[:limit], nil
	}
	return s.scheduled, nil
}

func (s *fakeFreezeStore) ListScheduledPage(ctx context.Context, status domain.BranchFreezeStatus, offset, limit int) ([]domain.BranchFreeze, int, error) {
	matched := make([]domain.BranchFreeze, 0, len(s.scheduled))
	for _, freeze := range s.scheduled {
		if status == "" || freeze.Status == status {
			matched = append(matched, freeze)
		}
	}
	total := len(matched)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []domain.BranchFreeze{}, total, nil
	}
	matched = matched[offset:]
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, total, nil
}

func (s *fakeFreezeStore) CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.scheduledCreated = append(s.scheduledCreated, params)
	s.actors = append(s.actors, actor)
	created := domain.BranchFreeze{ID: int64(len(s.scheduled) + 1), RepositoryID: params.RepositoryID, Branch: params.Branch, Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: params.Reason, StartsAt: &params.StartsAt, PlannedEndsAt: params.PlannedEndsAt}
	s.scheduled = append(s.scheduled, created)
	return created, nil
}

func (s *fakeFreezeStore) EditScheduled(ctx context.Context, params freeze.EditScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.scheduledEdited = append(s.scheduledEdited, params)
	s.actors = append(s.actors, actor)
	return domain.BranchFreeze{ID: params.ID, Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: params.Reason, StartsAt: &params.StartsAt, PlannedEndsAt: params.PlannedEndsAt}, nil
}

func (s *fakeFreezeStore) CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.scheduledCancelled = append(s.scheduledCancelled, id)
	s.actors = append(s.actors, actor)
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusCancelled, Scheduled: true}, nil
}

func (s *fakeFreezeStore) StartScheduledNow(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.scheduledStarted = append(s.scheduledStarted, id)
	s.actors = append(s.actors, actor)
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true}, nil
}

func (r *fakeSetupCheckRunner) Run(ctx context.Context, repo domain.Repository, actor domain.Actor) ([]setupcheck.Result, error) {
	r.repositories = append(r.repositories, repo)
	r.actors = append(r.actors, actor)
	if r.err != nil {
		return nil, r.err
	}
	return []setupcheck.Result{{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "Status posting remains untested."}}, nil
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

// ListBranches falls back to each repository's default branch so pages render
// realistic managed-branch data without per-test setup.
func (s *fakeRepositoryStore) ListBranches(ctx context.Context, repositoryID int64) ([]domain.RepositoryBranch, error) {
	if s.branches != nil {
		return s.branches[repositoryID], nil
	}
	for _, repo := range s.repositories {
		if repo.ID == repositoryID && repo.DefaultBranch != "" {
			return []domain.RepositoryBranch{{ID: 1, RepositoryID: repositoryID, Name: repo.DefaultBranch, SetupStatus: "unknown"}}, nil
		}
	}
	return nil, nil
}

func (s *fakeRepositoryStore) AddBranch(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) (domain.RepositoryBranch, error) {
	if s.branchErr != nil {
		return domain.RepositoryBranch{}, s.branchErr
	}
	s.branchAdds = append(s.branchAdds, branchUpdate{repositoryID: repositoryID, branch: branch})
	s.branchActors = append(s.branchActors, actor)
	return domain.RepositoryBranch{ID: int64(len(s.branchAdds)), RepositoryID: repositoryID, Name: branch, SetupStatus: "unknown"}, nil
}

func (s *fakeRepositoryStore) RemoveBranch(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error {
	if s.branchErr != nil {
		return s.branchErr
	}
	s.branchRemovals = append(s.branchRemovals, branchUpdate{repositoryID: repositoryID, branch: branch})
	s.branchActors = append(s.branchActors, actor)
	return nil
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

func (s *fakeRepositoryStore) SetStatusToken(ctx context.Context, repositoryID int64, token string, actor domain.Actor) (domain.Repository, error) {
	if s.statusTokenErr != nil {
		return domain.Repository{}, s.statusTokenErr
	}
	s.statusTokens = append(s.statusTokens, statusTokenUpdate{repositoryID: repositoryID, token: token})
	s.statusTokenActors = append(s.statusTokenActors, actor)
	for index, repo := range s.repositories {
		if repo.ID == repositoryID {
			s.repositories[index].HasStatusToken = true
			return s.repositories[index], nil
		}
	}
	return domain.Repository{}, repositorysetup.ValidationError{Message: "repository not found"}
}

func TestDevPreviewDashboardRequiresDevMode(t *testing.T) {
	// Without DevMode the route is never registered: the path falls through
	// to the catch-all "GET /" (the real, auth-gated dashboard), so the
	// fictional preview fixtures must never appear in the response.
	prod := NewServer(Config{AppName: "Thawguard"})
	recorder := httptest.NewRecorder()
	prod.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/dashboard", nil))
	for _, leaked := range []string{"mira.frost@example.test", "Repository #17", "dev-preview-fictional-token"} {
		if strings.Contains(recorder.Body.String(), leaked) {
			t.Fatalf("expected non-dev server not to serve preview fixture %q", leaked)
		}
	}
	// The dev handler itself also re-checks the flag, so even a stray route
	// registration cannot serve the preview in production.
	recorder = httptest.NewRecorder()
	prod.handleDevPreviewDashboard(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/dashboard", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected dev preview dashboard handler to 404 without dev mode, got %d", recorder.Code)
	}

	dev := NewServer(Config{AppName: "Thawguard", DevMode: true})
	recorder = httptest.NewRecorder()
	dev.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/dashboard", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected /dev/preview/dashboard to render in dev mode, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Dashboard", "aurora/ice-station", "Repository #17", "mira.frost@example.test"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dev preview dashboard to contain %q", want)
		}
	}

	recorder = httptest.NewRecorder()
	dev.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/dashboard?variant=empty&role=viewer", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected empty-variant dev preview dashboard to render, got %d", recorder.Code)
	}
	body = recorder.Body.String()
	for _, want := range []string{"No active freezes", "No recorded activity yet.", `text-text">0 of 0`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected empty dev preview dashboard to contain %q", want)
		}
	}
}

func TestDevPreviewWebhooksRequiresDevMode(t *testing.T) {
	// Without DevMode the route is never registered and the handler re-checks
	// the flag, mirroring the other preview pages.
	prod := NewServer(Config{AppName: "Thawguard"})
	recorder := httptest.NewRecorder()
	prod.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/webhooks", nil))
	for _, leaked := range []string{"mira.frost@example.test", "f47ac10b", "dev-preview-fictional-token"} {
		if strings.Contains(recorder.Body.String(), leaked) {
			t.Fatalf("expected non-dev server not to serve preview fixture %q", leaked)
		}
	}
	recorder = httptest.NewRecorder()
	prod.handleDevPreviewWebhooks(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/webhooks", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected dev preview webhooks handler to 404 without dev mode, got %d", recorder.Code)
	}

	dev := NewServer(Config{AppName: "Thawguard", DevMode: true})
	recorder = httptest.NewRecorder()
	dev.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/webhooks", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected /dev/preview/webhooks to render in dev mode, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Webhook deliveries", "Webhook Log", "aurora/ice-station", "borealis/frost-api", "f47ac10b…", "26 deliveries", "Processed with error", "Retryable failure", `aria-sort="descending"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dev preview webhooks to contain %q", want)
		}
	}

	// The two oldest fixtures - the historical unverified receipt and the
	// unknown-repository fallback - land on the second page.
	recorder = httptest.NewRecorder()
	dev.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/webhooks?page=2", nil))
	body = recorder.Body.String()
	for _, want := range []string{"Not verified", "Repository #12"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dev preview webhooks page 2 to contain %q", want)
		}
	}

	recorder = httptest.NewRecorder()
	dev.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/webhooks?variant=empty&role=viewer", nil))
	body = recorder.Body.String()
	for _, want := range []string{"No webhook deliveries yet", "sten.hale@example.test"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected empty dev preview webhooks to contain %q", want)
		}
	}

	recorder = httptest.NewRecorder()
	dev.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/preview/webhooks?variant=empty&processing=processed", nil))
	if !strings.Contains(recorder.Body.String(), "No matching deliveries") {
		t.Fatalf("expected filtered empty dev preview webhooks to show the filtered empty state, got %q", recorder.Body.String())
	}
}
