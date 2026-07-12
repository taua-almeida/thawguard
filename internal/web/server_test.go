package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
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
	for _, want := range []string{"webhook configured", "status token configured", "Rotate secret", "Rotate token", "Connect a repository", "Credential values are write-only", "data-alert-dialog"} {
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
	if !strings.Contains(setupBody, "tg-brand-icon") || strings.Contains(setupBody, ">TG</span>") {
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
	if !strings.Contains(body, "Setup form expired") || !strings.Contains(body, "Create the first Thawguard admin") {
		t.Fatalf("expected setup csrf failure to re-render setup form, body=%q", body)
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
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, RepositoryStore: &fakeRepositoryStore{}})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: adminSession.ID}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/users", nil)
	request.AddCookie(adminCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Users & Roles") {
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
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "Users & Roles") {
		t.Fatalf("expected viewer to read repositories without admin nav, status=%d body=%q", recorder.Code, recorder.Body.String())
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
		`data-confirm-title="Rotate webhook secret?"`,
		`data-confirm-action="Reveal secret input"`,
		`data-confirm-title="Rotate status token?"`,
		`data-confirm-action="Reveal token input"`,
		`id="webhook-secret-7" class="tg-secret-form tg-credential-form" hidden data-credential-form`,
		`id="status-token-7" class="tg-secret-form tg-credential-form" hidden data-credential-form`,
		`name="webhook_secret" minlength="16" maxlength="512" autocomplete="new-password" placeholder="New webhook secret" aria-label="New webhook secret for taua-almeida/thawguard" required disabled data-credential-input`,
		`name="status_token" minlength="16" maxlength="1024" autocomplete="new-password" placeholder="New status token" aria-label="New status token for taua-almeida/thawguard" required disabled data-credential-input`,
		`data-alert-dialog hidden`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
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
	for _, want := range []string{"Bot can post statuses", "ok", "Pull request webhook configured", "failed", "Run setup check", "local placeholders for setup visibility"} {
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
	for _, want := range []string{"Create a freeze", "Preview impact", "3 open PRs", "Active Freezes", "taua-almeida/thawguard", "dev", "QA freeze", "Freeze Branch", "Lift", "Cancel", `<form method="post" action="/freezes/end" data-confirm-submit data-confirm-title="Lift freeze?"`, `data-confirm-action="Lift freeze"`, `<button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Lift</button>`, `<form method="post" action="/freezes/cancel" data-confirm-submit data-confirm-title="Cancel freeze?"`, `data-confirm-action="Cancel freeze"`, `data-alert-dialog hidden`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "window."+"confirm") {
		t.Fatalf("expected custom confirmation dialog instead of browser confirm, got %q", body)
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
	if !strings.Contains(body, "No active freezes yet") {
		t.Fatalf("expected empty active freeze state, got %q", body)
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
	if !strings.Contains(body, "No active freezes yet") {
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

func TestScheduledFreezesPageShowsFormAndWindows(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	startsAt := time.Date(2026, 7, 10, 18, 0, 0, 0, time.UTC)
	plannedEndsAt := startsAt.Add(63 * time.Hour)
	store := &fakeFreezeStore{scheduled: []domain.BranchFreeze{{ID: 9, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true, Reason: "Weekend release freeze", StartsAt: &startsAt, PlannedEndsAt: &plannedEndsAt}}}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, ScheduledFreezeStore: store})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/scheduled-freezes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Scheduled Freezes", "Create scheduled freeze", "One-time windows only", "taua-almeida/thawguard", "main", "Weekend release freeze", "2026-07-10 18:00 UTC", "2026-07-13 09:00 UTC", "upcoming", `action="/scheduled-freezes/cancel"`, `data-confirm-action="Cancel schedule"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if token := csrfTokenFromBody(t, body); token == "" {
		t.Fatal("expected CSRF token in scheduled freeze form")
	}
}

func TestCreateScheduledFreezePostsToStore(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
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
	for _, want := range []string{"Thaw Requests", "Approve a thaw exception", "Auditable exceptions", "current forge head SHA", "taua-almeida/thawguard", "Target branch", "main", "thawguard/freeze", "Blocked", "Branch is frozen", "2026-06-29 16:30 UTC"} {
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
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
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
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

func TestRenderDecisionsSharedHeadReadOnlyUserGetsNoConfirmationForm(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, StatusDecisionStore: &fakeStatusDecisionStore{}})
	confirmation := sharedHeadConfirmationViewFrom(sharedHeadOutcome("Release fix", "Other fix"), repo.ID, 42, "main", "production fix")
	session := sessionState{CSRFToken: "viewer-token", Roles: auth.RoleSet{auth.RoleAdmin}}

	recorder := httptest.NewRecorder()
	server.renderDecisions(recorder, []domain.Repository{repo}, nil, "", session, confirmation)

	body := recorder.Body.String()
	if !strings.Contains(body, "These pull requests share one commit SHA") {
		t.Fatalf("expected read-only user to still see the shared-head warning, got %q", body)
	}
	if strings.Contains(body, `name="confirm_shared_head"`) || strings.Contains(body, "Approve thaw for all") {
		t.Fatal("expected no actionable confirmation form for read-only thaw access")
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
		t.Fatalf("expected no thaw approvals, got %d", len(store.runs))
	}
}

func TestCreateDecisionShowsValidationError(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
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
	for _, want := range []string{"Audit Log", "Recent webhook deliveries", "Sanitized local metadata only", "tg-table-toolbar", "tg-responsive-table", "tg-mobile-card-list", "Rows per page", "Filter audit log", "aria-sort=\"descending\"", "Showing 3 of 3 matching rows", "3 total rows loaded", "sanitized webhook delivery metadata", "taua-almeida/thawguard", "delivery-processed", "pull_request", "opened", "verified", "processed", "delivery-retry", "synchronized", "retryable failure", "webhook processing failed", "delivery-processing", "processing", "2026-06-30 12:00 UTC"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	for _, unwanted := range []string{"Latest 25", "Local records", ">Details</a>", "Clear controls", "Processed <span class=\"tg-sort-indicator\"", ">Sort by\n", ">Direction\n"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected body not to contain %q, got %q", unwanted, body)
		}
	}
	if strings.Contains(body, "raw webhook payload:") || strings.Contains(body, "X-Hub-Signature") {
		t.Fatalf("expected page not to render raw webhook details, got %q", body)
	}
}

func TestWebhooksPageShowsSystemActivityAndStatusAttempts(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}
	createdAt := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{Action: audit.ActionThawExceptionApproved, SubjectType: audit.SubjectTypeThawException, SubjectID: "5", DetailsJSON: `{"actor_kind":"bootstrap_admin","actor_role":"admin","repository_id":"1","pull_request_index":"42","target_branch":"main","head_sha":"abc123","reason":"production fix"}`, CreatedAt: createdAt},
		{Action: audit.ActionRepositoryOpenPullRequestsSynced, SubjectType: audit.SubjectTypeRepository, SubjectID: "1", DetailsJSON: `{"repository_id":"1","full_name":"taua-almeida/thawguard","target_branch":"main","open_count":"2","closed_absent_count":"1"}`, CreatedAt: createdAt.Add(-time.Minute)},
	}
	attempt := statuspublication.Attempt{ID: 9, PublicationID: 8, StatusResultID: 7, RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "PR is explicitly thawed during an active freeze", Mode: statuspublication.AttemptModeForgejoStatus, Result: statuspublication.AttemptResultPosted, AttemptedAt: createdAt.Add(time.Minute)}
	server := NewServer(Config{
		AppName:                "Thawguard",
		RepositoryStore:        &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore:   &fakeWebhookDeliveryStore{},
		AuditStore:             &fakeAuditStore{events: events},
		StatusPublicationStore: &fakeStatusPublicationStore{attempts: []statuspublication.Attempt{attempt}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"System activity", "Status publication attempts", "Thaw approved", "Open PRs synced", "taua-almeida/thawguard PR #42", "Head abc123 on main", "production fix", "2 open from forge, 1 cached closed", "forgejo_status", "posted", "PR is explicitly thawed during an active freeze"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "secret-token") || strings.Contains(body, "X-Hub-Signature") {
		t.Fatalf("expected activity page not to render sensitive details, got %q", body)
	}
}

func TestSystemAuditEventViewShowsTruthfulSharedHeadApproval(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard"}
	repositories := map[int64]domain.Repository{repo.ID: repo}
	for _, test := range []struct {
		name        string
		detailsJSON string
		wantLabel   string
		wantSummary string
	}{
		{
			name:        "all newly created",
			detailsJSON: `{"repository_id":"1","created_pull_request_indexes":"42,43","already_covered_pull_request_indexes":"","created_pull_request_count":"2","already_covered_pull_request_count":"0","head_sha":"abc123","reason":"production fix"}`,
			wantLabel:   "Shared-head thaw approved",
			wantSummary: "taua-almeida/thawguard · New exceptions: #42, #43",
		},
		{
			name:        "mixed created and covered",
			detailsJSON: `{"repository_id":"1","created_pull_request_indexes":"43","already_covered_pull_request_indexes":"42","created_pull_request_count":"1","already_covered_pull_request_count":"1","head_sha":"abc123","reason":"production fix"}`,
			wantLabel:   "Shared-head thaw approved",
			wantSummary: "taua-almeida/thawguard · New exceptions: #43 · Already covered: #42",
		},
		{
			name:        "all already covered",
			detailsJSON: `{"repository_id":"1","created_pull_request_indexes":"","already_covered_pull_request_indexes":"42,43","created_pull_request_count":"0","already_covered_pull_request_count":"2","head_sha":"abc123","reason":"confirmed shared impact"}`,
			wantLabel:   "Shared head already covered",
			wantSummary: "taua-almeida/thawguard · Active exceptions: #42, #43",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			view, ok := systemAuditEventViewForEvent(repositories, audit.Event{Action: audit.ActionThawExceptionSharedHeadApproved, DetailsJSON: test.detailsJSON})
			if !ok {
				t.Fatal("expected shared-head audit event to be allowlisted")
			}
			if view.Label != test.wantLabel || view.Summary != test.wantSummary {
				t.Fatalf("unexpected shared-head view: %+v", view)
			}
			if !strings.Contains(view.Detail, "Head abc123 — Confirmation reason:") {
				t.Fatalf("expected reason to be scoped to the confirmation, got %q", view.Detail)
			}
		})
	}
}

func TestSystemAuditEventViewSharedHeadMalformedDetailsFailSafely(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard"}
	repositories := map[int64]domain.Repository{repo.ID: repo}
	for _, detailsJSON := range []string{
		`{"repository_id":"1","raw":"raw-secret-marker"`,
		`{"repository_id":"1","created_pull_request_indexes":"42","already_covered_pull_request_indexes":"","already_covered_pull_request_count":"0","head_sha":"abc123","reason":"raw-secret-marker"}`,
		`{"repository_id":"1","created_pull_request_indexes":"42,raw-secret-marker","already_covered_pull_request_indexes":"","created_pull_request_count":"2","already_covered_pull_request_count":"0","head_sha":"abc123","reason":"production fix"}`,
		`{"repository_id":"1","created_pull_request_indexes":"42","already_covered_pull_request_indexes":"","created_pull_request_count":"1","already_covered_pull_request_count":"0","head_sha":"raw-secret-marker","reason":"production fix"}`,
	} {
		view, ok := systemAuditEventViewForEvent(repositories, audit.Event{Action: audit.ActionThawExceptionSharedHeadApproved, DetailsJSON: detailsJSON})
		if !ok {
			t.Fatal("expected malformed shared-head event to remain allowlisted")
		}
		if view.Label != "Shared-head confirmation recorded" || (view.Summary != "taua-almeida/thawguard" && view.Summary != "Repository") || view.Detail != "Approval details unavailable" || view.StateClass != "warning" {
			t.Fatalf("expected safe fallback view, got %+v", view)
		}
		visible := view.Label + view.Summary + view.Detail
		if strings.Contains(visible, "raw-secret-marker") || strings.Contains(visible, detailsJSON) {
			t.Fatalf("expected malformed/raw details to stay hidden, got %q", visible)
		}
	}
}

func TestWebhooksPageEscapesSharedHeadAuditDetails(t *testing.T) {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard"}
	event := audit.Event{Action: audit.ActionThawExceptionSharedHeadApproved, DetailsJSON: `{"repository_id":"1","created_pull_request_indexes":"42,43","already_covered_pull_request_indexes":"","created_pull_request_count":"2","already_covered_pull_request_count":"0","head_sha":"abc123","reason":"fix <b>now</b>"}`}
	server := NewServer(Config{
		AppName:              "Thawguard",
		RepositoryStore:      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		WebhookDeliveryStore: &fakeWebhookDeliveryStore{},
		AuditStore:           &fakeAuditStore{events: []audit.Event{event}},
	})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, "fix &lt;b&gt;now&lt;/b&gt;") {
		t.Fatalf("expected escaped shared-head reason, status=%d body=%q", recorder.Code, body)
	}
	if strings.Contains(body, "fix <b>now</b>") {
		t.Fatalf("expected template escaping to prevent raw markup, got %q", body)
	}
}

func TestWebhooksPageFiltersSortsAndLimitsDeliveries(t *testing.T) {
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
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/webhooks?processing=retryable_failure&sort=processed&direction=asc&limit=50", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Filters active", "selected>50", "aria-sort=\"ascending\"", "Showing 1 of 1 matching rows", "2 total rows loaded", "delivery-retry", "retryable failure", "webhook processing failed"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "delivery-processed") {
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

func TestForgejoWebhookSmokeWithSQLiteStores(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	secretStore, err := secrets.NewAESGCMStore(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetWebhookSecret(ctx, repo.ID, "super-secret-value", actor); err != nil {
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
	dryRunPublisher := statuspublisher.NewDryRunPublisher(publicationStore, publicationStore)
	deliveryStore := webhook.NewDeliveryStore(database)
	processor := webhook.NewPullRequestProcessor(repository.NewStore(database), pullRequestStore, statusService, dryRunPublisher)
	server := NewServer(Config{
		AppName:                     "Thawguard",
		RepositoryStore:             repositorySetup,
		StatusPublicationStore:      publicationStore,
		WebhookRepositoryStore:      repositorySetup,
		WebhookDeliveryStore:        deliveryStore,
		PullRequestWebhookProcessor: processor,
	})

	body := pullRequestWebhookBody("opened")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, signedWebhookRequest(t, body, "super-secret-value", "delivery-smoke"))

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "accepted\n" {
		t.Fatalf("expected generic accepted response, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	deliveries, err := deliveryStore.ListRecent(ctx, 10)
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
	if len(publications) != 1 || publications[0].StatusResultID != results[0].ID || publications[0].HeadSHA != results[0].HeadSHA || publications[0].DeliveryMode != statuspublication.DeliveryModeLocalRecord {
		t.Fatalf("expected local publication intent, got %+v", publications)
	}
	attempts, err := publicationStore.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].PublicationID != publications[0].ID || attempts[0].StatusResultID != results[0].ID || attempts[0].Mode != statuspublication.AttemptModeDryRun || attempts[0].Result != statuspublication.AttemptResultPlanned {
		t.Fatalf("expected dry-run publication attempt, got %+v", attempts)
	}

	webhooksPage := httptest.NewRecorder()
	server.Routes().ServeHTTP(webhooksPage, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	if webhooksPage.Code != http.StatusOK || !strings.Contains(webhooksPage.Body.String(), "delivery-smoke") || !strings.Contains(webhooksPage.Body.String(), "processed") {
		t.Fatalf("expected webhook delivery page to show processed delivery, status=%d body=%q", webhooksPage.Code, webhooksPage.Body.String())
	}
	publicationsPage := httptest.NewRecorder()
	server.Routes().ServeHTTP(publicationsPage, httptest.NewRequest(http.MethodGet, "/publications", nil))
	if publicationsPage.Code != http.StatusOK || !strings.Contains(publicationsPage.Body.String(), "dry_run") || !strings.Contains(publicationsPage.Body.String(), "Branch is frozen") {
		t.Fatalf("expected publications page to show dry-run attempt, status=%d body=%q", publicationsPage.Code, publicationsPage.Body.String())
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
	statusTokens        []statusTokenUpdate
	statusTokenActors   []domain.Actor
	statusTokenErr      error
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

func (s *fakeAuditStore) List(ctx context.Context, limit int) ([]audit.Event, error) {
	if s.err != nil {
		return nil, s.err
	}
	if limit > 0 && len(s.events) > limit {
		return s.events[:limit], nil
	}
	return s.events, nil
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
	freezes            []domain.BranchFreeze
	scheduled          []domain.BranchFreeze
	created            []freeze.CreateParams
	scheduledCreated   []freeze.ScheduleParams
	ended              []int64
	cancelled          []int64
	scheduledCancelled []int64
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

func (s *fakeFreezeStore) ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if limit > 0 && len(s.scheduled) > limit {
		return s.scheduled[:limit], nil
	}
	return s.scheduled, nil
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

func (s *fakeFreezeStore) CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s.err != nil {
		return domain.BranchFreeze{}, s.err
	}
	s.scheduledCancelled = append(s.scheduledCancelled, id)
	s.actors = append(s.actors, actor)
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusCancelled, Scheduled: true}, nil
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
