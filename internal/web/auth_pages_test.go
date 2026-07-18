package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/auth"
)

func renderAuthTestLayout(t *testing.T, name string, data any) string {
	t.Helper()
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("execute %s: %v", name, err)
	}
	return buf.String()
}

func TestLoginTemplateRendersFormAndPreservedEmail(t *testing.T) {
	body := renderAuthTestLayout(t, "layouts/login", authLoginData{
		AppName:   "Thawguard",
		PageTitle: "Sign in",
		CSRFField: csrfFormField,
		CSRFToken: "fictional-token",
		FormError: "Your sign-in form expired. Please try again.",
		Email:     "mira.frost@example.test",
	})
	for _, want := range []string{
		"Sign in · Thawguard",
		">Sign in</h1>",
		">Email<",
		">Password<",
		`name="csrf_token" value="fictional-token"`,
		`value="mira.frost@example.test"`,
		"Your sign-in form expired. Please try again.",
		`autocomplete="current-password"`,
		"autofocus",
		`action="/login"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected login page to contain %q, body=%q", want, body)
		}
	}
	if strings.Contains(body, "<script") {
		t.Fatal("auth pages must not include scripts")
	}
}

func TestSetupTemplateRendersFirstAdminForm(t *testing.T) {
	body := renderAuthTestLayout(t, "layouts/setup", authSetupData{
		AppName:     "Thawguard",
		PageTitle:   "Set up",
		CSRFField:   csrfFormField,
		CSRFToken:   "fictional-token",
		FormError:   "password must be at least 12 characters",
		Email:       "mira.frost@example.test",
		DisplayName: "Mira Frost",
	})
	for _, want := range []string{
		"Create the first admin",
		"This first account gets every role",
		"password must be at least 12 characters",
		`value="mira.frost@example.test"`,
		`value="Mira Frost"`,
		"At least 12 characters. Use a strong local password.",
		`minlength="12"`,
		"signed in and taken to the dashboard",
		`name="csrf_token" value="fictional-token"`,
		`action="/setup"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected setup page to contain %q, body=%q", want, body)
		}
	}
	if strings.Contains(body, "<script") {
		t.Fatal("auth pages must not include scripts")
	}
}

func TestAccountPasswordTemplateForcedAndVoluntaryModes(t *testing.T) {
	base := authAccountPasswordData{
		AppName:   "Thawguard",
		PageTitle: "Change password",
		CSRFField: csrfFormField,
		CSRFToken: "fictional-token",
	}

	forced := base
	forced.MustChangePassword = true
	forcedBody := renderAuthTestLayout(t, "layouts/account-password", forced)
	for _, want := range []string{
		"Change your password",
		"Temporary password in use",
		"Choose a new password to continue using Thawguard.",
		"#tg-i-key",
		"Signs out your other sessions.",
		`action="/logout"`,
		`autocomplete="new-password"`,
	} {
		if !strings.Contains(forcedBody, want) {
			t.Fatalf("expected forced page to contain %q, body=%q", want, forcedBody)
		}
	}
	if strings.Contains(forcedBody, "Back to dashboard") {
		t.Fatal("forced password change must not offer a back-to-dashboard exit")
	}

	voluntaryBody := renderAuthTestLayout(t, "layouts/account-password", base)
	for _, want := range []string{
		"signs out every other session",
		"Back to dashboard",
		`action="/logout"`,
	} {
		if !strings.Contains(voluntaryBody, want) {
			t.Fatalf("expected voluntary page to contain %q, body=%q", want, voluntaryBody)
		}
	}
	if strings.Contains(voluntaryBody, "Temporary password in use") {
		t.Fatal("voluntary password change must not show the forced callout")
	}
	if strings.Contains(forcedBody, "<script") || strings.Contains(voluntaryBody, "<script") {
		t.Fatal("auth pages must not include scripts")
	}
}

func TestErrorTemplateRendersStatusCardAndAction(t *testing.T) {
	heading, message := errorPageContent(http.StatusNotFound)
	body := renderAuthTestLayout(t, "layouts/error", authErrorData{
		AppName:     "Thawguard",
		PageTitle:   heading,
		Status:      http.StatusNotFound,
		Heading:     heading,
		Message:     message,
		ActionHref:  "/login",
		ActionLabel: "Sign in",
	})
	for _, want := range []string{
		"Page not found",
		"HTTP 404",
		`href="/login"`,
		">Sign in</a>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected error page to contain %q, body=%q", want, body)
		}
	}
	if strings.Contains(body, "<script") {
		t.Fatal("auth pages must not include scripts")
	}
	if strings.Contains(strings.ToLower(body), "security boundary is") {
		t.Fatal("error copy must not claim a hard security boundary")
	}
}

func TestLoginCSRFFailureReRendersFriendlyFormWith403(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{"email": {"admin@example.test"}, "password": {"super-secret-password"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected login csrf failure to stay 403, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Your sign-in form expired. Please try again.") {
		t.Fatalf("expected friendly form-expired re-render, body=%q", body)
	}
	if !strings.Contains(body, `value="admin@example.test"`) {
		t.Fatalf("expected preserved email on re-render, body=%q", body)
	}
	if strings.Contains(body, "super-secret-password") {
		t.Fatal("password must never be echoed back")
	}
	refreshedCookie := namedCookieFromRecorder(t, recorder, loginCookieName)
	if refreshedCookie.Value != csrfTokenFromBody(t, body) {
		t.Fatal("expected refreshed login cookie to match rendered csrf token")
	}
}

func TestLoginCrossOriginPostReRendersFriendlyFormWith403(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{"email": {"admin@example.test"}, "password": {"super-secret-password"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://evil.example")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin login post to stay 403, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Your sign-in form expired. Please try again.") {
		t.Fatalf("expected friendly form-expired re-render, body=%q", recorder.Body.String())
	}
}

func TestLoginBadCredentialsPreservesEmailWith401(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected login form, got %d", recorder.Code)
	}
	loginCookie := namedCookieFromRecorder(t, recorder, loginCookieName)
	loginCSRF := csrfTokenFromBody(t, recorder.Body.String())

	form := url.Values{"email": {"admin@example.test"}, "password": {"wrong-password-entirely"}, csrfFormField: {loginCSRF}}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(loginCookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected bad credentials to stay 401, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `value="admin@example.test"`) {
		t.Fatalf("expected preserved email on auth error, body=%q", body)
	}
	if strings.Contains(body, "wrong-password-entirely") {
		t.Fatal("password must never be echoed back")
	}
}

func TestAccountPasswordPageRendersVoluntaryModeForAdmin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/account/password", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected account password page, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Change your password", "signs out every other session", "Back to dashboard", `action="/logout"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected voluntary page to contain %q, body=%q", want, body)
		}
	}
	if strings.Contains(body, "Temporary password in use") {
		t.Fatal("voluntary mode must not show the forced callout")
	}
}
