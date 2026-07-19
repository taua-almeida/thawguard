package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/auth"
)

// getUsersPage issues GET /users with the given cookie, optionally as an htmx
// request.
func getUsersPage(t *testing.T, server *Server, cookie *http.Cookie, hx bool) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/users", nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if hx {
		request.Header.Set("HX-Request", "true")
	}
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

// postUsersHXForm mirrors postAccountForm with the htmx request header set.
func postUsersHXForm(t *testing.T, server *Server, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func TestUsersPageHXGetReturnsFragmentWithVary(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	full := getUsersPage(t, server, adminCookie, false)
	if full.Code != http.StatusOK || !strings.Contains(full.Body.String(), "<!doctype html>") {
		t.Fatalf("expected full users page, status=%d", full.Code)
	}
	if !strings.Contains(full.Body.String(), `<div id="users-live"`) {
		t.Fatal("expected full page to contain the live region")
	}
	if !strings.Contains(full.Header().Get("Vary"), "HX-Request") {
		t.Fatalf("expected full page Vary to include HX-Request, got %q", full.Header().Get("Vary"))
	}

	fragment := getUsersPage(t, server, adminCookie, true)
	if fragment.Code != http.StatusOK {
		t.Fatalf("expected fragment response, status=%d", fragment.Code)
	}
	body := fragment.Body.String()
	if !strings.Contains(body, `<div id="users-live"`) {
		t.Fatal("expected fragment to contain the live region")
	}
	if strings.Contains(body, "<!doctype html>") || strings.Contains(body, "shell-sidebar") {
		t.Fatal("expected fragment to exclude the page shell")
	}
	if !strings.Contains(fragment.Header().Get("Vary"), "HX-Request") {
		t.Fatalf("expected fragment Vary to include HX-Request, got %q", fragment.Header().Get("Vary"))
	}
}

func TestUsersRolesMutationReturnsFragmentAndToastUnderHX(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "viewer@example.test", []auth.Role{auth.RoleViewer})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	form := url.Values{
		"user_id":     {fmt.Sprint(user.ID)},
		"roles":       {"viewer", "freezer"},
		csrfFormField: {admin.CSRFToken},
	}
	recorder := postUsersHXForm(t, server, "/users/roles", adminCookie, form)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `<div id="users-live"`) {
		t.Fatalf("expected HX success fragment, status=%d body=%q", recorder.Code, body)
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatal("expected HX success response to be a fragment, not a full page")
	}
	if !strings.Contains(body, `<div id="toasts" hx-swap-oob="true"`) || !strings.Contains(body, "Roles saved") {
		t.Fatalf("expected out-of-band success toast, body=%q", body)
	}

	// The same mutation without htmx keeps the 303 PRG contract.
	form.Set("roles", "viewer")
	plain := postAccountForm(t, server, "/users/roles", adminCookie, form)
	if plain.Code != http.StatusSeeOther || plain.Header().Get("Location") != "/users" {
		t.Fatalf("expected non-HX mutation redirect to /users, status=%d location=%q", plain.Code, plain.Header().Get("Location"))
	}
}

func TestUsersSelfDisableRedirectsToLogin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	second := mustCreateWebUser(t, ctx, authService, "second-admin@example.test", []auth.Role{auth.RoleAdmin})
	third := mustCreateWebUser(t, ctx, authService, "third-admin@example.test", []auth.Role{auth.RoleAdmin})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	secondSession, err := authService.Login(ctx, auth.LoginParams{Email: "second-admin@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"user_id": {fmt.Sprint(second.ID)}, csrfFormField: {secondSession.CSRFToken}}
	recorder := postUsersHXForm(t, server, "/users/disable", &http.Cookie{Name: sessionCookieName, Value: secondSession.ID}, form)
	if recorder.Code != http.StatusOK || recorder.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("expected HX self-disable to answer HX-Redirect /login, status=%d header=%q", recorder.Code, recorder.Header().Get("HX-Redirect"))
	}
	if strings.Contains(recorder.Body.String(), "users-live") {
		t.Fatal("expected no fragment body alongside HX-Redirect")
	}
	assertSessionCookieCleared(t, recorder)

	thirdSession, err := authService.Login(ctx, auth.LoginParams{Email: "third-admin@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	form = url.Values{"user_id": {fmt.Sprint(third.ID)}, csrfFormField: {thirdSession.CSRFToken}}
	plain := postAccountForm(t, server, "/users/disable", &http.Cookie{Name: sessionCookieName, Value: thirdSession.ID}, form)
	if plain.Code != http.StatusSeeOther || plain.Header().Get("Location") != "/login" {
		t.Fatalf("expected non-HX self-disable redirect to /login, status=%d location=%q", plain.Code, plain.Header().Get("Location"))
	}
	assertSessionCookieCleared(t, plain)
}

func assertSessionCookieCleared(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			if cookie.Value != "" || cookie.MaxAge >= 0 {
				t.Fatalf("expected session cookie to be cleared, got value=%q maxAge=%d", cookie.Value, cookie.MaxAge)
			}
			return
		}
	}
	t.Fatal("expected a cleared session cookie on the response")
}

func TestUsersLastAdminRowCarriesHiddenAdminRoleInput(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "viewer@example.test", []auth.Role{auth.RoleViewer})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := getUsersPage(t, server, &http.Cookie{Name: sessionCookieName, Value: admin.ID}, false)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected users page, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	// Exactly the final admin's desktop and mobile roles forms carry the
	// hidden admin input that stands in for the disabled checkbox.
	if got := strings.Count(body, `<input type="hidden" name="roles" value="admin">`); got != 2 {
		t.Fatalf("expected the hidden admin role input on the last-admin row's two responsive forms, got %d", got)
	}
	adminCheckbox := renderedControlTag(t, body, fmt.Sprintf("u%d-role-admin", admin.User.ID))
	if !strings.Contains(adminCheckbox, " checked") || !strings.Contains(adminCheckbox, " disabled") {
		t.Fatalf("expected last admin's admin checkbox to render checked and disabled, got %q", adminCheckbox)
	}
	if !strings.Contains(body, "The final enabled admin must keep the admin role.") {
		t.Fatal("expected the guarded admin checkbox hint")
	}
}

func TestUsersCreateValidationPreservesValuesNeverPasswords(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "taken@example.test", []auth.Role{auth.RoleViewer})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	const secretValue = "leak-canary-create-password"
	form := url.Values{
		"email":        {"taken@example.test"},
		"display_name": {"Preserved Name"},
		"password":     {secretValue},
		"roles":        {"freezer", "viewer"},
		csrfFormField:  {admin.CSRFToken},
	}
	for _, hx := range []bool{false, true} {
		var recorder *httptest.ResponseRecorder
		wantStatus := http.StatusBadRequest
		if hx {
			// htmx clients do not swap 4xx, so validation re-renders arrive as
			// 200 fragments with the dialog re-opened.
			recorder = postUsersHXForm(t, server, "/users", adminCookie, form)
			wantStatus = http.StatusOK
		} else {
			recorder = postAccountForm(t, server, "/users", adminCookie, form)
		}
		body := recorder.Body.String()
		if recorder.Code != wantStatus {
			t.Fatalf("hx=%v: expected create validation status %d, got %d body=%q", hx, wantStatus, recorder.Code, body)
		}
		if !strings.Contains(body, `<dialog id="users-create-dialog" open`) {
			t.Fatalf("hx=%v: expected add-user dialog to re-open after validation error", hx)
		}
		if !strings.Contains(body, `value="taken@example.test"`) || !strings.Contains(body, `value="Preserved Name"`) {
			t.Fatalf("hx=%v: expected submitted email and display name to be preserved", hx)
		}
		freezerTag := renderedControlTag(t, body, "create-role-freezer")
		if !strings.Contains(freezerTag, " checked") {
			t.Fatalf("hx=%v: expected submitted freezer role to stay selected", hx)
		}
		if strings.Contains(body, secretValue) {
			t.Fatalf("hx=%v: expected submitted password to never be re-rendered", hx)
		}
		passwordTag := renderedControlTag(t, body, "create-password")
		if strings.Contains(passwordTag, " value=") {
			t.Fatalf("hx=%v: expected create password input to render blank, got %q", hx, passwordTag)
		}
	}
}

func TestUsersGuardsRunBeforeHXBranch(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "viewer@example.test", []auth.Role{auth.RoleViewer})
	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	viewerCookie := &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}

	for _, hx := range []bool{false, true} {
		recorder := getUsersPage(t, server, viewerCookie, hx)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("hx=%v: expected viewer GET /users to be forbidden, got %d", hx, recorder.Code)
		}
		if !strings.Contains(recorder.Header().Get("Vary"), "HX-Request") {
			t.Fatalf("hx=%v: expected Vary HX-Request on forbidden response, got %q", hx, recorder.Header().Get("Vary"))
		}
	}

	anonymous := getUsersPage(t, server, nil, true)
	if anonymous.Code != http.StatusSeeOther || anonymous.Header().Get("Location") != "/login" {
		t.Fatalf("expected anonymous GET /users to redirect to login, status=%d location=%q", anonymous.Code, anonymous.Header().Get("Location"))
	}

	unconfigured := NewServer(Config{AppName: "Thawguard"})
	recorder := getUsersPage(t, unconfigured, nil, true)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "auth service is not configured") {
		t.Fatalf("expected 503 without auth service, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("Vary"), "HX-Request") {
		t.Fatalf("expected Vary HX-Request on 503, got %q", recorder.Header().Get("Vary"))
	}
}
