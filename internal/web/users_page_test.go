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
	"github.com/taua-almeida/thawguard/internal/domain"
)

func getUsersPage(t *testing.T, server *Server, path string, cookie *http.Cookie, hx bool) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if hx {
		request.Header.Set("HX-Request", "true")
	}
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func TestUsersPageKeepsPlainGETContractForHXRequests(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	cookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	for _, hx := range []bool{false, true} {
		recorder := getUsersPage(t, server, "/users", cookie, hx)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "<!doctype html>") {
			t.Fatalf("hx=%v: expected a full Users & Access page, status=%d", hx, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "Users &amp; Access") {
			t.Fatalf("hx=%v: expected Users & Access heading", hx)
		}
	}
}

func TestUsersDirectorySearchAndRepositoryFilter(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	kai := mustCreateWebUser(t, ctx, authService, "kai@example.test", nil)
	mustCreateWebUser(t, ctx, authService, "sten@example.test", nil)
	mustInsertWebRepositoryID(t, ctx, database, 1, "ice-station")
	mustInsertWebRepositoryID(t, ctx, database, 2, "frost-api")
	if err := authService.SetUserRepositoryRoles(ctx, auth.SetUserRepositoryRolesParams{ActorUserID: admin.User.ID, UserID: kai.ID, RepositoryID: 1, Roles: []auth.Role{auth.RoleFreezer}}); err != nil {
		t.Fatal(err)
	}
	repositories := []domain.Repository{
		{ID: 1, Owner: "aurora", Name: "ice-station"},
		{ID: 2, Owner: "borealis", Name: "frost-api"},
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, RepositoryStore: &fakeRepositoryStore{repositories: repositories}})
	cookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	recorder := getUsersPage(t, server, "/users?q=kai&repo=1", cookie, false)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, "kai@example.test") || strings.Contains(body, "sten@example.test") {
		t.Fatalf("expected SQL-backed filters to return only Kai, status=%d body=%q", recorder.Code, body)
	}
	for _, want := range []string{`value="1" selected`, "1 repositories", "Freezer"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected filtered directory to contain %q", want)
		}
	}
}

func TestUsersCreateValidationPreservesIdentityNeverPassword(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "taken@example.test", nil)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	cookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	const secret = "leak-canary-create-password"
	form := url.Values{
		"email":              {"taken@example.test"},
		"display_name":       {"Preserved Name"},
		"temporary_password": {secret},
		csrfFormField:        {admin.CSRFToken},
	}
	recorder := postAccountForm(t, server, "/users", cookie, form)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest || !strings.Contains(body, `<dialog id="users-create-dialog" open`) {
		t.Fatalf("expected validation re-render with open dialog, status=%d", recorder.Code)
	}
	if !strings.Contains(body, `value="taken@example.test"`) || !strings.Contains(body, `value="Preserved Name"`) {
		t.Fatal("expected submitted identity fields to be preserved")
	}
	if strings.Contains(body, secret) || strings.Contains(renderedControlTag(t, body, "create-temporary-password"), " value=") {
		t.Fatal("expected temporary password to never be rendered")
	}
}

func TestUsersAccessGuardsAndMissingTargets(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "viewer@example.test", nil)
	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	viewerCookie := &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}

	for _, path := range []string{"/users", "/users/999"} {
		recorder := getUsersPage(t, server, path, viewerCookie, false)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected non-Admin %s to be forbidden, got %d", path, recorder.Code)
		}
	}

	admin, err := authService.Login(ctx, auth.LoginParams{Email: "admin@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}
	for _, path := range []string{"/users/999", "/users/not-a-number"} {
		recorder := getUsersPage(t, server, path, adminCookie, false)
		if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "Page not found") {
			t.Fatalf("expected styled 404 for %s, got %d", path, recorder.Code)
		}
	}
}

func TestUsersSelfDisableRedirectsToLogin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	second := mustCreateWebUser(t, ctx, authService, "second-admin@example.test", []auth.Role{auth.RoleAdmin})
	mustCreateWebUser(t, ctx, authService, "third-admin@example.test", []auth.Role{auth.RoleAdmin})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	secondSession, err := authService.Login(ctx, auth.LoginParams{Email: second.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{csrfFormField: {secondSession.CSRFToken}}
	recorder := postAccountForm(t, server, fmt.Sprintf("/users/%d/disable", second.ID), &http.Cookie{Name: sessionCookieName, Value: secondSession.ID}, form)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected self-disable redirect to login, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	assertSessionCookieCleared(t, recorder)
}

func TestUsersLastAdminDetailProtectsRecoveryInvariant(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "viewer@example.test", nil)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := getUsersPage(t, server, fmt.Sprintf("/users/%d", admin.User.ID), &http.Cookie{Name: sessionCookieName, Value: admin.ID}, false)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected user detail, got %d", recorder.Code)
	}
	if !strings.Contains(body, `<input type="hidden" name="admin" value="1">`) {
		t.Fatal("expected hidden Admin value for the disabled recovery checkbox")
	}
	adminCheckbox := renderedControlTag(t, body, "user-admin")
	if !strings.Contains(adminCheckbox, " checked") || !strings.Contains(adminCheckbox, " disabled") {
		t.Fatalf("expected last Admin checkbox checked and disabled, got %q", adminCheckbox)
	}
	if !strings.Contains(body, "final enabled Admin") {
		t.Fatal("expected recovery-invariant explanation")
	}
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
