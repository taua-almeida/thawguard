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

const accountWebTestPassword = "correct horse battery staple"

func TestLegacyInMemorySessionHidesUnavailableChangePasswordAction(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected dashboard, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), `href="/account/password"`) {
		t.Fatal("legacy in-memory session must not advertise unavailable password changes")
	}
}

func TestAccountAdministrationRoutesRequireAdmin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	viewer := mustCreateWebUser(t, ctx, authService, "viewer@example.test", []auth.Role{auth.RoleViewer})
	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	routes := []string{"/users/roles", "/users/disable", "/users/enable", "/users/reset-password"}
	for _, route := range routes {
		form := url.Values{"user_id": {fmt.Sprint(admin.User.ID)}, "roles": {"viewer"}, csrfFormField: {viewerSession.CSRFToken}}
		recorder := postAccountForm(t, server, route, &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}, form)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected viewer POST %s to be forbidden, got %d", route, recorder.Code)
		}
	}
	_ = viewer
}

func TestAccountMutationsRejectMissingAndInvalidCSRF(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	routes := []string{"/users/roles", "/users/disable", "/users/enable", "/users/reset-password", "/account/password"}
	for _, route := range routes {
		for _, token := range []string{"", "invalid-token"} {
			form := url.Values{"user_id": {"1"}}
			if token != "" {
				form.Set(csrfFormField, token)
			}
			recorder := postAccountForm(t, server, route, adminCookie, form)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected POST %s with csrf %q to be forbidden, got %d", route, token, recorder.Code)
			}
		}
	}
}

func TestFinalEnabledAdminValidationIsRenderedSafely(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	form := url.Values{"user_id": {fmt.Sprint(admin.User.ID)}, csrfFormField: {admin.CSRFToken}}
	recorder := postAccountForm(t, server, "/users/disable", adminCookie, form)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "the final enabled admin cannot be disabled") {
		t.Fatalf("expected final admin disable validation, status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	form = url.Values{"user_id": {fmt.Sprint(admin.User.ID)}, "roles": {"viewer"}, csrfFormField: {admin.CSRFToken}}
	recorder = postAccountForm(t, server, "/users/roles", adminCookie, form)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "the final enabled admin must keep the admin role") {
		t.Fatalf("expected final admin role validation, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestUsersPageShowsAccountStateAndResponsiveLabels(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	if _, err := authService.DisableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/users", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected users page, got %d", recorder.Code)
	}
	for _, want := range []string{
		`<use href="#tg-i-warning"></use></svg>Disabled</span>`,
		`<use href="#tg-i-check"></use></svg>Enabled</span>`,
		`action="/users/enable"`,
		`action="/users/reset-password"`,
		`Re-enabling does not restore old sessions.`,
		`the final enabled admin cannot be disabled or lose the admin role`,
		`The final enabled admin cannot be disabled.`,
		`<caption class="sr-only">Local users with status, roles, creation date, and account actions</caption>`,
		`hidden overflow-x-auto md:block`,
		`md:hidden`,
		`href="/account/password"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected users page to contain %q", want)
		}
	}
	// The final enabled admin is guarded and the only other user is already
	// disabled, so no row may offer a disable action.
	if strings.Contains(body, `action="/users/disable"`) {
		t.Fatal("expected no disable form when every row is guarded or already disabled")
	}
	if strings.Contains(body, fmt.Sprintf(`id="users-reset-%d"`, admin.User.ID)) {
		t.Fatal("expected no reset-password dialog for the signed-in admin's own row")
	}
}

func TestRoleEditFormPreservesSubmittedRolesAfterValidationError(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "viewer@example.test", []auth.Role{auth.RoleViewer})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{
		"user_id":     {fmt.Sprint(user.ID)},
		"roles":       {"freezer", "owner"},
		csrfFormField: {admin.CSRFToken},
	}
	recorder := postAccountForm(t, server, "/users/roles", &http.Cookie{Name: sessionCookieName, Value: admin.ID}, form)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest || !strings.Contains(body, "role is invalid") {
		t.Fatalf("expected role validation error, status=%d body=%q", recorder.Code, body)
	}
	if !strings.Contains(renderedControlTag(t, body, fmt.Sprintf("u%d-role-freezer", user.ID)), " checked") {
		t.Fatal("expected submitted freezer role to stay selected after validation error")
	}
	if !strings.Contains(renderedControlTag(t, body, fmt.Sprintf("m-u%d-role-freezer", user.ID)), " checked") {
		t.Fatal("expected submitted freezer role to stay selected on the mobile card after validation error")
	}
	if strings.Contains(renderedControlTag(t, body, fmt.Sprintf("u%d-role-viewer", user.ID)), " checked") {
		t.Fatal("expected unsubmitted viewer role to be unselected after validation error")
	}
}

// renderedControlTag returns the markup of the form control carrying the given
// id, from its id attribute to the tag's closing ">" (users-page attribute
// values never contain ">"). The id="..." marker includes the closing quote, so
// label for=, -hint, and -confirm ids cannot match.
func renderedControlTag(t *testing.T, body, id string) string {
	t.Helper()
	marker := fmt.Sprintf("id=%q", id)
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("expected users page to render a control with id %q", id)
	}
	rest := body[start:]
	end := strings.Index(rest, ">")
	if end < 0 {
		t.Fatalf("expected control %q tag to close", id)
	}
	return rest[:end]
}

func TestPasswordResetNeverRendersPasswordValues(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: admin.ID}

	const secretValue = "leak-canary-temporary-password"
	form := url.Values{
		"user_id":                         {fmt.Sprint(user.ID)},
		"temporary_password":              {secretValue},
		"temporary_password_confirmation": {secretValue + "-mismatch"},
		csrfFormField:                     {admin.CSRFToken},
	}
	recorder := postAccountForm(t, server, "/users/reset-password", adminCookie, form)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "temporary passwords do not match") {
		t.Fatalf("expected mismatch validation, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), secretValue) {
		t.Fatal("expected temporary password to never be re-rendered")
	}
	if !strings.Contains(recorder.Body.String(), fmt.Sprintf(`<dialog id="users-reset-%d" open`, user.ID)) {
		t.Fatal("expected failed reset dialog to re-open on its row")
	}
	passwordTag := renderedControlTag(t, recorder.Body.String(), fmt.Sprintf("reset-%d-password", user.ID))
	// A bare " disabled" attribute, not the class's disabled: variant prefixes.
	if !strings.Contains(passwordTag, `minlength="12"`) || strings.Contains(passwordTag, " disabled ") || strings.HasSuffix(passwordTag, " disabled") {
		t.Fatalf("expected re-opened reset password input to stay enabled, got %q", passwordTag)
	}
	if strings.Contains(passwordTag, " value=") {
		t.Fatalf("expected reset password input to render blank, got %q", passwordTag)
	}

	form.Set("temporary_password_confirmation", secretValue)
	recorder = postAccountForm(t, server, "/users/reset-password", adminCookie, form)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/users" {
		t.Fatalf("expected reset redirect, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), secretValue) {
		t.Fatal("expected reset response to exclude the temporary password")
	}
}

func TestDisabledUserSessionRedirectsToLogin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	session, err := authService.Login(ctx, auth.LoginParams{Email: "freezer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	// Disable in SQL directly so the session row survives until the next request.
	if _, err := database.ExecContext(ctx, `UPDATE users SET disabled_at = '2026-07-13T00:00:00.000000000Z' WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected disabled session redirect to login, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestTemporaryPasswordLoginRedirectsToForcedPasswordChange(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	if err := authService.ResetPassword(ctx, auth.ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	loginCookie := namedCookieFromRecorder(t, recorder, loginCookieName)
	loginCSRF := csrfTokenFromBody(t, recorder.Body.String())

	form := url.Values{"email": {"freezer@example.test"}, "password": {"temporary local password"}, csrfFormField: {loginCSRF}}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(loginCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/account/password" {
		t.Fatalf("expected temporary-password login redirect to forced change, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestForcedPasswordSessionIsGatedToPasswordChangeAndLogout(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	if err := authService.ResetPassword(ctx, auth.ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); err != nil {
		t.Fatal(err)
	}
	forcedSession, err := authService.Login(ctx, auth.LoginParams{Email: "freezer@example.test", Password: "temporary local password"})
	if err != nil {
		t.Fatal(err)
	}
	freezeStore := &fakeFreezeStore{}
	server := NewServer(Config{
		AppName:                "Thawguard",
		AuthService:            authService,
		FreezeStore:            freezeStore,
		ScheduledFreezeStore:   freezeStore,
		RepositoryStore:        &fakeRepositoryStore{},
		StatusDecisionStore:    &fakeStatusDecisionStore{},
		StatusPublicationStore: &fakeStatusPublicationStore{},
		WebhookDeliveryStore:   &fakeWebhookDeliveryStore{},
		AuditStore:             &fakeAuditStore{},
	})
	forcedCookie := &http.Cookie{Name: sessionCookieName, Value: forcedSession.ID}

	for _, path := range []string{"/", "/repositories", "/freezes", "/scheduled-freezes", "/decisions", "/activity", "/publications", "/webhooks", "/users", "/login"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.AddCookie(forcedCookie)
		server.Routes().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/account/password" {
			t.Fatalf("expected forced session GET %s to redirect to password change, status=%d location=%q", path, recorder.Code, recorder.Header().Get("Location"))
		}
	}

	for _, path := range []string{"/freezes", "/users/roles", "/users/reset-password", "/repositories"} {
		form := url.Values{"user_id": {"1"}, "repository_id": {"1"}, "branch": {"main"}, "reason": {"release"}, csrfFormField: {forcedSession.CSRFToken}}
		recorder := postAccountForm(t, server, path, forcedCookie, form)
		if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/account/password" {
			t.Fatalf("expected forced session POST %s to redirect to password change, status=%d location=%q", path, recorder.Code, recorder.Header().Get("Location"))
		}
	}
	if len(freezeStore.created) != 0 {
		t.Fatalf("expected no freeze creation from forced session, got %d", len(freezeStore.created))
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/account/password", nil)
	request.AddCookie(forcedCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Choose a new password to continue") {
		t.Fatalf("expected forced session to reach password change page, status=%d", recorder.Code)
	}

	logoutForm := url.Values{csrfFormField: {forcedSession.CSRFToken}}
	recorder = postAccountForm(t, server, "/logout", forcedCookie, logoutForm)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected forced session logout, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestForcedPasswordChangeRotatesSessionAndRestoresAccess(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	if err := authService.ResetPassword(ctx, auth.ResetPasswordParams{ActorUserID: admin.User.ID, UserID: user.ID, TemporaryPassword: "temporary local password"}); err != nil {
		t.Fatal(err)
	}
	forcedSession, err := authService.Login(ctx, auth.LoginParams{Email: "freezer@example.test", Password: "temporary local password"})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	forcedCookie := &http.Cookie{Name: sessionCookieName, Value: forcedSession.ID}

	const leakCanary = "brand-new-local-password-canary"
	form := url.Values{
		"current_password":          {"temporary local password"},
		"new_password":              {leakCanary},
		"new_password_confirmation": {leakCanary + "-mismatch"},
		csrfFormField:               {forcedSession.CSRFToken},
	}
	recorder := postAccountForm(t, server, "/account/password", forcedCookie, form)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "new passwords do not match") {
		t.Fatalf("expected mismatch validation, status=%d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), leakCanary) {
		t.Fatal("expected password values to never be re-rendered")
	}

	form.Set("new_password_confirmation", leakCanary)
	recorder = postAccountForm(t, server, "/account/password", forcedCookie, form)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" {
		t.Fatalf("expected password change redirect, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	rotatedCookie := sessionCookieFromRecorder(t, recorder)
	if rotatedCookie.Value == "" || rotatedCookie.Value == forcedSession.ID {
		t.Fatalf("expected rotated session cookie, got %q", rotatedCookie.Value)
	}

	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(rotatedCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected rotated session to access dashboard, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(forcedCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected old session to be revoked, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestSelfDisableClearsSessionCookieAndRedirectsToLogin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "second-admin@example.test", []auth.Role{auth.RoleAdmin})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{"user_id": {fmt.Sprint(admin.User.ID)}, csrfFormField: {admin.CSRFToken}}
	recorder := postAccountForm(t, server, "/users/disable", &http.Cookie{Name: sessionCookieName, Value: admin.ID}, form)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Fatalf("expected self-disable redirect to login, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	cleared := sessionCookieFromRecorder(t, recorder)
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("expected cleared session cookie, got value=%q maxage=%d", cleared.Value, cleared.MaxAge)
	}
	if _, found, err := authService.SessionByID(ctx, admin.ID); err != nil || found {
		t.Fatalf("expected self-disabled admin session revoked, found=%v err=%v", found, err)
	}
}

func TestAccountMutationInternalErrorsRemainGeneric(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", []auth.Role{auth.RoleFreezer})
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"user_id": {fmt.Sprint(user.ID)}, csrfFormField: {admin.CSRFToken}}
	recorder := postAccountForm(t, server, "/users/disable", &http.Cookie{Name: sessionCookieName, Value: admin.ID}, form)
	body := strings.TrimSpace(recorder.Body.String())
	if recorder.Code != http.StatusInternalServerError || body != "internal server error" {
		t.Fatalf("expected generic internal error, status=%d body=%q", recorder.Code, body)
	}
}

func mustSetupWebAdmin(t *testing.T, ctx context.Context, authService *auth.Service) auth.Session {
	t.Helper()
	session, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func mustCreateWebUser(t *testing.T, ctx context.Context, authService *auth.Service, email string, roles []auth.Role) auth.User {
	t.Helper()
	user, err := authService.CreateUser(ctx, auth.CreateUserParams{Email: email, DisplayName: "User " + email, Password: accountWebTestPassword, Roles: roles})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func postAccountForm(t *testing.T, server *Server, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}
