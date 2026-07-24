package web

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

const accountWebTestPassword = "correct horse battery staple"

func TestLegacyInMemorySessionHidesUnavailableChangePasswordAction(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	session := setWebSessionRoles(t, server, auth.RoleSet{auth.RoleAdmin})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	server.Routes().ServeHTTP(recorder, request)

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
	viewer := mustCreateWebUser(t, ctx, authService, "viewer@example.test", false)
	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	routes := []string{
		fmt.Sprintf("/users/%d/admin", admin.User.ID),
		fmt.Sprintf("/users/%d/disable", admin.User.ID),
		fmt.Sprintf("/users/%d/enable", admin.User.ID),
		fmt.Sprintf("/users/%d/password-recovery", admin.User.ID),
	}
	for _, route := range routes {
		form := url.Values{"admin": {"1"}, csrfFormField: {viewerSession.CSRFToken}}
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

	routes := []string{
		fmt.Sprintf("/users/%d/admin", admin.User.ID),
		fmt.Sprintf("/users/%d/disable", admin.User.ID),
		fmt.Sprintf("/users/%d/enable", admin.User.ID),
		fmt.Sprintf("/users/%d/password-recovery", admin.User.ID),
		"/account/password",
	}
	for _, route := range routes {
		for _, token := range []string{"", "invalid-token"} {
			form := url.Values{}
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

	form := url.Values{csrfFormField: {admin.CSRFToken}}
	recorder := postAccountForm(t, server, fmt.Sprintf("/users/%d/disable", admin.User.ID), adminCookie, form)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "the final enabled admin cannot be disabled") {
		t.Fatalf("expected final admin disable validation, status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	form = url.Values{csrfFormField: {admin.CSRFToken}}
	recorder = postAccountForm(t, server, fmt.Sprintf("/users/%d/admin", admin.User.ID), adminCookie, form)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "the final enabled admin must keep the admin role") {
		t.Fatalf("expected final admin role validation, status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestUsersPageShowsAccountStateAndResponsiveLabels(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
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
		`<use href="#tg-i-check"></use></svg>Active</span>`,
		fmt.Sprintf(`href="/users/%d"`, user.ID),
		`No repository access`,
		`<caption class="sr-only">Users, sign-in method, account status, and access summary</caption>`,
		`hidden overflow-x-auto md:block`,
		`md:hidden`,
		`href="/account/password"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected users page to contain %q", want)
		}
	}
	if strings.Contains(body, `action="/users/`) {
		t.Fatal("expected directory rows to remain navigation-only")
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/users/%d", user.ID), nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	body = recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected user detail page, got %d", recorder.Code)
	}
	for _, want := range []string{
		fmt.Sprintf(`action="/users/%d/enable"`, user.ID),
		`Re-enable this account before issuing a recovery link.`,
		`Repository access`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected user detail page to contain %q", want)
		}
	}
	if strings.Contains(body, fmt.Sprintf(`action="/users/%d/password-recovery"`, user.ID)) {
		t.Fatal("expected disabled user detail to omit the recovery issuance action")
	}

	if _, err := authService.EnableUser(ctx, admin.User.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/users/%d", user.ID), nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: admin.ID})
	server.Routes().ServeHTTP(recorder, request)
	body = recorder.Body.String()
	for _, want := range []string{
		fmt.Sprintf(`action="/users/%d/password-recovery"`, user.ID),
		`Issue recovery link`,
		`Create a one-hour bearer link. Anyone with this link can set this person&rsquo;s password until it expires. Share it through a trusted channel.`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected enabled user detail page to contain %q", want)
		}
	}
}

func TestRepositoryAccessFormPreservesSubmittedRolesAfterValidationError(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "viewer@example.test", false)
	repositoryID := mustInsertWebRepository(t, ctx, database)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{ID: repositoryID, Owner: "taua-almeida", Name: "thawguard"}}}})

	form := url.Values{
		"repository_id": {fmt.Sprint(repositoryID)},
		"roles":         {"freezer", "owner"},
		csrfFormField:   {admin.CSRFToken},
	}
	recorder := postAccountForm(t, server, fmt.Sprintf("/users/%d/repository-access", user.ID), &http.Cookie{Name: sessionCookieName, Value: admin.ID}, form)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest || !strings.Contains(body, "repository role is invalid") {
		t.Fatalf("expected role validation error, status=%d body=%q", recorder.Code, body)
	}
	if !strings.Contains(renderedControlTag(t, body, fmt.Sprintf("repo-%d-freezer", repositoryID)), " checked") {
		t.Fatal("expected submitted freezer role to stay selected after validation error")
	}
	if strings.Contains(renderedControlTag(t, body, fmt.Sprintf("repo-%d-viewer", repositoryID)), " checked") {
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

func TestDisabledUserSessionRedirectsToLogin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
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
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
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
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
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

	for _, path := range []string{"/freezes", fmt.Sprintf("/users/%d/admin", user.ID), fmt.Sprintf("/users/%d/password-recovery", user.ID), "/repositories"} {
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
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
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
	mustCreateWebUser(t, ctx, authService, "second-admin@example.test", true)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})

	form := url.Values{csrfFormField: {admin.CSRFToken}}
	recorder := postAccountForm(t, server, fmt.Sprintf("/users/%d/disable", admin.User.ID), &http.Cookie{Name: sessionCookieName, Value: admin.ID}, form)
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
	user := mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}

	form := url.Values{csrfFormField: {admin.CSRFToken}}
	recorder := postAccountForm(t, server, fmt.Sprintf("/users/%d/disable", user.ID), &http.Cookie{Name: sessionCookieName, Value: admin.ID}, form)
	body := recorder.Body.String()
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(body, "Something went wrong") || strings.Contains(body, "audit_events") {
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

func mustCreateWebUser(t *testing.T, ctx context.Context, authService *auth.Service, email string, isAdmin bool) auth.User {
	t.Helper()
	users, err := authService.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var actorUserID int64
	for _, user := range users {
		if user.IsAdmin && !user.Disabled() {
			actorUserID = user.ID
			break
		}
	}
	if actorUserID == 0 {
		t.Fatal("expected an enabled Admin fixture")
	}
	const temporaryPassword = "temporary initial password"
	user, err := authService.CreateUser(ctx, auth.CreateUserParams{ActorUserID: actorUserID, Email: email, DisplayName: "User " + email, Password: temporaryPassword})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := authService.ChangePassword(ctx, auth.ChangePasswordParams{UserID: user.ID, CurrentPassword: temporaryPassword, NewPassword: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	user = changed.User
	if isAdmin {
		user, err = authService.SetUserAdmin(ctx, auth.SetUserAdminParams{ActorUserID: actorUserID, UserID: user.ID, Admin: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	return user
}

func mustInsertWebRepository(t *testing.T, ctx context.Context, database interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) int64 {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := database.ExecContext(ctx, `
INSERT INTO repositories(forge, base_url, owner, name, default_branch, created_at, updated_at)
VALUES ('forgejo', 'https://forge.example.test', 'taua-almeida', 'thawguard', 'main', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustInsertWebRepositoryID(t *testing.T, ctx context.Context, database interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, id int64, name string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, created_at, updated_at)
VALUES (?, 'forgejo', 'https://forge.example.test', 'taua-almeida', ?, 'main', ?, ?)`, id, name, now, now); err != nil {
		t.Fatal(err)
	}
}

func postAccountForm(t *testing.T, server *Server, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", server.cfg.PublicURL)
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}
