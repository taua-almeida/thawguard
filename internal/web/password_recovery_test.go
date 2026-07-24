package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"html"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	webassets "github.com/taua-almeida/thawguard/web"
)

const (
	passwordRecoveryWebPublicURL = "https://thawguard.example.test"
	recoveredWebTestPassword     = "a recovered browser password"
)

var issuedRecoveryLinkPattern = regexp.MustCompile(`id="password-recovery-issued-link"[^>]*value="([^"]+)"`)

type passwordRecoveryWebFixture struct {
	ctx      context.Context
	database *sql.DB
	service  *auth.Service
	server   *Server
	admin    auth.Session
	target   auth.User
}

func TestNewServerRegistersPasswordRecoveryRoutesWithoutPatternConflict(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("NewServer panicked while registering password recovery routes: %v", recovered)
		}
	}()
	_ = NewServer(Config{AppName: "Thawguard"})
}

func TestPasswordRecoveryRouteSecurityHeaderMatrix(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	tests := []struct {
		method     string
		path       string
		wantStatus int
		wantAllow  bool
	}{
		{method: http.MethodGet, path: "/password-recovery", wantStatus: http.StatusOK},
		{method: http.MethodHead, path: "/password-recovery", wantStatus: http.StatusOK},
		{method: http.MethodPost, path: "/password-recovery", wantStatus: http.StatusForbidden},
		{method: http.MethodPut, path: "/password-recovery", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodOptions, path: "/password-recovery", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodGet, path: "/users/42/password-recovery", wantStatus: http.StatusNotFound},
		{method: http.MethodPost, path: "/users/42/password-recovery", wantStatus: http.StatusForbidden},
		{method: http.MethodDelete, path: "/users/42/password-recovery", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, nil)
			server.Routes().ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			assertPasswordRecoveryHeaders(t, recorder.Header())
			if test.wantAllow && recorder.Header().Get("Allow") == "" {
				t.Fatal("expected automatic method response to include Allow")
			}
		})
	}

	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/password-recovery/extra", nil))
	if recorder.Header().Get("Cache-Control") != "" || recorder.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("recovery headers must apply only to exact recovery paths")
	}
}

func TestPasswordRecoveryGETBootstrapsFragmentTransferWithoutCookie(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/password-recovery", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET recovery status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertPasswordRecoveryHeaders(t, recorder.Header())
	if recorder.Header().Get("Set-Cookie") != "" || len(recorder.Result().Cookies()) != 0 {
		t.Fatal("password recovery bootstrap must not create a CSRF or session cookie")
	}
	body := recorder.Body.String()
	for _, want := range []string{
		`id="password-recovery-form"`,
		`action="/password-recovery"`,
		`name="recovery_token" value=""`,
		`id="password-recovery-unavailable" role="alert" hidden`,
		`<noscript>`,
		"JavaScript is required to use this link safely. Enable JavaScript and reopen the original link, or ask your Admin for a new one.",
		`<script src="/static/js/password-recovery.js" defer></script>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("recovery bootstrap is missing %q", want)
		}
	}
	if strings.Count(body, "<script") != 1 || strings.Contains(body, "#token=") {
		t.Fatalf("unexpected recovery bootstrap script or bearer material: %q", body)
	}
	csrfToken := csrfTokenFromBody(t, body)
	if !server.validSignedCSRFToken(csrfToken, passwordRecoveryCSRFPurpose) {
		t.Fatal("GET recovery did not render a valid recovery-purpose CSRF token")
	}
}

func TestPasswordRecoveryCSRFIsPurposeSeparated(t *testing.T) {
	server := NewServer(Config{})
	recoveryToken, err := server.newPasswordRecoveryCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	setupToken, err := server.newSignedCSRFToken(setupCSRFPurpose)
	if err != nil {
		t.Fatal(err)
	}
	loginToken, err := server.newSignedCSRFToken(loginCSRFPurpose)
	if err != nil {
		t.Fatal(err)
	}

	if !server.validSignedCSRFToken(recoveryToken, passwordRecoveryCSRFPurpose) {
		t.Fatal("recovery-purpose token did not validate for recovery")
	}
	for purpose, token := range map[string]string{
		setupCSRFPurpose: setupToken,
		loginCSRFPurpose: loginToken,
	} {
		if server.validSignedCSRFToken(recoveryToken, purpose) {
			t.Fatalf("recovery token validated for %s", purpose)
		}
		if server.validSignedCSRFToken(token, passwordRecoveryCSRFPurpose) {
			t.Fatalf("%s token validated for password recovery", purpose)
		}
	}
}

func TestPasswordRecoveryScriptClearsFragmentBeforeParsingOrDOMMutation(t *testing.T) {
	scriptBytes, err := fs.ReadFile(webassets.StaticFS(), "js/password-recovery.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)
	capture := `const recoveryFragment = window.location.hash;`
	replace := `history.replaceState(null, "", "/password-recovery");`
	captureIndex := strings.Index(script, capture)
	replaceIndex := strings.Index(script, replace)
	parseIndex := strings.Index(script, "recoveryFragment.match(")
	domIndex := strings.Index(script, "document.getElementById(")
	if captureIndex < 0 || replaceIndex < 0 || parseIndex < 0 || domIndex < 0 {
		t.Fatalf("script is missing required fragment-transfer steps: %q", script)
	}
	if captureIndex >= replaceIndex || replaceIndex >= parseIndex || replaceIndex >= domIndex {
		t.Fatalf("fragment-transfer order is not capture -> replaceState -> parse/DOM: %q", script)
	}
	between := script[captureIndex+len(capture) : replaceIndex]
	if strings.TrimSpace(between) != "" {
		t.Fatalf("replaceState must immediately follow fragment capture, got %q", between)
	}
	if !strings.Contains(script, `^#token=([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$`) {
		t.Fatal("script does not enforce the canonical 43-character base64url token shape")
	}
	for _, forbidden := range []string{
		"fetch(",
		"xmlhttprequest",
		"sendbeacon",
		"websocket",
		"localstorage",
		"sessionstorage",
		"document.cookie",
		"console.",
		"innerhtml",
		"insertadjacenthtml",
	} {
		if strings.Contains(strings.ToLower(script), forbidden) {
			t.Fatalf("recovery script contains forbidden API %q", forbidden)
		}
	}
}

func TestAdminIssuesOneTimeRecoveryLinkFromCanonicalPublicURL(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID),
		strings.NewReader(form.Encode()),
	)
	request.Host = "hostile.example.test"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", passwordRecoveryWebPublicURL)
	request.Header.Set("Forwarded", "host=hostile.example.test;proto=http")
	request.Header.Set("X-Forwarded-Host", "hostile.example.test")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID})
	fixture.server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Location") != "" {
		t.Fatalf("issuance status=%d location=%q body=%q", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	assertPasswordRecoveryHeaders(t, recorder.Header())
	if recorder.Header().Get("Set-Cookie") != "" || len(recorder.Result().Cookies()) != 0 {
		t.Fatal("one-time issuance response must not create a cookie")
	}
	body := recorder.Body.String()
	link := issuedPasswordRecoveryLink(t, body)
	token := recoveryTokenFromLink(t, link)
	if !strings.HasPrefix(link, passwordRecoveryWebPublicURL+"/password-recovery#token=") {
		t.Fatalf("issued link did not use canonical PublicURL: %q", link)
	}
	for _, hostile := range []string{"hostile.example.test", "X-Forwarded-Host", "Forwarded"} {
		if strings.Contains(body, hostile) {
			t.Fatalf("issued response was influenced by hostile request metadata %q", hostile)
		}
	}
	for _, want := range []string{
		fixture.target.DisplayName,
		fixture.target.Email,
		"Copy this link now. Thawguard stores only its digest and cannot display it again.",
		"Issuing another link replaces this one.",
		"The current password and sessions remain unchanged until the link is used.",
		"Refreshing or resubmitting this form issues a replacement link and makes this one unavailable.",
		"UTC",
		fmt.Sprintf(`href="/users/%d"`, fixture.target.ID),
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("issuance response is missing %q", want)
		}
	}
	if strings.Contains(body, `href="`+link+`"`) || strings.Contains(body, `<a href="`+link) {
		t.Fatal("recovery bearer link must be read-only text, not a clickable anchor")
	}

	var storedDigest []byte
	var expiresAt int64
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT token_digest, expires_at FROM password_recovery_tokens WHERE user_id = ?`, fixture.target.ID).Scan(&storedDigest, &expiresAt); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256([]byte(token))
	if !bytes.Equal(storedDigest, wantDigest[:]) || bytes.Equal(storedDigest, []byte(token)) || expiresAt <= 0 {
		t.Fatal("password recovery storage did not retain exactly the digest and expiry")
	}
	assertRecoveryAuditDoesNotContain(t, fixture, token, link)

	for _, path := range []string{fmt.Sprintf("/users/%d", fixture.target.ID), "/password-recovery"} {
		later := httptest.NewRecorder()
		laterRequest := httptest.NewRequest(http.MethodGet, path, nil)
		if strings.HasPrefix(path, "/users/") {
			laterRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID})
		}
		fixture.server.Routes().ServeHTTP(later, laterRequest)
		if strings.Contains(later.Body.String(), token) || strings.Contains(later.Body.String(), link) {
			t.Fatalf("later GET %s reproduced one-time recovery material", path)
		}
	}

	second := postPasswordRecoveryForm(
		t,
		fixture.server,
		fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID),
		&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID},
		form,
		[]string{passwordRecoveryWebPublicURL},
	)
	secondLink := issuedPasswordRecoveryLink(t, second.Body.String())
	if second.Code != http.StatusOK || secondLink == link {
		t.Fatal("resubmission did not issue a distinct replacement link")
	}
	if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 1 || countAuditAction(t, fixture.ctx, fixture.database, audit.ActionUserPasswordRecoveryIssued) != 2 {
		t.Fatal("reissuance did not replace one row while retaining sanitized audit history")
	}
}

func TestAdminRecoveryIssuanceGatesHaveNoSideEffects(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(t *testing.T, fixture *passwordRecoveryWebFixture) (path string, cookie *http.Cookie, form url.Values)
		origins    []string
		wantStatus int
		wantPath   string
	}{
		{
			name: "missing Origin",
			prepare: func(_ *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{csrfFormField: {fixture.admin.CSRFToken}}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "wrong Origin",
			prepare: func(_ *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{csrfFormField: {fixture.admin.CSRFToken}}
			},
			origins:    []string{"https://hostile.example.test"},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "multiple Origin headers",
			prepare: func(_ *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{csrfFormField: {fixture.admin.CSRFToken}}
			},
			origins:    []string{passwordRecoveryWebPublicURL, passwordRecoveryWebPublicURL},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "missing session CSRF",
			prepare: func(_ *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{}
			},
			origins:    []string{passwordRecoveryWebPublicURL},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "invalid session CSRF",
			prepare: func(_ *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{csrfFormField: {"invalid"}}
			},
			origins:    []string{passwordRecoveryWebPublicURL},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "non-Admin",
			prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				session, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: fixture.target.Email, Password: accountWebTestPassword})
				if err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("/users/%d/password-recovery", fixture.admin.User.ID), &http.Cookie{Name: sessionCookieName, Value: session.ID}, url.Values{csrfFormField: {session.CSRFToken}}
			},
			origins:    []string{passwordRecoveryWebPublicURL},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "self target",
			prepare: func(_ *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				return fmt.Sprintf("/users/%d/password-recovery", fixture.admin.User.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{csrfFormField: {fixture.admin.CSRFToken}}
			},
			origins:    []string{passwordRecoveryWebPublicURL},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "disabled target",
			prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				if _, err := fixture.service.DisableUser(fixture.ctx, fixture.admin.User.ID, fixture.target.ID); err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID}, url.Values{csrfFormField: {fixture.admin.CSRFToken}}
			},
			origins:    []string{passwordRecoveryWebPublicURL},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "forced-password Admin",
			prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) (string, *http.Cookie, url.Values) {
				forcedAdmin := mustCreateWebUser(t, fixture.ctx, fixture.service, "forced-admin@example.test", true)
				const temporaryPassword = "forced admin temporary password"
				if err := fixture.service.ResetPassword(fixture.ctx, auth.ResetPasswordParams{
					ActorUserID:       fixture.admin.User.ID,
					UserID:            forcedAdmin.ID,
					TemporaryPassword: temporaryPassword,
				}); err != nil {
					t.Fatal(err)
				}
				session, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: forcedAdmin.Email, Password: temporaryPassword})
				if err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID), &http.Cookie{Name: sessionCookieName, Value: session.ID}, url.Values{csrfFormField: {session.CSRFToken}}
			},
			origins:    []string{passwordRecoveryWebPublicURL},
			wantStatus: http.StatusSeeOther,
			wantPath:   "/account/password",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPasswordRecoveryWebFixture(t)
			path, cookie, form := test.prepare(t, fixture)
			recorder := postPasswordRecoveryForm(t, fixture.server, path, cookie, form, test.origins)
			if recorder.Code != test.wantStatus || recorder.Header().Get("Location") != test.wantPath {
				t.Fatalf("status=%d location=%q body=%q", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
			}
			assertPasswordRecoveryHeaders(t, recorder.Header())
			if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 0 {
				t.Fatal("rejected issuance persisted a recovery token")
			}
			if countAuditAction(t, fixture.ctx, fixture.database, audit.ActionUserPasswordRecoveryIssued) != 0 {
				t.Fatal("rejected issuance created an audit event")
			}
			if strings.Contains(recorder.Body.String(), "#token=") {
				t.Fatal("rejected issuance response exposed bearer material")
			}
		})
	}
}

func TestAdminOversizedIssuanceBodyHasNoSideEffect(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	canary := strings.Repeat("oversized-issuance-canary", 500)
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}, "padding": {canary}}
	recorder := postPasswordRecoveryForm(
		t,
		fixture.server,
		fmt.Sprintf("/users/%d/password-recovery", fixture.target.ID),
		&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID},
		form,
		[]string{passwordRecoveryWebPublicURL},
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized issuance status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "oversized-issuance-canary") || countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 0 {
		t.Fatal("oversized issuance leaked input or created a token")
	}
}

func TestOldAdminPasswordResetRouteIsUnavailable(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	recorder := postPasswordRecoveryForm(
		t,
		fixture.server,
		fmt.Sprintf("/users/%d/reset-password", fixture.target.ID),
		&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID},
		url.Values{csrfFormField: {fixture.admin.CSRFToken}, "temporary_password": {"obsolete temporary password"}},
		[]string{passwordRecoveryWebPublicURL},
	)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("old reset route status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 0 {
		t.Fatal("old reset route created recovery state")
	}
}

func TestPasswordRecoveryOriginAndCSRFFailuresLeaveBearerUsable(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	issued := mustIssuePasswordRecoveryForWeb(t, fixture)
	csrfToken := getPasswordRecoveryCSRF(t, fixture.server)
	form := url.Values{
		csrfFormField:    {csrfToken},
		"recovery_token": {issued.Token},
		"new_password":   {recoveredWebTestPassword},
	}

	for _, test := range []struct {
		name    string
		origins []string
		csrf    string
	}{
		{name: "missing Origin", csrf: csrfToken},
		{name: "wrong Origin", origins: []string{"https://hostile.example.test"}, csrf: csrfToken},
		{name: "multiple Origin", origins: []string{passwordRecoveryWebPublicURL, passwordRecoveryWebPublicURL}, csrf: csrfToken},
		{name: "wrong CSRF purpose", origins: []string{passwordRecoveryWebPublicURL}, csrf: mustSignedCSRFToken(t, fixture.server, loginCSRFPurpose)},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempt := maps.Clone(form)
			attempt.Set(csrfFormField, test.csrf)
			recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, attempt, test.origins)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), issued.Token) || strings.Contains(recorder.Body.String(), recoveredWebTestPassword) {
				t.Fatal("origin/CSRF rejection rendered submitted secrets")
			}
			if countAuditAction(t, fixture.ctx, fixture.database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
				t.Fatal("origin/CSRF rejection called password recovery completion")
			}
		})
	}

	recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, form, []string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Password changed. Existing sessions were signed out. Sign in with your new password.") {
		t.Fatalf("bearer was not usable after origin/CSRF failures: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestPasswordRecoveryPasswordValidationRetainsBearerOnlyForHiddenRetry(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	issued := mustIssuePasswordRecoveryForWeb(t, fixture)
	csrfToken := getPasswordRecoveryCSRF(t, fixture.server)
	const shortPassword = "short"
	recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
		csrfFormField:    {csrfToken},
		"recovery_token": {issued.Token},
		"new_password":   {shortPassword},
	}, []string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("short-password status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	assertPasswordRecoveryHeaders(t, recorder.Header())
	body := recorder.Body.String()
	if !strings.Contains(body, "password must be at least 12 characters") {
		t.Fatalf("password-policy response is missing validation: %q", body)
	}
	if strings.Count(body, issued.Token) != 1 || !strings.Contains(body, `type="hidden" name="recovery_token" value="`+issued.Token+`"`) {
		t.Fatal("valid bearer was not retained exactly once in the hidden retry field")
	}
	if strings.Contains(body, shortPassword) || strings.Contains(body, "#token=") || strings.Contains(body, "/static/js/password-recovery.js") {
		t.Fatal("password-policy retry leaked a password, token-bearing URL, or bootstrap script")
	}
	if strings.Contains(renderedControlTag(t, body, "password-recovery-new-password"), " value=") {
		t.Fatal("password-policy retry must render a blank password field")
	}
	freshCSRF := csrfTokenFromBody(t, body)
	if freshCSRF == csrfToken || !fixture.server.validSignedCSRFToken(freshCSRF, passwordRecoveryCSRFPurpose) {
		t.Fatal("password-policy retry did not issue a fresh recovery-purpose CSRF token")
	}
	if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 1 {
		t.Fatal("password-policy failure consumed the bearer")
	}

	retry := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
		csrfFormField:    {freshCSRF},
		"recovery_token": {issued.Token},
		"new_password":   {recoveredWebTestPassword},
	}, []string{passwordRecoveryWebPublicURL})
	if retry.Code != http.StatusOK || retry.Header().Get("Location") != "" || strings.Contains(retry.Body.String(), issued.Token) {
		t.Fatalf("hidden retry did not complete safely: status=%d body=%q", retry.Code, retry.Body.String())
	}
}

func TestEveryInvalidPasswordRecoveryTokenStateHasIdenticalResponse(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, fixture *passwordRecoveryWebFixture) string
	}{
		{name: "malformed", prepare: func(_ *testing.T, _ *passwordRecoveryWebFixture) string { return "malformed-token-canary" }},
		{name: "unknown", prepare: func(_ *testing.T, _ *passwordRecoveryWebFixture) string { return strings.Repeat("A", 43) }},
		{name: "expired", prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) string {
			issued := mustIssuePasswordRecoveryForWeb(t, fixture)
			if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE password_recovery_tokens SET expires_at = 1 WHERE user_id = ?`, fixture.target.ID); err != nil {
				t.Fatal(err)
			}
			return issued.Token
		}},
		{name: "replaced", prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) string {
			first := mustIssuePasswordRecoveryForWeb(t, fixture)
			_ = mustIssuePasswordRecoveryForWeb(t, fixture)
			return first.Token
		}},
		{name: "used", prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) string {
			issued := mustIssuePasswordRecoveryForWeb(t, fixture)
			if err := fixture.service.CompletePasswordRecovery(fixture.ctx, auth.CompletePasswordRecoveryParams{Token: issued.Token, NewPassword: recoveredWebTestPassword}); err != nil {
				t.Fatal(err)
			}
			return issued.Token
		}},
		{name: "disabled", prepare: func(t *testing.T, fixture *passwordRecoveryWebFixture) string {
			issued := mustIssuePasswordRecoveryForWeb(t, fixture)
			if _, err := fixture.service.DisableUser(fixture.ctx, fixture.admin.User.ID, fixture.target.ID); err != nil {
				t.Fatal(err)
			}
			return issued.Token
		}},
	}

	var referenceBody string
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPasswordRecoveryWebFixture(t)
			token := test.prepare(t, fixture)
			recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
				csrfFormField:    {getPasswordRecoveryCSRF(t, fixture.server)},
				"recovery_token": {token},
				"new_password":   {recoveredWebTestPassword},
			}, []string{passwordRecoveryWebPublicURL})
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), invalidPasswordRecoveryMessage) {
				t.Fatalf("invalid-token response status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), token) || strings.Contains(recorder.Body.String(), recoveredWebTestPassword) {
				t.Fatal("invalid-token response exposed submitted bearer or password")
			}
			if referenceBody == "" {
				referenceBody = recorder.Body.String()
			} else if recorder.Body.String() != referenceBody {
				t.Fatal("invalid-token states did not return identical bodies")
			}
		})
	}
}

func TestPasswordRecoverySuccessCreatesNoSessionAndAppliesBackendEffects(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	const temporaryPassword = "temporary password before recovery"
	if err := fixture.service.ResetPassword(fixture.ctx, auth.ResetPasswordParams{
		ActorUserID:       fixture.admin.User.ID,
		UserID:            fixture.target.ID,
		TemporaryPassword: temporaryPassword,
	}); err != nil {
		t.Fatal(err)
	}
	firstSession, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: fixture.target.Email, Password: temporaryPassword})
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: fixture.target.Email, Password: temporaryPassword})
	if err != nil {
		t.Fatal(err)
	}
	issued := mustIssuePasswordRecoveryForWeb(t, fixture)
	recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
		csrfFormField:    {getPasswordRecoveryCSRF(t, fixture.server)},
		"recovery_token": {issued.Token},
		"new_password":   {recoveredWebTestPassword},
	}, []string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusOK || recorder.Header().Get("Location") != "" {
		t.Fatalf("completion status=%d location=%q body=%q", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	if recorder.Header().Get("Set-Cookie") != "" || len(recorder.Result().Cookies()) != 0 {
		t.Fatal("successful recovery must not create a session or CSRF cookie")
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Password changed. Existing sessions were signed out. Sign in with your new password.") || !strings.Contains(body, `href="/login"`) {
		t.Fatalf("completion response is missing success state: %q", body)
	}
	if strings.Contains(body, issued.Token) || strings.Contains(body, recoveredWebTestPassword) || strings.Contains(body, firstSession.ID) || strings.Contains(body, secondSession.ID) {
		t.Fatal("completion response exposed bearer, password, or session material")
	}
	if countUserSessionsForWeb(t, fixture.ctx, fixture.database, fixture.target.ID) != 0 {
		t.Fatal("successful recovery did not revoke every session or created a new one")
	}
	if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 0 {
		t.Fatal("successful recovery did not consume its bearer")
	}
	var passwordHash string
	var mustChange int
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT password_hash, must_change_password FROM users WHERE id = ?`, fixture.target.ID).Scan(&passwordHash, &mustChange); err != nil {
		t.Fatal(err)
	}
	if mustChange != 0 || strings.Contains(body, passwordHash) {
		t.Fatal("successful recovery did not clear forced-change state or exposed the password hash")
	}
	if _, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: fixture.target.Email, Password: temporaryPassword}); !auth.IsAuthenticationError(err) {
		t.Fatalf("old password remained usable after recovery: %v", err)
	}
	if _, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: fixture.target.Email, Password: recoveredWebTestPassword}); err != nil {
		t.Fatalf("recovered password could not sign in: %v", err)
	}
	if countAuditAction(t, fixture.ctx, fixture.database, audit.ActionUserPasswordRecoveryCompleted) != 1 {
		t.Fatal("successful recovery did not create exactly one completion audit event")
	}
	assertRecoveryAuditDoesNotContain(t, fixture, issued.Token, recoveredWebTestPassword, passwordHash, firstSession.ID, secondSession.ID)
}

func TestPasswordRecoveryRejectsUnexpectedAndOversizedFormsWithoutConsumingBearer(t *testing.T) {
	tests := []struct {
		name       string
		path       func(token string) string
		form       func(token, csrf string) url.Values
		wantStatus int
		canary     string
	}{
		{
			name: "unexpected field",
			path: func(_ string) string { return "/password-recovery" },
			form: func(token, csrf string) url.Values {
				return url.Values{csrfFormField: {csrf}, "recovery_token": {token}, "new_password": {recoveredWebTestPassword}, "unexpected": {"unexpected-field-canary"}}
			},
			wantStatus: http.StatusBadRequest,
			canary:     "unexpected-field-canary",
		},
		{
			name: "query bearer",
			path: func(token string) string { return "/password-recovery?recovery_token=" + url.QueryEscape(token) },
			form: func(_ string, csrf string) url.Values {
				return url.Values{csrfFormField: {csrf}, "new_password": {recoveredWebTestPassword}}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "oversized body",
			path: func(_ string) string { return "/password-recovery" },
			form: func(token, csrf string) url.Values {
				return url.Values{csrfFormField: {csrf}, "recovery_token": {token}, "new_password": {strings.Repeat("oversized-password-canary", 500)}}
			},
			wantStatus: http.StatusRequestEntityTooLarge,
			canary:     "oversized-password-canary",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPasswordRecoveryWebFixture(t)
			issued := mustIssuePasswordRecoveryForWeb(t, fixture)
			csrfToken := getPasswordRecoveryCSRF(t, fixture.server)
			recorder := postPasswordRecoveryForm(t, fixture.server, test.path(issued.Token), nil, test.form(issued.Token, csrfToken), []string{passwordRecoveryWebPublicURL})
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), issued.Token) || (test.canary != "" && strings.Contains(recorder.Body.String(), test.canary)) {
				t.Fatal("rejected form rendered submitted secret material")
			}
			if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 1 || countAuditAction(t, fixture.ctx, fixture.database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
				t.Fatal("rejected form consumed the bearer or completed recovery")
			}
			if err := fixture.service.CompletePasswordRecovery(fixture.ctx, auth.CompletePasswordRecoveryParams{Token: issued.Token, NewPassword: recoveredWebTestPassword}); err != nil {
				t.Fatalf("bearer was unusable after rejected form: %v", err)
			}
		})
	}
}

func TestPasswordRecoveryInternalFailureIsGenericAndRollsBack(t *testing.T) {
	fixture := newPasswordRecoveryWebFixture(t)
	issued := mustIssuePasswordRecoveryForWeb(t, fixture)
	const passwordCanary = "internal-failure-password-canary"
	if _, err := fixture.database.ExecContext(fixture.ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
		csrfFormField:    {getPasswordRecoveryCSRF(t, fixture.server)},
		"recovery_token": {issued.Token},
		"new_password":   {passwordCanary},
	}, []string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "Thawguard could not complete password recovery") {
		t.Fatalf("internal failure status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	for _, secret := range []string{issued.Token, passwordCanary, "audit_events", "password_hash", "session"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("internal error response exposed %q", secret)
		}
	}
	if countPasswordRecoveryRows(t, fixture.ctx, fixture.database) != 1 {
		t.Fatal("internal completion failure did not roll back bearer consumption")
	}
}

func newPasswordRecoveryWebFixture(t *testing.T) *passwordRecoveryWebFixture {
	t.Helper()
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	service := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, service)
	target := mustCreateWebUser(t, ctx, service, "recovery-target@example.test", false)
	return &passwordRecoveryWebFixture{
		ctx:      ctx,
		database: database,
		service:  service,
		server: NewServer(Config{
			AppName:     "Thawguard",
			PublicURL:   passwordRecoveryWebPublicURL,
			AuthService: service,
		}),
		admin:  admin,
		target: target,
	}
}

func mustIssuePasswordRecoveryForWeb(t *testing.T, fixture *passwordRecoveryWebFixture) auth.PasswordRecoveryToken {
	t.Helper()
	issued, err := fixture.service.IssuePasswordRecoveryToken(fixture.ctx, auth.IssuePasswordRecoveryParams{
		ActorUserID: fixture.admin.User.ID,
		UserID:      fixture.target.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func getPasswordRecoveryCSRF(t *testing.T, server *Server) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/password-recovery", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("recovery bootstrap status=%d Set-Cookie=%q", recorder.Code, recorder.Header().Get("Set-Cookie"))
	}
	return csrfTokenFromBody(t, recorder.Body.String())
}

func mustSignedCSRFToken(t *testing.T, server *Server, purpose string) string {
	t.Helper()
	token, err := server.newSignedCSRFToken(purpose)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func postPasswordRecoveryForm(
	t *testing.T,
	server *Server,
	path string,
	cookie *http.Cookie,
	form url.Values,
	origins []string,
) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, origin := range origins {
		request.Header.Add("Origin", origin)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func issuedPasswordRecoveryLink(t *testing.T, body string) string {
	t.Helper()
	match := issuedRecoveryLinkPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("issued recovery response does not contain read-only link input: %q", body)
	}
	return html.UnescapeString(match[1])
}

func recoveryTokenFromLink(t *testing.T, link string) string {
	t.Helper()
	prefix := passwordRecoveryWebPublicURL + "/password-recovery#token="
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("unexpected recovery link %q", link)
	}
	token := strings.TrimPrefix(link, prefix)
	if len(token) != 43 {
		t.Fatalf("recovery bearer length=%d, want 43", len(token))
	}
	return token
}

func countPasswordRecoveryRows(t *testing.T, ctx context.Context, database *sql.DB) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM password_recovery_tokens`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countAuditAction(t *testing.T, ctx context.Context, database *sql.DB, action string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ?`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countUserSessionsForWeb(t *testing.T, ctx context.Context, database *sql.DB, userID int64) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = ?`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func assertRecoveryAuditDoesNotContain(t *testing.T, fixture *passwordRecoveryWebFixture, secrets ...string) {
	t.Helper()
	rows, err := fixture.database.QueryContext(fixture.ctx, `SELECT action, subject_type, subject_id, details_json FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var auditText strings.Builder
	for rows.Next() {
		var action, subjectType, subjectID, details string
		if err := rows.Scan(&action, &subjectType, &subjectID, &details); err != nil {
			t.Fatal(err)
		}
		auditText.WriteString(action)
		auditText.WriteString(subjectType)
		auditText.WriteString(subjectID)
		auditText.WriteString(details)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(auditText.String(), secret) {
			t.Fatalf("audit storage exposed secret material")
		}
	}
}

func assertPasswordRecoveryHeaders(t *testing.T, header http.Header) {
	t.Helper()
	wants := map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": passwordRecoveryCSP,
	}
	for name, want := range wants {
		if got := header.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}
