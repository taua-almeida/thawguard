package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
	webassets "github.com/taua-almeida/thawguard/web"
)

const invitedWebTestPassword = "an invited chooser password"

var issuedInvitationLinkPattern = regexp.MustCompile(`id="invitation-issued-link"[^>]*value="([^"]+)"`)

type invitationWebFixture struct {
	ctx          context.Context
	database     *sql.DB
	service      *auth.Service
	server       *Server
	logs         *bytes.Buffer
	admin        auth.Session
	repositoryID int64
}

func newInvitationWebFixture(t *testing.T) *invitationWebFixture {
	t.Helper()
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	service := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, service)
	repositoryID := mustInsertWebRepository(t, ctx, database)
	logger, logs := newRejectionLogSink()
	server := NewServer(Config{
		AppName:     "Thawguard",
		PublicURL:   passwordRecoveryWebPublicURL,
		AuthService: service,
		Logger:      logger,
		RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{
			ID:    repositoryID,
			Owner: "taua-almeida",
			Name:  "thawguard",
		}}},
	})
	return &invitationWebFixture{
		ctx:          ctx,
		database:     database,
		service:      service,
		server:       server,
		logs:         logs,
		admin:        admin,
		repositoryID: repositoryID,
	}
}

func (f *invitationWebFixture) adminCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: f.admin.ID}
}

func (f *invitationWebFixture) invitationCreateForm(email, displayName string, grants ...string) url.Values {
	form := url.Values{
		csrfFormField:  {f.admin.CSRFToken},
		"email":        {email},
		"display_name": {displayName},
	}
	for _, grant := range grants {
		form.Add("repository_grants", grant)
	}
	return form
}

func (f *invitationWebFixture) mustCreateInvitationOverHTTP(t *testing.T, form url.Values) string {
	t.Helper()
	recorder := postPasswordRecoveryForm(t, f.server, "/users/invitations", f.adminCookie(), form, []string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusOK {
		t.Fatalf("create invitation status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	return issuedInvitationLink(t, recorder.Body.String())
}

func (f *invitationWebFixture) mustCreateServiceInvitation(t *testing.T, email string, isAdmin bool, grants ...auth.InvitationRepositoryGrant) auth.InvitationCredential {
	t.Helper()
	credential, err := f.service.CreateInvitation(f.ctx, auth.CreateInvitationParams{
		ActorUserID:      f.admin.User.ID,
		Email:            email,
		DisplayName:      "Invited " + email,
		IsAdmin:          isAdmin,
		RepositoryGrants: grants,
	})
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func (f *invitationWebFixture) expireInvitation(t *testing.T, invitationID string) {
	t.Helper()
	if _, err := f.database.ExecContext(f.ctx, `UPDATE invitations SET expires_at = 1 WHERE id = ?`, invitationID); err != nil {
		t.Fatal(err)
	}
}

func (f *invitationWebFixture) markInvitationNeedsReplacement(t *testing.T, invitationID string) {
	t.Helper()
	if _, err := f.database.ExecContext(f.ctx, `UPDATE invitations SET status = 'needs_reissue', token_digest = NULL, expires_at = NULL, authorized_by_user_id = NULL WHERE id = ?`, invitationID); err != nil {
		t.Fatal(err)
	}
}

func (f *invitationWebFixture) deleteRepository(t *testing.T, repositoryID int64) {
	t.Helper()
	if _, err := f.database.ExecContext(f.ctx, `DELETE FROM repositories WHERE id = ?`, repositoryID); err != nil {
		t.Fatal(err)
	}
}

func (f *invitationWebFixture) countInvitations(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.database.QueryRowContext(f.ctx, `SELECT count(*) FROM invitations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (f *invitationWebFixture) invitationStatus(t *testing.T, invitationID string) string {
	t.Helper()
	var status string
	if err := f.database.QueryRowContext(f.ctx, `SELECT status FROM invitations WHERE id = ?`, invitationID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func (f *invitationWebFixture) countStagedGrants(t *testing.T, invitationID string) int {
	t.Helper()
	var count int
	if err := f.database.QueryRowContext(f.ctx, `SELECT count(*) FROM invitation_repository_grants WHERE invitation_id = ?`, invitationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// assertInvitationTombstone verifies the terminal row keeps only its status:
// every identity, bearer, expiry, and staged-authority column must be NULLed
// and the staged grants deleted.
func (f *invitationWebFixture) assertInvitationTombstone(t *testing.T, invitationID, wantStatus string) {
	t.Helper()
	var status string
	nulls := make([]bool, 7)
	if err := f.database.QueryRowContext(f.ctx, `
SELECT status,
       canonical_email IS NULL,
       display_name IS NULL,
       token_digest IS NULL,
       expires_at IS NULL,
       is_admin IS NULL,
       authorized_by_user_id IS NULL,
       expected_repository_grant_count IS NULL
FROM invitations WHERE id = ?`, invitationID).Scan(&status, &nulls[0], &nulls[1], &nulls[2], &nulls[3], &nulls[4], &nulls[5], &nulls[6]); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus {
		t.Fatalf("invitation status = %q, want %q", status, wantStatus)
	}
	for i, isNull := range nulls {
		if !isNull {
			t.Fatalf("tombstoned invitation retained a value in redacted column %d", i)
		}
	}
	if got := f.countStagedGrants(t, invitationID); got != 0 {
		t.Fatalf("tombstoned invitation kept %d staged grants", got)
	}
}

// mustPendingInvitationID returns the single live invitation, which is what
// makes "the replacement was not rotated" checkable: a replay that minted
// another row would leave two.
func (f *invitationWebFixture) mustPendingInvitationID(t *testing.T) string {
	t.Helper()
	var invitationID string
	if err := f.database.QueryRowContext(f.ctx, `SELECT id FROM invitations WHERE status = 'pending'`).Scan(&invitationID); err != nil {
		t.Fatal(err)
	}
	return invitationID
}

func (f *invitationWebFixture) invitationTokenDigest(t *testing.T, invitationID string) []byte {
	t.Helper()
	var digest []byte
	if err := f.database.QueryRowContext(f.ctx, `SELECT token_digest FROM invitations WHERE id = ?`, invitationID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

func sha256Sum(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func (f *invitationWebFixture) invitationIsAdmin(t *testing.T, invitationID string) bool {
	t.Helper()
	var isAdmin int64
	if err := f.database.QueryRowContext(f.ctx, `SELECT is_admin FROM invitations WHERE id = ?`, invitationID).Scan(&isAdmin); err != nil {
		t.Fatal(err)
	}
	return isAdmin != 0
}

// usersDialogWidth is the width every /users dialog shares. The design requires
// Add local user, Invite person, and the one-time result to match, and the
// min() keeps a gutter at 390px that a bare w-full would not: a modal <dialog>
// sizes against the viewport, so width:100% renders edge to edge.
const usersDialogWidth = `w-[min(28rem,90vw)]`

// assertSingleOpenInvitationResult pins the one-time delivery contract: the
// result dialog is rendered once, already open, on exactly the response that
// carries the bearer.
func assertSingleOpenInvitationResult(t *testing.T, body string) {
	t.Helper()
	if got := strings.Count(body, "data-invitation-result"); got != 1 {
		t.Fatalf("result dialog rendered %d times, want exactly one", got)
	}
	if !strings.Contains(body, `id="invitation-result-dialog" open data-invitation-result`) {
		t.Fatal("result dialog must be server-rendered open so it works without JavaScript")
	}
	if got := strings.Count(body, `aria-label="Active invitations"`); got != 1 {
		t.Fatal("the one-time link must be delivered over the signed-in Users & Access shell")
	}
	if link := renderedControlTag(t, body, "invitation-issued-link"); !strings.Contains(link, "autofocus") {
		t.Fatal("the one-time link must receive focus so the no-JavaScript result scrolls into view")
	}
	if tag := renderedControlTag(t, body, "invitation-result-dialog"); !strings.Contains(tag, usersDialogWidth) {
		t.Fatalf("result dialog width must match the other /users dialogs: %s", tag)
	}
	for _, id := range []string{"invitation-result-title", "invitation-result-guidance"} {
		if got := strings.Count(body, fmt.Sprintf(`id=%q`, id)); got != 1 {
			t.Fatalf("result dialog target %s rendered %d times, want exactly once", id, got)
		}
	}
}

func TestUsersPageRequiredUtilitiesAreCompiled(t *testing.T) {
	cssBytes, err := fs.ReadFile(webassets.StaticFS(), "app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssBytes)
	for _, want := range []string{
		`.items-end{align-items:flex-end}`,
		`.md\:grid-cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}`,
		`.w-\[min\(28rem\,90vw\)\]{width:min(28rem,90vw)}`,
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("compiled app.css is missing required /users utility %q", want)
		}
	}
}

func issuedInvitationLink(t *testing.T, body string) string {
	t.Helper()
	match := issuedInvitationLinkPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("issued invitation response does not contain read-only link input: %q", body)
	}
	return html.UnescapeString(match[1])
}

func invitationTokenFromLink(t *testing.T, link string) string {
	t.Helper()
	prefix := passwordRecoveryWebPublicURL + "/invitations/accept#token="
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("unexpected invitation link %q", link)
	}
	token := strings.TrimPrefix(link, prefix)
	if len(token) != 43 {
		t.Fatalf("invitation bearer length=%d, want 43", len(token))
	}
	return token
}

func invitationAcceptForm(csrfToken, token, password string) url.Values {
	return url.Values{
		csrfFormField:      {csrfToken},
		"invitation_token": {token},
		"new_password":     {password},
	}
}

func getInvitationAcceptCSRF(t *testing.T, server *Server) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/invitations/accept", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("invitation bootstrap status=%d Set-Cookie=%q", recorder.Code, recorder.Header().Get("Set-Cookie"))
	}
	return csrfTokenFromBody(t, recorder.Body.String())
}

func assertNoSetCookie(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if cookies := recorder.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("response set cookies %q on a cookie-free contract", cookies)
	}
}

func assertInvitationAuditDoesNotContain(t *testing.T, fixture *invitationWebFixture, secrets ...string) {
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

func TestInvitationRouteSecurityHeaderMatrix(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	tests := []struct {
		method     string
		path       string
		wantStatus int
		wantAllow  bool
		wantBody   string
	}{
		{method: http.MethodGet, path: "/invitations/accept", wantStatus: http.StatusOK},
		{method: http.MethodHead, path: "/invitations/accept", wantStatus: http.StatusOK},
		{method: http.MethodPost, path: "/invitations/accept", wantStatus: http.StatusForbidden},
		{method: http.MethodPut, path: "/invitations/accept", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodPost, path: "/users/invitations", wantStatus: http.StatusForbidden, wantBody: "Invitation not created"},
		{method: http.MethodGet, path: "/users/invitations", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodHead, path: "/users/invitations", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodPut, path: "/users/invitations", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodOptions, path: "/users/invitations", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodDelete, path: "/users/invitations", wantStatus: http.StatusMethodNotAllowed, wantAllow: true},
		{method: http.MethodPost, path: "/users/invitations/inv_AAAAAAAAAAAAAAAAAAAAAA/cancel", wantStatus: http.StatusForbidden, wantBody: "forbidden"},
		{method: http.MethodPost, path: "/users/invitations/not-an-id/cancel", wantStatus: http.StatusNotFound},
		{method: http.MethodPost, path: "/users/invitations/inv_AAAAAAAAAAAAAAAAAAAAAA/replace", wantStatus: http.StatusForbidden, wantBody: "Invitation link not replaced"},
		{method: http.MethodPost, path: "/users/invitations/not-an-id/replace", wantStatus: http.StatusNotFound},
		{method: http.MethodGet, path: "/users/invitations/inv_AAAAAAAAAAAAAAAAAAAAAA/replace", wantStatus: http.StatusNotFound, wantBody: "Page not found"},
		// GET on the cancel path falls through to the "GET /" catch-all 404
		// page; the sensitive headers still apply.
		{method: http.MethodGet, path: "/users/invitations/inv_AAAAAAAAAAAAAAAAAAAAAA/cancel", wantStatus: http.StatusNotFound, wantBody: "Page not found"},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			fixture.server.Routes().ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			assertPasswordRecoveryHeaders(t, recorder.Header())
			assertNoSetCookie(t, recorder)
			if test.wantAllow && recorder.Header().Get("Allow") == "" {
				t.Fatal("expected automatic method response to include Allow")
			}
			if test.path == "/users/invitations" && test.method != http.MethodPost && recorder.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow = %q, want POST", recorder.Header().Get("Allow"))
			}
			if test.wantBody != "" && !strings.Contains(recorder.Body.String(), test.wantBody) {
				t.Fatalf("body=%q, want substring %q", recorder.Body.String(), test.wantBody)
			}
		})
	}
	for _, path := range []string{"/invitations/accept/extra", "/users"} {
		t.Run("not sensitive "+path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			fixture.server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Header().Get("Content-Security-Policy") == passwordRecoveryCSP {
				t.Fatalf("path %s must not adopt the sensitive bearer CSP", path)
			}
		})
	}
}

func TestInvitationAcceptBootstrapServesTokenlessFormWithoutCookies(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	recorder := httptest.NewRecorder()
	fixture.server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/invitations/accept", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertNoSetCookie(t, recorder)
	body := recorder.Body.String()
	if !strings.Contains(body, `gap-4" hidden>`) {
		t.Fatal("bootstrap form must start hidden until the script validates the fragment")
	}
	if !strings.Contains(body, `<input id="invitation-accept-token" type="hidden" name="invitation_token" value="">`) {
		t.Fatal("bootstrap page must render an empty hidden token field")
	}
	if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/js/invitation-accept.js" defer></script>`) {
		t.Fatalf("bootstrap page must load exactly the invitation script, body=%q", body)
	}
	unavailable := renderedControlTag(t, body, "invitation-accept-unavailable")
	if !strings.Contains(unavailable, `role="alert"`) || !strings.Contains(unavailable, "hidden") {
		t.Fatalf("unavailable state tag = %q", unavailable)
	}
	if !strings.Contains(body, "JavaScript is required to use this link safely.") {
		t.Fatal("expected explicit no-JavaScript guidance")
	}
	if got := strings.Count(strings.ToLower(body), "ask an admin for a replacement invitation link"); got != 1 {
		t.Fatalf("replacement guidance rendered %d times, want only the no-JavaScript state", got)
	}
	if !strings.Contains(body, "Try signing in with your invited email address, or ask an Admin to check your account or active invitation.") {
		t.Fatal("invalid-fragment guidance must cover terminal accepted invitations truthfully")
	}
	if strings.Contains(body, "cancel this invitation and create a new one") {
		t.Fatal("acceptance guidance must preserve replacement semantics")
	}
	if strings.Contains(body, "#token=") {
		t.Fatal("bootstrap page must never mention the fragment bearer")
	}
	csrfToken := csrfTokenFromBody(t, body)
	if !fixture.server.validSignedCSRFToken(csrfToken, invitationCSRFPurpose) {
		t.Fatal("bootstrap CSRF token failed invitation-purpose validation")
	}
}

func TestInvitationCSRFPurposeIsSeparateFromPasswordRecovery(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	recoveryToken := mustSignedCSRFToken(t, fixture.server, passwordRecoveryCSRFPurpose)
	invitationToken := mustSignedCSRFToken(t, fixture.server, invitationCSRFPurpose)
	if fixture.server.validSignedCSRFToken(recoveryToken, invitationCSRFPurpose) {
		t.Fatal("recovery-purpose CSRF token validated for the invitation purpose")
	}
	if fixture.server.validSignedCSRFToken(invitationToken, passwordRecoveryCSRFPurpose) {
		t.Fatal("invitation-purpose CSRF token validated for the recovery purpose")
	}

	unknownBearer := strings.Repeat("A", 43)
	crossed := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(recoveryToken, unknownBearer, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if crossed.Code != http.StatusForbidden || !strings.Contains(crossed.Body.String(), "Invitation request not verified") {
		t.Fatalf("crossed-purpose CSRF status=%d body=%q", crossed.Code, crossed.Body.String())
	}
	correct := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(invitationToken, unknownBearer, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if correct.Code != http.StatusBadRequest || !strings.Contains(correct.Body.String(), "Invitation unavailable") {
		t.Fatalf("invitation-purpose CSRF should reach the service, status=%d body=%q", correct.Code, correct.Body.String())
	}
}

func TestInvitationAcceptStaticScriptStaysFragmentOnlyAndInert(t *testing.T) {
	scriptBytes, err := fs.ReadFile(webassets.StaticFS(), "js/invitation-accept.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)

	capture := strings.Index(script, "const invitationFragment = window.location.hash;")
	scrub := strings.Index(script, `history.replaceState(null, "", "/invitations/accept");`)
	firstDOM := strings.Index(script, "document.getElementById(")
	match := strings.Index(script, "invitationFragment.match(")
	if capture < 0 || scrub < 0 || firstDOM < 0 || match < 0 {
		t.Fatalf("script is missing a required statement: capture=%d scrub=%d dom=%d match=%d", capture, scrub, firstDOM, match)
	}
	if !(capture < scrub && scrub < firstDOM && scrub < match) {
		t.Fatal("script must copy the fragment and scrub the address bar before any DOM or matching work")
	}
	if !strings.Contains(script, "/^#token=([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/") {
		t.Fatal("script must accept only the exact canonical 32-byte base64url bearer shape")
	}

	lowered := strings.ToLower(script)
	forbidden := []string{
		"fetch(",
		"xmlhttprequest",
		"sendbeacon",
		"websocket",
		"eventsource",
		"localstorage",
		"sessionstorage",
		"indexeddb",
		"document.cookie",
		"console.",
		"innerhtml",
		"insertadjacenthtml",
		"document.write",
		"clipboard",
		"location.search",
	}
	for _, needle := range forbidden {
		if strings.Contains(lowered, needle) {
			t.Fatalf("script must not use %q", needle)
		}
	}
}

func TestInvitationCreateDisplaysOneTimeCanonicalLink(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	form := fixture.invitationCreateForm(
		"invitee@example.test",
		"Invited Person",
		fmt.Sprintf("%d:viewer", fixture.repositoryID),
		fmt.Sprintf("%d:thaw_approver", fixture.repositoryID),
	)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users/invitations", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", passwordRecoveryWebPublicURL)
	request.Host = "evil.example.test"
	request.Header.Set("X-Forwarded-Host", "evil.example.test")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Forwarded", "host=evil.example.test;proto=https")
	request.AddCookie(fixture.adminCookie())
	fixture.server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertPasswordRecoveryHeaders(t, recorder.Header())

	body := recorder.Body.String()
	link := issuedInvitationLink(t, body)
	token := invitationTokenFromLink(t, link)
	if strings.Contains(body, "evil.example.test") {
		t.Fatal("issued link must ignore hostile Host and forwarding headers")
	}
	if strings.Count(body, token) != 1 {
		t.Fatalf("bearer appeared %d times, want exactly once", strings.Count(body, token))
	}
	if cookies := strings.Join(recorder.Header().Values("Set-Cookie"), " "); strings.Contains(cookies, token) {
		t.Fatal("bearer leaked into a cookie")
	}
	if !strings.Contains(renderedControlTag(t, body, "invitation-issued-link"), "readonly") {
		t.Fatal("issued link input must be read-only")
	}
	for _, want := range []string{
		"Invitation created",
		"One-time invitation link",
		"cannot display it again.",
		"Valid for up to seven days, until",
		"The link can stop working earlier if the invitation is cancelled",
		"If you lose it, replace the link in Active invitations.",
		"No email was sent.",
		"No account exists until they accept.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("issued page missing %q", want)
		}
	}
	assertSingleOpenInvitationResult(t, body)

	var invitationID string
	var digest []byte
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT id, token_digest FROM invitations WHERE status = 'pending'`).Scan(&invitationID, &digest); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256([]byte(token))
	if !bytes.Equal(digest, wantDigest[:]) {
		t.Fatal("stored digest does not match the displayed bearer")
	}
	if got := fixture.countStagedGrants(t, invitationID); got != 2 {
		t.Fatalf("staged grants = %d, want 2", got)
	}
	if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationCreated); got != 1 {
		t.Fatalf("invitation.created audit rows = %d, want 1", got)
	}
	assertInvitationAuditDoesNotContain(t, fixture, token)

	later := getUsersPage(t, fixture.server, "/users", fixture.adminCookie(), false)
	if later.Code != http.StatusOK {
		t.Fatalf("users page status = %d", later.Code)
	}
	if strings.Contains(later.Body.String(), token) || strings.Contains(later.Body.String(), "#token=") {
		t.Fatal("bearer must never be reproduced after the one-time response")
	}
}

func TestInvitationCreateUnknownOutcomeClaimsNoRollbackAndRevealsNoLink(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	if _, err := fixture.database.ExecContext(fixture.ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(),
		fixture.invitationCreateForm("unknown-create@example.test", "Unknown Create"),
		[]string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertPasswordRecoveryHeaders(t, recorder.Header())
	body := recorder.Body.String()
	for _, want := range []string{
		"Invitation result unconfirmed",
		"could not confirm whether the invitation was created",
		"Inspect Active invitations before retrying",
		"replace its link, because the original was never displayed",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unknown create response missing %q", want)
		}
	}
	for _, forbidden := range []string{"#token=", "nothing changed", "was not created", "rolled back"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("unknown create response must not contain %q", forbidden)
		}
	}
	if got := fixture.countInvitations(t); got != 0 {
		t.Fatalf("pre-commit audit failure left %d invitation rows", got)
	}
}

func TestInvitationCreateGatesLeaveNoSideEffects(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	mustCreateWebUser(t, fixture.ctx, fixture.service, "viewer@example.test", false)
	viewerSession, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: "viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	forcedAdmin := mustCreateWebUser(t, fixture.ctx, fixture.service, "forced-admin@example.test", true)
	forcedSession, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: "forced-admin@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, forcedAdmin.ID); err != nil {
		t.Fatal(err)
	}

	baseForm := func() url.Values {
		return fixture.invitationCreateForm("gate-invitee@example.test", "Gate Invitee", fmt.Sprintf("%d:viewer", fixture.repositoryID))
	}
	tests := []struct {
		name         string
		origins      []string
		cookie       *http.Cookie
		form         func() url.Values
		wantStatus   int
		wantBody     string
		wantLocation string
	}{
		{name: "missing origin", origins: nil, cookie: fixture.adminCookie(), form: baseForm, wantStatus: http.StatusForbidden, wantBody: "Invitation not created"},
		{name: "wrong origin", origins: []string{"https://evil.example.test"}, cookie: fixture.adminCookie(), form: baseForm, wantStatus: http.StatusForbidden, wantBody: "Invitation not created"},
		{name: "null origin", origins: []string{"null"}, cookie: fixture.adminCookie(), form: baseForm, wantStatus: http.StatusForbidden, wantBody: "Invitation not created"},
		{name: "duplicated origin", origins: []string{passwordRecoveryWebPublicURL, passwordRecoveryWebPublicURL}, cookie: fixture.adminCookie(), form: baseForm, wantStatus: http.StatusForbidden, wantBody: "Invitation not created"},
		{name: "no session", origins: []string{passwordRecoveryWebPublicURL}, cookie: nil, form: baseForm, wantStatus: http.StatusForbidden, wantBody: "forbidden"},
		{
			name:    "non-admin session",
			origins: []string{passwordRecoveryWebPublicURL},
			cookie:  &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID},
			form: func() url.Values {
				form := baseForm()
				form.Set(csrfFormField, viewerSession.CSRFToken)
				return form
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "wrong session CSRF",
			origins: []string{passwordRecoveryWebPublicURL},
			cookie:  fixture.adminCookie(),
			form: func() url.Values {
				form := baseForm()
				form.Set(csrfFormField, "not-the-session-token")
				return form
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "forbidden",
		},
		{
			name:    "missing session CSRF",
			origins: []string{passwordRecoveryWebPublicURL},
			cookie:  fixture.adminCookie(),
			form: func() url.Values {
				form := baseForm()
				form.Del(csrfFormField)
				return form
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "forbidden",
		},
		{
			name:    "forced-password admin",
			origins: []string{passwordRecoveryWebPublicURL},
			cookie:  &http.Cookie{Name: sessionCookieName, Value: forcedSession.ID},
			form: func() url.Values {
				form := baseForm()
				form.Set(csrfFormField, forcedSession.CSRFToken)
				return form
			},
			wantStatus:   http.StatusSeeOther,
			wantLocation: "/account/password",
		},
		{
			name:    "oversized body",
			origins: []string{passwordRecoveryWebPublicURL},
			cookie:  fixture.adminCookie(),
			form: func() url.Values {
				form := baseForm()
				form.Set("display_name", strings.Repeat("x", int(invitationCreateMaxBodyBytes)+1024))
				return form
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad request",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", test.cookie, test.form(), test.origins)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantBody != "" && !strings.Contains(recorder.Body.String(), test.wantBody) {
				t.Fatalf("body=%q, want substring %q", recorder.Body.String(), test.wantBody)
			}
			if test.wantLocation != "" && recorder.Header().Get("Location") != test.wantLocation {
				t.Fatalf("Location = %q, want %q", recorder.Header().Get("Location"), test.wantLocation)
			}
			if strings.Contains(recorder.Body.String(), "#token=") {
				t.Fatal("rejected request rendered bearer material")
			}
			if got := fixture.countInvitations(t); got != 0 {
				t.Fatalf("rejected request created %d invitations", got)
			}
			if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationCreated); got != 0 {
				t.Fatalf("rejected request wrote %d creation audits", got)
			}
		})
	}
}

func TestInvitationCreateValidationPreservesSafeStateNeverBearer(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	goodGrant := fmt.Sprintf("%d:viewer", fixture.repositoryID)
	tests := []struct {
		name      string
		mutate    func(form url.Values)
		wantError string
	}{
		{
			name:      "duplicate email field",
			mutate:    func(form url.Values) { form.Add("email", "second@example.test") },
			wantError: "the email field was submitted more than once",
		},
		{
			name:      "unsupported field",
			mutate:    func(form url.Values) { form.Set("surprise", "1") },
			wantError: "the form contains an unsupported field",
		},
		{
			name:      "invalid admin value",
			mutate:    func(form url.Values) { form.Set("admin", "2") },
			wantError: "the admin selection is invalid",
		},
		{
			name:      "malformed grant",
			mutate:    func(form url.Values) { form.Add("repository_grants", "abc") },
			wantError: "a staged repository access selection is invalid",
		},
		{
			name:      "signed repository id",
			mutate:    func(form url.Values) { form.Add("repository_grants", "+3:viewer") },
			wantError: "a staged repository access selection is invalid",
		},
		{
			name:      "zero-padded repository id",
			mutate:    func(form url.Values) { form.Add("repository_grants", "03:viewer") },
			wantError: "a staged repository access selection is invalid",
		},
		{
			name:      "zero repository id",
			mutate:    func(form url.Values) { form.Add("repository_grants", "0:viewer") },
			wantError: "a staged repository access selection is invalid",
		},
		{
			name:      "admin role is not a repository role",
			mutate:    func(form url.Values) { form.Add("repository_grants", fmt.Sprintf("%d:admin", fixture.repositoryID)) },
			wantError: "a staged repository access selection is invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			form := fixture.invitationCreateForm("invitee@example.test", "Preserved Person", goodGrant)
			test.mutate(form)
			recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), form, []string{passwordRecoveryWebPublicURL})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			if !strings.Contains(body, `id="users-invite-dialog" open`) {
				t.Fatal("validation failure must reopen the invite dialog")
			}
			if !strings.Contains(body, test.wantError) {
				t.Fatalf("body missing validation error %q", test.wantError)
			}
			if !strings.Contains(body, `value="invitee@example.test"`) || !strings.Contains(body, `value="Preserved Person"`) {
				t.Fatal("validation failure must preserve the submitted identity")
			}
			if !strings.Contains(renderedControlTag(t, body, fmt.Sprintf("invite-grant-%d-viewer", fixture.repositoryID)), "checked") {
				t.Fatal("validation failure must preserve parseable staged role selections")
			}
			if strings.Contains(body, "#token=") {
				t.Fatal("validation failure rendered bearer material")
			}
			if got := fixture.countInvitations(t); got != 0 {
				t.Fatalf("validation failure created %d invitations", got)
			}
		})
	}

	t.Run("admin selection preserved", func(t *testing.T) {
		form := fixture.invitationCreateForm("invitee@example.test", "Preserved Person", goodGrant)
		form.Set("admin", "1")
		form.Add("repository_grants", "abc")
		recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), form, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", recorder.Code)
		}
		if !strings.Contains(renderedControlTag(t, recorder.Body.String(), "invite-admin"), "checked") {
			t.Fatal("validation failure must preserve the Admin selection")
		}
	})

	t.Run("existing user email", func(t *testing.T) {
		form := fixture.invitationCreateForm("admin@example.test", "Existing Person")
		recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), form, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "user email already exists") {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if got := fixture.countInvitations(t); got != 0 {
			t.Fatalf("collision created %d invitations", got)
		}
	})

	t.Run("reserved email", func(t *testing.T) {
		fixture.mustCreateServiceInvitation(t, "reserved@example.test", false)
		form := fixture.invitationCreateForm("reserved@example.test", "Reserved Person")
		recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), form, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "an active invitation already exists for this email") {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if got := fixture.countInvitations(t); got != 1 {
			t.Fatalf("invitations = %d, want only the pre-existing reservation", got)
		}
	})
}

// TestInvitationCreateResubmissionAfterValidationIssuesOneBearer follows the
// admin path a browser takes after a rejected invitation form: the validation
// rerender carries the sensitive headers, and correcting the form under the
// same session and canonical Origin must still create the invitation once.
func TestInvitationCreateResubmissionAfterValidationIssuesOneBearer(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	grant := fmt.Sprintf("%d:viewer", fixture.repositoryID)
	correctedForm := func() url.Values {
		return fixture.invitationCreateForm("resubmitted@example.test", "Resubmitting Person", grant)
	}

	rejected := correctedForm()
	rejected.Add("repository_grants", "abc")
	validation := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), rejected, []string{passwordRecoveryWebPublicURL})
	if validation.Code != http.StatusBadRequest || !strings.Contains(validation.Body.String(), `id="users-invite-dialog" open`) {
		t.Fatalf("validation rerender status=%d body=%q", validation.Code, validation.Body.String())
	}
	assertPasswordRecoveryHeaders(t, validation.Header())

	created := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), correctedForm(), []string{passwordRecoveryWebPublicURL})
	if created.Code != http.StatusOK {
		t.Fatalf("corrected resubmission status=%d body=%q", created.Code, created.Body.String())
	}
	body := created.Body.String()
	token := invitationTokenFromLink(t, issuedInvitationLink(t, body))
	if got := strings.Count(body, token); got != 1 {
		t.Fatalf("corrected resubmission displayed the bearer %d times, want 1", got)
	}
	if got := fixture.countInvitations(t); got != 1 {
		t.Fatalf("invitations = %d, want 1 after a rejected then corrected submission", got)
	}
}

func TestInvitationCancelAcrossLifecycleStatesTombstonesAndAudits(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	const driftRepositoryID = 90
	mustInsertWebRepositoryID(t, fixture.ctx, fixture.database, driftRepositoryID, "drift-repo")

	pending := fixture.mustCreateServiceInvitation(t, "pending@example.test", false, auth.InvitationRepositoryGrant{RepositoryID: fixture.repositoryID, Role: auth.RoleViewer})
	expired := fixture.mustCreateServiceInvitation(t, "expired@example.test", false)
	fixture.expireInvitation(t, expired.InvitationID)
	needsReplacement := fixture.mustCreateServiceInvitation(t, "reissue@example.test", false)
	fixture.markInvitationNeedsReplacement(t, needsReplacement.InvitationID)
	drifted := fixture.mustCreateServiceInvitation(t, "drift@example.test", false, auth.InvitationRepositoryGrant{RepositoryID: driftRepositoryID, Role: auth.RoleFreezer})
	fixture.deleteRepository(t, driftRepositoryID)

	for _, invitationID := range []string{pending.InvitationID, expired.InvitationID, needsReplacement.InvitationID, drifted.InvitationID} {
		recorder := postAccountForm(t, fixture.server, "/users/invitations/"+invitationID+"/cancel", fixture.adminCookie(), url.Values{csrfFormField: {fixture.admin.CSRFToken}})
		if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/users?notice=invitation-cancelled" {
			t.Fatalf("cancel %s: status=%d Location=%q body=%q", invitationID, recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
		}
		fixture.assertInvitationTombstone(t, invitationID, "cancelled")
	}
	if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationCancelled); got != 4 {
		t.Fatalf("invitation.cancelled audit rows = %d, want 4", got)
	}

	notice := getUsersPage(t, fixture.server, "/users?notice=invitation-cancelled", fixture.adminCookie(), false)
	if notice.Code != http.StatusOK || !strings.Contains(notice.Body.String(), "Invitation cancelled. Its email address is no longer reserved and can be invited again.") {
		t.Fatalf("cancel notice status=%d body=%q", notice.Code, notice.Body.String())
	}

	if _, err := fixture.service.CreateInvitation(fixture.ctx, auth.CreateInvitationParams{
		ActorUserID: fixture.admin.User.ID,
		Email:       "pending@example.test",
		DisplayName: "Invited Again",
	}); err != nil {
		t.Fatalf("cancelled email was not released for re-invitation: %v", err)
	}
}

func TestInvitationCancelStaleUnknownAndBrokenOutcomes(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	cancelForm := url.Values{csrfFormField: {fixture.admin.CSRFToken}}

	accepted := fixture.mustCreateServiceInvitation(t, "accepted@example.test", false)
	if _, err := fixture.service.AcceptInvitation(fixture.ctx, accepted.Token, invitedWebTestPassword); err != nil {
		t.Fatal(err)
	}
	recorder := postAccountForm(t, fixture.server, "/users/invitations/"+accepted.InvitationID+"/cancel", fixture.adminCookie(), cancelForm)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invitation cannot be cancelled") {
		t.Fatalf("accepted cancel status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	pending := fixture.mustCreateServiceInvitation(t, "twice@example.test", false)
	first := postAccountForm(t, fixture.server, "/users/invitations/"+pending.InvitationID+"/cancel", fixture.adminCookie(), cancelForm)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first cancel status=%d", first.Code)
	}
	second := postAccountForm(t, fixture.server, "/users/invitations/"+pending.InvitationID+"/cancel", fixture.adminCookie(), cancelForm)
	if second.Code != http.StatusBadRequest || !strings.Contains(second.Body.String(), "invitation cannot be cancelled") {
		t.Fatalf("double cancel status=%d body=%q", second.Code, second.Body.String())
	}

	unknown := postAccountForm(t, fixture.server, "/users/invitations/inv_AAAAAAAAAAAAAAAAAAAAAA/cancel", fixture.adminCookie(), cancelForm)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "invitation was not found") {
		t.Fatalf("unknown cancel status=%d body=%q", unknown.Code, unknown.Body.String())
	}
	malformed := postAccountForm(t, fixture.server, "/users/invitations/not-an-id/cancel", fixture.adminCookie(), cancelForm)
	if malformed.Code != http.StatusNotFound {
		t.Fatalf("malformed cancel status=%d", malformed.Code)
	}

	guarded := fixture.mustCreateServiceInvitation(t, "guarded@example.test", false)
	wrappedID := postAccountForm(t, fixture.server, "/users/invitations/%20"+guarded.InvitationID+"%20/cancel", fixture.adminCookie(), cancelForm)
	if wrappedID.Code != http.StatusNotFound {
		t.Fatalf("whitespace-wrapped invitation ID status=%d, want 404", wrappedID.Code)
	}
	mustCreateWebUser(t, fixture.ctx, fixture.service, "cancel-viewer@example.test", false)
	viewerSession, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: "cancel-viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	nonAdmin := postAccountForm(t, fixture.server, "/users/invitations/"+guarded.InvitationID+"/cancel",
		&http.Cookie{Name: sessionCookieName, Value: viewerSession.ID},
		url.Values{csrfFormField: {viewerSession.CSRFToken}})
	if nonAdmin.Code != http.StatusForbidden {
		t.Fatalf("non-admin cancel status=%d", nonAdmin.Code)
	}
	noCSRF := postAccountForm(t, fixture.server, "/users/invitations/"+guarded.InvitationID+"/cancel", fixture.adminCookie(), url.Values{})
	if noCSRF.Code != http.StatusForbidden || !strings.Contains(noCSRF.Body.String(), "forbidden") {
		t.Fatalf("missing-CSRF cancel status=%d body=%q", noCSRF.Code, noCSRF.Body.String())
	}
	if got := fixture.invitationStatus(t, guarded.InvitationID); got != "pending" {
		t.Fatalf("guarded invitation status = %q after rejected cancels", got)
	}

	broken := newInvitationWebFixture(t)
	target := broken.mustCreateServiceInvitation(t, "broken@example.test", false)
	if _, err := broken.database.ExecContext(broken.ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	unconfirmed := postAccountForm(t, broken.server, "/users/invitations/"+target.InvitationID+"/cancel", broken.adminCookie(), url.Values{csrfFormField: {broken.admin.CSRFToken}})
	if unconfirmed.Code != http.StatusInternalServerError ||
		!strings.Contains(unconfirmed.Body.String(), "Cancellation result unconfirmed") ||
		!strings.Contains(unconfirmed.Body.String(), "Inspect Active invitations before retrying") {
		t.Fatalf("broken cancel status=%d body=%q", unconfirmed.Code, unconfirmed.Body.String())
	}
}

func TestInvitationReplaceIssuesOneTimeLinkOverUsersShellAndFencesReplay(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	const goneRepositoryID = 94
	mustInsertWebRepositoryID(t, fixture.ctx, fixture.database, goneRepositoryID, "deleted-before-replacement")
	original := fixture.mustCreateServiceInvitation(t, "replace-me@example.test", true,
		auth.InvitationRepositoryGrant{RepositoryID: fixture.repositoryID, Role: auth.RoleFreezer},
		auth.InvitationRepositoryGrant{RepositoryID: goneRepositoryID, Role: auth.RoleViewer},
	)
	fixture.deleteRepository(t, goneRepositoryID)

	replaceForm := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	replacePath := "/users/invitations/" + original.InvitationID + "/replace"
	recorder := postAccountForm(t, fixture.server, replacePath, fixture.adminCookie(), replaceForm)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertPasswordRecoveryHeaders(t, recorder.Header())
	body := recorder.Body.String()
	assertSingleOpenInvitationResult(t, body)
	for _, want := range []string{
		"Invitation link replaced",
		"replace-me@example.test",
		"The previous link for this invitation stopped working. Only the link above can be accepted.",
		"No email was sent.",
		"Valid for up to seven days, until",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("replacement response missing %q", want)
		}
	}
	link := issuedInvitationLink(t, body)
	token := invitationTokenFromLink(t, link)
	if strings.Count(body, token) != 1 {
		t.Fatalf("bearer appeared %d times, want exactly once", strings.Count(body, token))
	}
	if strings.Contains(body, original.Token) {
		t.Fatal("the retired bearer must never be echoed")
	}
	if cookies := strings.Join(recorder.Header().Values("Set-Cookie"), " "); strings.Contains(cookies, token) {
		t.Fatal("bearer leaked into a cookie")
	}

	fixture.assertInvitationTombstone(t, original.InvitationID, "cancelled")
	replacementID := fixture.mustPendingInvitationID(t)
	if replacementID == original.InvitationID {
		t.Fatal("replacement must mint a new canonical invitation ID")
	}
	wantDigest := sha256.Sum256([]byte(token))
	if !bytes.Equal(fixture.invitationTokenDigest(t, replacementID), wantDigest[:]) {
		t.Fatal("stored digest does not match the displayed bearer")
	}
	if !fixture.invitationIsAdmin(t, replacementID) {
		t.Fatal("replacement dropped the invitation's Admin flag")
	}
	// The grant for the deleted repository cannot survive; the other one must.
	if got := fixture.countStagedGrants(t, replacementID); got != 1 {
		t.Fatalf("replacement copied %d staged grants, want the 1 surviving grant", got)
	}
	if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationReplaced); got != 1 {
		t.Fatalf("invitation.replaced audit rows = %d, want 1", got)
	}
	assertInvitationAuditDoesNotContain(t, fixture, token, original.Token, "replace-me@example.test", link)

	// Refreshing or replaying the POST targets the retired ID, which no longer
	// accepts replacement, so the link just handed out cannot be rotated.
	replay := postAccountForm(t, fixture.server, replacePath, fixture.adminCookie(), replaceForm)
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "invitation link cannot be replaced") {
		t.Fatalf("replayed replacement status=%d body=%q", replay.Code, replay.Body.String())
	}
	for _, forbidden := range []string{"#token=", "data-invitation-result", token} {
		if strings.Contains(replay.Body.String(), forbidden) {
			t.Fatalf("replayed replacement revealed %q", forbidden)
		}
	}
	if got := fixture.mustPendingInvitationID(t); got != replacementID {
		t.Fatal("replaying the retired POST rotated the live invitation")
	}
	if !bytes.Equal(fixture.invitationTokenDigest(t, replacementID), wantDigest[:]) {
		t.Fatal("replaying the retired POST rotated the live bearer")
	}

	later := getUsersPage(t, fixture.server, "/users", fixture.adminCookie(), false)
	if later.Code != http.StatusOK {
		t.Fatalf("users page status = %d", later.Code)
	}
	if strings.Contains(later.Body.String(), token) || strings.Contains(later.Body.String(), "#token=") {
		t.Fatal("bearer must never be reproduced after the one-time response")
	}

	if _, err := fixture.service.AcceptInvitation(fixture.ctx, original.Token, invitedWebTestPassword); err == nil {
		t.Fatal("the retired bearer is still accepted")
	}
	accepted, err := fixture.service.AcceptInvitation(fixture.ctx, token, invitedWebTestPassword)
	if err != nil {
		t.Fatalf("replacement bearer rejected: %v", err)
	}
	if !accepted.IsAdmin || accepted.Email != "replace-me@example.test" {
		t.Fatalf("replacement lost the staged identity or authority: %+v", accepted)
	}
}

func TestInvitationReplaceReportsCommittedLinkWhenBufferedRenderFails(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	original := fixture.mustCreateServiceInvitation(t, "undisplayed-replacement@example.test", false)

	brokenTemplates, err := template.New("").Funcs(templateFuncs).ParseFS(templateFS,
		"templates/layouts/*.html",
		"templates/pages/*.html",
		"templates/components/*.html",
		"templates/components/primitives/*.html",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokenTemplates.Parse(`{{ define "layouts/users" }}{{ .MissingField }}{{ end }}`); err != nil {
		t.Fatal(err)
	}
	originalTemplates := pageTemplates
	pageTemplates = brokenTemplates
	t.Cleanup(func() { pageTemplates = originalTemplates })

	recorder := postAccountForm(
		t,
		fixture.server,
		"/users/invitations/"+original.InvitationID+"/replace",
		fixture.adminCookie(),
		url.Values{csrfFormField: {fixture.admin.CSRFToken}},
	)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"Invitation link replaced but not displayed",
		"The invitation is active",
		"cannot show it again",
		"replace the link for that invitation",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("undisplayed replacement response missing %q", want)
		}
	}
	for _, forbidden := range []string{"#token=", "data-invitation-result", "undisplayed-replacement@example.test"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("undisplayed replacement response revealed %q", forbidden)
		}
	}
	fixture.assertInvitationTombstone(t, original.InvitationID, "cancelled")
	if replacementID := fixture.mustPendingInvitationID(t); replacementID == original.InvitationID {
		t.Fatal("render failure rolled back or reused the retired invitation")
	}
	if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationReplaced); got != 1 {
		t.Fatalf("invitation.replaced audit rows = %d, want 1", got)
	}
}

func TestInvitationResultStaticScriptProtectsOneTimeDeliveryLifecycle(t *testing.T) {
	scriptBytes, err := fs.ReadFile(webassets.StaticFS(), "js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)

	for _, want := range []string{
		"upgradeOpenDialogs();\ninitInvitationResult();",
		`history.replaceState(null, "", "/users");`,
		"navigator.clipboard?.writeText",
		"manualHint.hidden = false;",
		"link.focus();",
		"link.select();",
		`window.addEventListener("pagehide"`,
		`link.value = "";`,
		`dialog.addEventListener("close", () => {
    if (dialog.open) return;
    location.replace("/users");
  });`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("invitation result script missing %q", want)
		}
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", "document.cookie", "console."} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("invitation result script must not use %q", forbidden)
		}
	}
}

func TestInvitationReplaceRejectsUnsupportedRequestShapes(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	guarded := fixture.mustCreateServiceInvitation(t, "guarded-replace@example.test", false)
	replacePath := "/users/invitations/" + guarded.InvitationID + "/replace"
	csrf := url.Values{csrfFormField: {fixture.admin.CSRFToken}}

	extraField := url.Values{csrfFormField: {fixture.admin.CSRFToken}, "is_admin": {"1"}}
	if got := postAccountForm(t, fixture.server, replacePath, fixture.adminCookie(), extraField); got.Code != http.StatusBadRequest {
		t.Fatalf("client-submitted authority status=%d, want 400", got.Code)
	}
	if got := postAccountForm(t, fixture.server, replacePath+"?notice=x", fixture.adminCookie(), csrf); got.Code != http.StatusBadRequest {
		t.Fatalf("query-carrying replacement status=%d, want 400", got.Code)
	}
	if got := postAccountForm(t, fixture.server, replacePath, fixture.adminCookie(), url.Values{}); got.Code != http.StatusForbidden {
		t.Fatalf("missing-CSRF replacement status=%d, want 403", got.Code)
	}
	if got := postAccountForm(t, fixture.server, "/users/invitations/not-an-id/replace", fixture.adminCookie(), csrf); got.Code != http.StatusNotFound {
		t.Fatalf("malformed invitation ID status=%d, want 404", got.Code)
	}
	if got := postAccountForm(t, fixture.server, "/users/invitations/inv_AAAAAAAAAAAAAAAAAAAAAA/replace", fixture.adminCookie(), csrf); got.Code != http.StatusBadRequest {
		t.Fatalf("unknown invitation status=%d, want 400", got.Code)
	}

	mustCreateWebUser(t, fixture.ctx, fixture.service, "replace-viewer@example.test", false)
	viewerSession, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: "replace-viewer@example.test", Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	nonAdmin := postAccountForm(t, fixture.server, replacePath,
		&http.Cookie{Name: sessionCookieName, Value: viewerSession.ID},
		url.Values{csrfFormField: {viewerSession.CSRFToken}})
	if nonAdmin.Code != http.StatusForbidden {
		t.Fatalf("non-admin replacement status=%d, want 403", nonAdmin.Code)
	}

	if got := fixture.invitationStatus(t, guarded.InvitationID); got != "pending" {
		t.Fatalf("guarded invitation status = %q after rejected replacements", got)
	}
	if got := fixture.invitationTokenDigest(t, guarded.InvitationID); !bytes.Equal(got, sha256Sum(guarded.Token)) {
		t.Fatal("a rejected replacement rotated the live bearer")
	}
	if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationReplaced); got != 0 {
		t.Fatalf("rejected replacements wrote %d audit rows", got)
	}
}

func TestInvitationConfirmationsRenderServerSideWithoutJavaScript(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	invitation := fixture.mustCreateServiceInvitation(t, "confirm@example.test", false)

	for _, action := range []string{"replace", "cancel"} {
		recorder := getUsersPage(t, fixture.server, "/users?confirm="+action+"&invitation="+invitation.InvitationID, fixture.adminCookie(), false)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s confirmation status=%d", action, recorder.Code)
		}
		body := recorder.Body.String()
		open := fmt.Sprintf(`id="invitation-%s-%s" open`, action, invitation.InvitationID)
		if !strings.Contains(body, open) {
			t.Fatalf("%s confirmation dialog was not rendered open", action)
		}
		other := "replace"
		if action == "replace" {
			other = "cancel"
		}
		if strings.Contains(body, fmt.Sprintf(`id="invitation-%s-%s" open`, other, invitation.InvitationID)) {
			t.Fatalf("%s confirmation also opened the %s dialog", action, other)
		}
	}

	replaceBody := getUsersPage(t, fixture.server, "/users?confirm=replace&invitation="+invitation.InvitationID, fixture.adminCookie(), false).Body.String()
	for _, want := range []string{
		"The current link stops working immediately and a new link is shown once.",
		"The Admin setting and the staged repository access that still exists are preserved, and a fresh seven-day expiry starts.",
		"Staged access for repositories that were deleted cannot be restored.",
	} {
		if !strings.Contains(replaceBody, want) {
			t.Fatalf("replace confirmation missing %q", want)
		}
	}
	cancelBody := getUsersPage(t, fixture.server, "/users?confirm=cancel&invitation="+invitation.InvitationID, fixture.adminCookie(), false).Body.String()
	for _, want := range []string{
		"The invitation link becomes unusable and this person can no longer accept it.",
		"The email address is released, so it can be invited again.",
	} {
		if !strings.Contains(cancelBody, want) {
			t.Fatalf("cancel confirmation missing %q", want)
		}
	}

	// Contradictory, partial, or malformed confirmation state is rejected
	// rather than narrowed to whichever value happened to parse.
	for _, query := range []string{
		"?confirm=replace",
		"?invitation=" + invitation.InvitationID,
		"?confirm=replace&confirm=cancel&invitation=" + invitation.InvitationID,
		"?confirm=replace&invitation=" + invitation.InvitationID + "&invitation=inv_AAAAAAAAAAAAAAAAAAAAAA",
		"?confirm=delete&invitation=" + invitation.InvitationID,
		"?confirm=replace&invitation=not-an-id",
	} {
		recorder := getUsersPage(t, fixture.server, "/users"+query, fixture.adminCookie(), false)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("confirmation query %q status=%d, want 400", query, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), " open") {
			t.Fatalf("confirmation query %q opened a dialog", query)
		}
	}
}

func TestInvitationAcceptGatesLeaveBearerUsable(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	credential := fixture.mustCreateServiceInvitation(t, "gate-invitee@example.test", false)
	validCSRF := func() string { return mustSignedCSRFToken(t, fixture.server, invitationCSRFPurpose) }

	tests := []struct {
		name       string
		path       string
		origins    []string
		form       func() url.Values
		wantStatus int
		wantBody   string
	}{
		{
			name: "missing origin", path: "/invitations/accept", origins: nil,
			form:       func() url.Values { return invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword) },
			wantStatus: http.StatusForbidden, wantBody: "Invitation request not verified",
		},
		{
			name: "wrong origin", path: "/invitations/accept", origins: []string{"https://evil.example.test"},
			form:       func() url.Values { return invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword) },
			wantStatus: http.StatusForbidden, wantBody: "Invitation request not verified",
		},
		{
			name: "duplicated origin", path: "/invitations/accept", origins: []string{passwordRecoveryWebPublicURL, passwordRecoveryWebPublicURL},
			form:       func() url.Values { return invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword) },
			wantStatus: http.StatusForbidden, wantBody: "Invitation request not verified",
		},
		{
			name: "query string", path: "/invitations/accept?x=1", origins: []string{passwordRecoveryWebPublicURL},
			form:       func() url.Values { return invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword) },
			wantStatus: http.StatusBadRequest, wantBody: "could not be processed",
		},
		{
			name: "forced empty query", path: "/invitations/accept?", origins: []string{passwordRecoveryWebPublicURL},
			form:       func() url.Values { return invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword) },
			wantStatus: http.StatusBadRequest, wantBody: "could not be processed",
		},
		{
			name: "extra field", path: "/invitations/accept", origins: []string{passwordRecoveryWebPublicURL},
			form: func() url.Values {
				form := invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword)
				form.Set("extra", "1")
				return form
			},
			wantStatus: http.StatusBadRequest, wantBody: "could not be processed",
		},
		{
			name: "duplicate password field", path: "/invitations/accept", origins: []string{passwordRecoveryWebPublicURL},
			form: func() url.Values {
				form := invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword)
				form.Add("new_password", "second password value")
				return form
			},
			wantStatus: http.StatusBadRequest, wantBody: "could not be processed",
		},
		{
			name: "recovery-purpose CSRF", path: "/invitations/accept", origins: []string{passwordRecoveryWebPublicURL},
			form: func() url.Values {
				return invitationAcceptForm(mustSignedCSRFToken(t, fixture.server, passwordRecoveryCSRFPurpose), credential.Token, invitedWebTestPassword)
			},
			wantStatus: http.StatusForbidden, wantBody: "Invitation request not verified",
		},
		{
			name: "missing CSRF", path: "/invitations/accept", origins: []string{passwordRecoveryWebPublicURL},
			form: func() url.Values {
				form := invitationAcceptForm("", credential.Token, invitedWebTestPassword)
				form.Del(csrfFormField)
				return form
			},
			wantStatus: http.StatusForbidden, wantBody: "Invitation request not verified",
		},
		{
			name: "oversized body", path: "/invitations/accept", origins: []string{passwordRecoveryWebPublicURL},
			form: func() url.Values {
				return invitationAcceptForm(validCSRF(), credential.Token, strings.Repeat("p", int(invitationAcceptMaxBodyBytes)+1024))
			},
			wantStatus: http.StatusRequestEntityTooLarge, wantBody: "This request is too large.",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := postPasswordRecoveryForm(t, fixture.server, test.path, nil, test.form(), test.origins)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), test.wantBody) {
				t.Fatalf("body=%q, want substring %q", recorder.Body.String(), test.wantBody)
			}
			assertNoSetCookie(t, recorder)
			if strings.Contains(recorder.Body.String(), credential.Token) {
				t.Fatal("rejected request echoed the bearer")
			}
			if got := fixture.invitationStatus(t, credential.InvitationID); got != "pending" {
				t.Fatalf("invitation status = %q after rejected request", got)
			}
		})
	}

	final := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(validCSRF(), credential.Token, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if final.Code != http.StatusOK || !strings.Contains(final.Body.String(), "Account created") {
		t.Fatalf("bearer was unusable after rejected requests: status=%d body=%q", final.Code, final.Body.String())
	}
	assertNoSetCookie(t, final)
}

func TestInvitationAcceptWeakPasswordRetryKeepsBearerHiddenOnly(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	credential := fixture.mustCreateServiceInvitation(t, "retry-invitee@example.test", false)
	const weakPassword = "canary7pw"

	csrfToken := getInvitationAcceptCSRF(t, fixture.server)
	recorder := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(csrfToken, credential.Token, weakPassword),
		[]string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertNoSetCookie(t, recorder)
	body := recorder.Body.String()
	if !strings.Contains(body, "Choose a password") || !strings.Contains(body, "password must be at least 12 characters") {
		t.Fatalf("retry page missing policy guidance, body=%q", body)
	}
	if strings.Count(body, credential.Token) != 1 {
		t.Fatalf("bearer appeared %d times on retry, want exactly once", strings.Count(body, credential.Token))
	}
	if !strings.Contains(body, `type="hidden" name="invitation_token" value="`+credential.Token) {
		t.Fatal("bearer must be retained only in the escaped hidden token field")
	}
	if strings.Contains(body, weakPassword) {
		t.Fatal("retry page echoed the rejected password")
	}
	if strings.Contains(body, "invitation-accept.js") {
		t.Fatal("retry page must not reload the fragment bootstrap script")
	}
	if strings.Contains(body, `gap-4" hidden>`) {
		t.Fatal("retry form must be visible without the bootstrap script")
	}

	freshCSRF := csrfTokenFromBody(t, body)
	if !fixture.server.validSignedCSRFToken(freshCSRF, invitationCSRFPurpose) {
		t.Fatal("retry page must carry a fresh invitation-purpose CSRF token")
	}
	retry := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(freshCSRF, credential.Token, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if retry.Code != http.StatusOK || !strings.Contains(retry.Body.String(), "Account created") {
		t.Fatalf("retry status=%d body=%q", retry.Code, retry.Body.String())
	}
	if _, err := fixture.service.Login(fixture.ctx, auth.LoginParams{Email: "retry-invitee@example.test", Password: invitedWebTestPassword}); err != nil {
		t.Fatalf("invited account cannot sign in after retry: %v", err)
	}
}

func TestInvitationAcceptInvalidStatesAreIndistinguishable(t *testing.T) {
	fixture := newInvitationWebFixture(t)

	expired := fixture.mustCreateServiceInvitation(t, "invalid-expired@example.test", false)
	fixture.expireInvitation(t, expired.InvitationID)
	cancelled := fixture.mustCreateServiceInvitation(t, "invalid-cancelled@example.test", false)
	if err := fixture.service.CancelInvitation(fixture.ctx, auth.CancelInvitationParams{ActorUserID: fixture.admin.User.ID, InvitationID: cancelled.InvitationID}); err != nil {
		t.Fatal(err)
	}
	needsReplacement := fixture.mustCreateServiceInvitation(t, "invalid-reissue@example.test", false)
	fixture.markInvitationNeedsReplacement(t, needsReplacement.InvitationID)
	accepted := fixture.mustCreateServiceInvitation(t, "invalid-accepted@example.test", false)
	if _, err := fixture.service.AcceptInvitation(fixture.ctx, accepted.Token, invitedWebTestPassword); err != nil {
		t.Fatal(err)
	}
	const driftRepositoryID = 91
	mustInsertWebRepositoryID(t, fixture.ctx, fixture.database, driftRepositoryID, "drift-a")
	drifted := fixture.mustCreateServiceInvitation(t, "invalid-drift@example.test", false, auth.InvitationRepositoryGrant{RepositoryID: driftRepositoryID, Role: auth.RoleFreezer})
	fixture.deleteRepository(t, driftRepositoryID)

	tests := []struct {
		name     string
		token    string
		password string
	}{
		{name: "malformed token", token: "not-a-token", password: invitedWebTestPassword},
		{name: "unknown token", token: strings.Repeat("A", 43), password: invitedWebTestPassword},
		{name: "expired", token: expired.Token, password: invitedWebTestPassword},
		{name: "expired beats weak password", token: expired.Token, password: "short"},
		{name: "cancelled", token: cancelled.Token, password: invitedWebTestPassword},
		{name: "needs replacement", token: needsReplacement.Token, password: invitedWebTestPassword},
		{name: "already accepted", token: accepted.Token, password: invitedWebTestPassword},
		{name: "drifted staged access", token: drifted.Token, password: invitedWebTestPassword},
	}
	var reference string
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
				invitationAcceptForm(mustSignedCSRFToken(t, fixture.server, invitationCSRFPurpose), test.token, test.password),
				[]string{passwordRecoveryWebPublicURL})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
			}
			assertNoSetCookie(t, recorder)
			body := recorder.Body.String()
			if !strings.Contains(body, "Invitation unavailable") || !strings.Contains(body, invalidInvitationMessage) {
				t.Fatalf("body missing generic unavailable copy: %q", body)
			}
			if len(test.token) == 43 && strings.Contains(body, test.token) {
				t.Fatal("invalid state echoed the bearer")
			}
			if reference == "" {
				reference = body
			} else if body != reference {
				t.Fatal("invalid invitation states must render byte-identical responses")
			}
		})
	}
}

func TestInvitationEndToEndSmokeCreatesAccountAuthorityAndAudit(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	link := fixture.mustCreateInvitationOverHTTP(t, fixture.invitationCreateForm(
		"invitee@example.test",
		"Invited Person",
		fmt.Sprintf("%d:viewer", fixture.repositoryID),
		fmt.Sprintf("%d:thaw_approver", fixture.repositoryID),
	))
	token := invitationTokenFromLink(t, link)
	var invitationID string
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT id FROM invitations`).Scan(&invitationID); err != nil {
		t.Fatal(err)
	}

	csrfToken := getInvitationAcceptCSRF(t, fixture.server)
	accept := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(csrfToken, token, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if accept.Code != http.StatusOK {
		t.Fatalf("accept status=%d body=%q", accept.Code, accept.Body.String())
	}
	assertNoSetCookie(t, accept)
	body := accept.Body.String()
	for _, want := range []string{
		"Account created",
		"Your account is ready. Sign in with your invited email address and the password you just chose.",
		`href="/login"`,
		"Sign in",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("acceptance page missing %q", want)
		}
	}
	if strings.Contains(body, token) {
		t.Fatal("acceptance page echoed the bearer")
	}

	users, err := fixture.service.ListUsers(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var invitee auth.User
	for _, user := range users {
		if user.Email == "invitee@example.test" {
			invitee = user
		}
	}
	if invitee.ID == 0 {
		t.Fatal("accepted invitation did not create the invited account")
	}
	if invitee.IsAdmin {
		t.Fatal("non-admin invitation produced an Admin account")
	}
	var mustChange int
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT must_change_password FROM local_credentials WHERE user_id = ?`, invitee.ID).Scan(&mustChange); err != nil {
		t.Fatal(err)
	}
	if mustChange != 0 {
		t.Fatal("invitee chose their own password and must not be forced to change it")
	}

	grantRows, err := fixture.database.QueryContext(fixture.ctx, `SELECT repository_id, role, granted_by_user_id FROM repository_grants WHERE user_id = ?`, invitee.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer grantRows.Close()
	granted := map[string]int64{}
	for grantRows.Next() {
		var repositoryID, grantedBy int64
		var role string
		if err := grantRows.Scan(&repositoryID, &role, &grantedBy); err != nil {
			t.Fatal(err)
		}
		if repositoryID != fixture.repositoryID {
			t.Fatalf("grant materialized on repository %d, want %d", repositoryID, fixture.repositoryID)
		}
		granted[role] = grantedBy
	}
	if err := grantRows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(granted) != 2 || granted["viewer"] != fixture.admin.User.ID || granted["thaw_approver"] != fixture.admin.User.ID {
		t.Fatalf("materialized grants = %v, want viewer and thaw_approver from the authorizing Admin", granted)
	}

	fixture.assertInvitationTombstone(t, invitationID, "accepted")
	if got := countUserSessionsForWeb(t, fixture.ctx, fixture.database, invitee.ID); got != 0 {
		t.Fatalf("acceptance created %d sessions, want none", got)
	}
	if got := countAuditAction(t, fixture.ctx, fixture.database, audit.ActionInvitationAccepted); got != 1 {
		t.Fatalf("invitation.accepted audit rows = %d, want 1", got)
	}
	assertInvitationAuditDoesNotContain(t, fixture, token, invitedWebTestPassword)
	loginPage := httptest.NewRecorder()
	fixture.server.Routes().ServeHTTP(loginPage, httptest.NewRequest(http.MethodGet, "/login", nil))
	if loginPage.Code != http.StatusOK {
		t.Fatalf("login page status=%d body=%q", loginPage.Code, loginPage.Body.String())
	}
	loginCookie := namedCookieFromRecorder(t, loginPage, loginCookieName)
	loginCSRF := csrfTokenFromBody(t, loginPage.Body.String())
	loginForm := url.Values{
		"email":       {"invitee@example.test"},
		"password":    {invitedWebTestPassword},
		csrfFormField: {loginCSRF},
	}
	login := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRequest.Header.Set("Origin", "http://example.com")
	loginRequest.AddCookie(loginCookie)
	fixture.server.Routes().ServeHTTP(login, loginRequest)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/" {
		t.Fatalf("invited account HTTP login status=%d location=%q body=%q", login.Code, login.Header().Get("Location"), login.Body.String())
	}
	invitedSessionCookie := namedCookieFromRecorder(t, login, sessionCookieName)
	if _, found, err := fixture.service.SessionByID(fixture.ctx, invitedSessionCookie.Value); err != nil || !found {
		t.Fatalf("HTTP login did not create a valid invited-user session, found=%v err=%v", found, err)
	}

	adminForm := fixture.invitationCreateForm("second-admin@example.test", "Second Admin")
	adminForm.Set("admin", "1")
	adminLink := fixture.mustCreateInvitationOverHTTP(t, adminForm)
	adminToken := invitationTokenFromLink(t, adminLink)
	adminAccept := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(getInvitationAcceptCSRF(t, fixture.server), adminToken, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if adminAccept.Code != http.StatusOK {
		t.Fatalf("admin accept status=%d body=%q", adminAccept.Code, adminAccept.Body.String())
	}
	users, err = fixture.service.ListUsers(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var secondAdmin auth.User
	for _, user := range users {
		if user.Email == "second-admin@example.test" {
			secondAdmin = user
		}
	}
	if secondAdmin.ID == 0 || !secondAdmin.IsAdmin {
		t.Fatal("admin invitation did not create an Admin account")
	}
	var secondAdminGrants int
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ?`, secondAdmin.ID).Scan(&secondAdminGrants); err != nil {
		t.Fatal(err)
	}
	if secondAdminGrants != 0 {
		t.Fatalf("zero-grant admin invitation materialized %d repository grants", secondAdminGrants)
	}
}

func TestInvitationAcceptUnknownOutcomeIsOperationalWithoutBearer(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	credential := fixture.mustCreateServiceInvitation(t, "unknown-outcome@example.test", false)
	if _, err := fixture.database.ExecContext(fixture.ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	recorder := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil,
		invitationAcceptForm(mustSignedCSRFToken(t, fixture.server, invitationCSRFPurpose), credential.Token, invitedWebTestPassword),
		[]string{passwordRecoveryWebPublicURL})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body=%q", recorder.Code, recorder.Body.String())
	}
	assertNoSetCookie(t, recorder)
	body := recorder.Body.String()
	for _, want := range []string{
		"Acceptance result unconfirmed",
		"could not confirm whether your account was created",
		"Try signing in with your invited email address and the password you chose",
		"If sign-in fails, ask an Admin for a new invitation link",
		`href="/login"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unknown outcome missing %q, body=%q", want, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "resubmit") {
		t.Fatal("unknown outcome must not advise bearer resubmission")
	}
	if strings.Contains(body, credential.Token) || strings.Contains(body, invitedWebTestPassword) {
		t.Fatal("unknown outcome echoed secret material")
	}
}

func TestUsersPageShowsActiveInvitationsAndInviteDialogs(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	const driftRepositoryID = 92
	mustInsertWebRepositoryID(t, fixture.ctx, fixture.database, driftRepositoryID, "drift-source")
	const secondRepositoryID = 93
	mustInsertWebRepositoryID(t, fixture.ctx, fixture.database, secondRepositoryID, "second-repo")

	pending := fixture.mustCreateServiceInvitation(t, "noor.glacia@example.test", false,
		auth.InvitationRepositoryGrant{RepositoryID: fixture.repositoryID, Role: auth.RoleViewer},
		auth.InvitationRepositoryGrant{RepositoryID: secondRepositoryID, Role: auth.RoleFreezer},
	)
	expired := fixture.mustCreateServiceInvitation(t, "ivo.rime@example.test", true)
	fixture.expireInvitation(t, expired.InvitationID)
	needsReplacement := fixture.mustCreateServiceInvitation(t, "sana.firn@example.test", false,
		auth.InvitationRepositoryGrant{RepositoryID: fixture.repositoryID, Role: auth.RoleThawApprover})
	fixture.markInvitationNeedsReplacement(t, needsReplacement.InvitationID)
	drifted := fixture.mustCreateServiceInvitation(t, "drift@example.test", false,
		auth.InvitationRepositoryGrant{RepositoryID: driftRepositoryID, Role: auth.RoleFreezer})
	fixture.deleteRepository(t, driftRepositoryID)

	recorder := getUsersPage(t, fixture.server, "/users", fixture.adminCookie(), false)
	if recorder.Code != http.StatusOK {
		t.Fatalf("users page status=%d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		`aria-label="Active invitations"`,
		"4 invitations",
		"noor.glacia@example.test",
		"Pending",
		"Expired",
		"Needs replacement",
		"The link no longer works. Replace it to issue a new link with a fresh seven-day expiry.",
		"The link was invalidated because the authorizing Admin lost Admin access. Replace it to issue a new link authorized by you.",
		"Staged repository access changed after this invitation was created. Replace the link to keep the access that still exists; access for deleted repositories cannot be restored.",
		"Expires ",
		"2 repositories",
		"1 repository",
		"No repository access",
		"Viewer",
		"Freezer",
		"Thaw approver",
		"Cancel invitation",
		"Replace link",
		"Invite person",
		"Add local user",
		"Temporary fallback workflow.",
		"Create zero-access user",
		"Creates a one-time invitation link, valid for up to seven days.",
		"Does not imply Freeze or Thaw actions.",
		"Staged now and granted when the invitation is accepted.",
		fmt.Sprintf(`value="%d:viewer"`, fixture.repositoryID),
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("users page missing %q", want)
		}
	}
	// Both entry-point dialogs share the result dialog's width and name their
	// own explanatory paragraph, so a screen reader hears why Add local user is
	// the fallback and Invite person is the default.
	for _, dialogID := range []string{"users-create-dialog", "users-invite-dialog"} {
		tag := renderedControlTag(t, body, dialogID)
		if !strings.Contains(tag, usersDialogWidth) {
			t.Fatalf("%s width must match the other /users dialogs: %s", dialogID, tag)
		}
		if !strings.Contains(tag, fmt.Sprintf(`aria-labelledby=%q`, dialogID+"-title")) ||
			!strings.Contains(tag, fmt.Sprintf(`aria-describedby=%q`, dialogID+"-body")) {
			t.Fatalf("%s must name its own title and description: %s", dialogID, tag)
		}
		for _, suffix := range []string{"-title", "-body"} {
			id := dialogID + suffix
			if got := strings.Count(body, fmt.Sprintf(`id=%q`, id)); got != 1 {
				t.Fatalf("%s target %s rendered %d times, want exactly once", dialogID, id, got)
			}
		}
	}
	for _, invitationID := range []string{pending.InvitationID, expired.InvitationID, needsReplacement.InvitationID, drifted.InvitationID} {
		for _, action := range []string{"cancel", "replace"} {
			// The trigger is a real link to the server-rendered confirmation
			// state, duplicated across the desktop row and the mobile card.
			href := fmt.Sprintf(
				`href="/users?confirm=%s&amp;invitation=%s#invitation-%s-%s"`,
				action,
				invitationID,
				action,
				invitationID,
			)
			if got := strings.Count(body, href); got != 2 {
				t.Fatalf("%s trigger for %s rendered %d times, want desktop and mobile", action, invitationID, got)
			}
			// The dialog it controls is rendered once, outside both loops, so
			// the duplicated triggers cannot produce duplicate ids.
			dialogID := fmt.Sprintf(`id="invitation-%s-%s"`, action, invitationID)
			if got := strings.Count(body, dialogID); got != 1 {
				t.Fatalf("%s dialog for %s rendered %d times, want exactly one", action, invitationID, got)
			}
			// The POST lives only on the confirm button inside that dialog.
			post := fmt.Sprintf(`action="/users/invitations/%s/%s"`, invitationID, action)
			if got := strings.Count(body, post); got != 1 {
				t.Fatalf("%s form for %s rendered %d times, want exactly one", action, invitationID, got)
			}
		}
		if strings.Contains(body, "open") && strings.Contains(body, `id="invitation-cancel-`+invitationID+`" open`) {
			t.Fatalf("confirmation dialog for %s must stay closed without a confirmation request", invitationID)
		}
	}
	if strings.Contains(body, "Resend") {
		t.Fatal("replacement must never be labelled Resend")
	}
	if strings.Contains(body, "#token=") {
		t.Fatal("users page rendered bearer material")
	}

	filtered := getUsersPage(t, fixture.server, "/users?q=zzz-no-match", fixture.adminCookie(), false)
	if filtered.Code != http.StatusOK || !strings.Contains(filtered.Body.String(), "4 invitations") {
		t.Fatal("active invitations must stay visible independent of people filters")
	}

	emptyCtx := context.Background()
	emptyDatabase := newWebTestDB(t, emptyCtx)
	emptyService := auth.NewService(emptyDatabase)
	emptyAdmin := mustSetupWebAdmin(t, emptyCtx, emptyService)
	emptyServer := NewServer(Config{AppName: "Thawguard", PublicURL: passwordRecoveryWebPublicURL, AuthService: emptyService})
	empty := getUsersPage(t, emptyServer, "/users", &http.Cookie{Name: sessionCookieName, Value: emptyAdmin.ID}, false)
	if empty.Code != http.StatusOK {
		t.Fatalf("empty users page status=%d", empty.Code)
	}
	for _, want := range []string{
		"No active invitations",
		"Each invitation link is displayed once when it is created or replaced, and handed to the invitee over a channel you trust.",
		"Invitation links are displayed once. If a link is lost or stops working, replace it: the person, Admin setting, and staged access that still exists are kept, and a new link is shown once.",
		"No repositories are configured yet, so this invitation grants no repository access. Access can be granted after the person joins.",
	} {
		if !strings.Contains(empty.Body.String(), want) {
			t.Fatalf("empty users page missing %q", want)
		}
	}
}

func TestUsersPagePeopleSignInColumnTellsLocalPasswordTruth(t *testing.T) {
	fixture := newInvitationWebFixture(t)
	mustCreateWebUser(t, fixture.ctx, fixture.service, "haspw@example.test", false)
	noPassword := mustCreateWebUser(t, fixture.ctx, fixture.service, "nopw@example.test", false)
	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM local_credentials WHERE user_id = ?`, noPassword.ID); err != nil {
		t.Fatal(err)
	}

	recorder := getUsersPage(t, fixture.server, "/users", fixture.adminCookie(), false)
	if recorder.Code != http.StatusOK {
		t.Fatalf("users page status=%d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Sign-in") {
		t.Fatal("people rows must label the sign-in column")
	}
	if got := strings.Count(body, `<span class="text-text-muted">No local password</span>`); got != 2 {
		t.Fatalf("neutral no-password state rendered %d times, want desktop and mobile", got)
	}
	if got := strings.Count(body, `<td class="px-4 py-4 text-text">Password</td>`); got != 2 {
		t.Fatalf("desktop Password cell rendered %d times, want admin and haspw", got)
	}
	if got := strings.Count(body, `<dd class="m-0">Password</dd>`); got != 2 {
		t.Fatalf("mobile Password value rendered %d times, want admin and haspw", got)
	}
}
