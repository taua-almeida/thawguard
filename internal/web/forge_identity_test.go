package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeidentity"
)

const forgeIdentityWebPublicURL = "http://thawguard.example.test"

type fakeForgeIdentityService struct {
	oauthClient forgeidentity.OAuthClient
	oauthFound  bool
	oauthErr    error

	saveErr      error
	saveCalls    []forgeidentity.SaveOAuthClientInput
	disableErr   error
	disableCalls []forgeidentity.DisableOAuthClientInput

	account    forgeidentity.AccountView
	accountErr error

	startResult forgeidentity.LinkStart
	startErr    error
	startCalls  []forgeidentity.StartLinkInput
	cancelCalls int

	callbackResult forgeidentity.LinkResultCode
	callbackErr    error
	callbackCalls  []forgeidentity.CallbackInput

	unlinkErr   error
	unlinkCalls []forgeidentity.UnlinkInput
	purgeErr    error
	purgeCalls  []forgeidentity.PurgeInput

	identity      forgeidentity.Identity
	identityFound bool
	hasIdentities bool
}

func (f *fakeForgeIdentityService) OAuthClient(context.Context) (forgeidentity.OAuthClient, bool, error) {
	return f.oauthClient, f.oauthFound, f.oauthErr
}

func (f *fakeForgeIdentityService) SaveOAuthClient(_ context.Context, _ int64, input forgeidentity.SaveOAuthClientInput) error {
	f.saveCalls = append(f.saveCalls, input)
	return f.saveErr
}

func (f *fakeForgeIdentityService) DisableOAuthClient(_ context.Context, _ int64, input forgeidentity.DisableOAuthClientInput) error {
	f.disableCalls = append(f.disableCalls, input)
	return f.disableErr
}

func (f *fakeForgeIdentityService) AccountForUser(context.Context, int64) (forgeidentity.AccountView, error) {
	return f.account, f.accountErr
}

func (f *fakeForgeIdentityService) StartLink(_ context.Context, input forgeidentity.StartLinkInput) (forgeidentity.LinkStart, error) {
	f.startCalls = append(f.startCalls, input)
	return f.startResult, f.startErr
}

func (f *fakeForgeIdentityService) CancelStart(context.Context, forgeidentity.StartHandle) error {
	f.cancelCalls++
	return nil
}

func (f *fakeForgeIdentityService) CompleteLinkCallback(_ context.Context, input forgeidentity.CallbackInput) (forgeidentity.LinkResultCode, error) {
	f.callbackCalls = append(f.callbackCalls, input)
	return f.callbackResult, f.callbackErr
}

func (f *fakeForgeIdentityService) Unlink(_ context.Context, input forgeidentity.UnlinkInput) error {
	f.unlinkCalls = append(f.unlinkCalls, input)
	return f.unlinkErr
}

func (f *fakeForgeIdentityService) Purge(_ context.Context, input forgeidentity.PurgeInput) error {
	f.purgeCalls = append(f.purgeCalls, input)
	return f.purgeErr
}

func (f *fakeForgeIdentityService) IdentityForUser(context.Context, int64) (forgeidentity.Identity, bool, error) {
	return f.identity, f.identityFound, nil
}

func (f *fakeForgeIdentityService) HasIdentities(context.Context) (bool, error) {
	return f.hasIdentities, nil
}

type forgeIdentityWebFixture struct {
	ctx         context.Context
	authService *auth.Service
	service     *fakeForgeIdentityService
	connections *fakeForgeConnectionService
	server      *Server
	admin       auth.Session
	user        auth.Session
	userRecord  auth.User
}

func newForgeIdentityWebFixture(t *testing.T) *forgeIdentityWebFixture {
	t.Helper()
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	userRecord := mustCreateWebUser(t, ctx, authService, "linker@example.test", false)
	userSession, err := authService.Login(ctx, auth.LoginParams{Email: userRecord.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	service := &fakeForgeIdentityService{}
	connections := &fakeForgeConnectionService{connection: savedForgeConnection(), found: true}
	server := NewServer(Config{
		AppName:                "Thawguard",
		PublicURL:              forgeIdentityWebPublicURL,
		AuthService:            authService,
		ForgeIdentityService:   service,
		ForgeConnectionService: connections,
		ForgeConnectionSecretEncryptionConfigured: true,
	})
	return &forgeIdentityWebFixture{
		ctx:         ctx,
		authService: authService,
		service:     service,
		connections: connections,
		server:      server,
		admin:       admin,
		user:        userSession,
		userRecord:  userRecord,
	}
}

func (f *forgeIdentityWebFixture) get(session auth.Session, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Host = "thawguard.example.test"
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	f.server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func (f *forgeIdentityWebFixture) post(session auth.Session, path string, form url.Values) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Host = "thawguard.example.test"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", forgeIdentityWebPublicURL)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	f.server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func linkedForgeIdentityView() forgeidentity.AccountView {
	identity := forgeidentity.Identity{
		ID:             5,
		ConnectionID:   3,
		UserID:         2,
		UsernameAtLink: "fixture-user",
		LinkedAt:       time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC),
	}
	return forgeidentity.AccountView{Status: forgeidentity.AccountLinked, Identity: &identity}
}

func TestForgeCallbackGuardBoundary(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)
	fixture.service.callbackResult = forgeidentity.LinkStale

	rejected := []struct {
		name   string
		method string
		target string
		host   string
		status int
	}{
		{"trailing slash", http.MethodGet, "/account/forgejo/callback/", "", http.StatusNotFound},
		{"duplicate separators", http.MethodGet, "/account/forgejo//callback", "", http.StatusNotFound},
		{"dot segments", http.MethodGet, "/account/forgejo/../forgejo/callback", "", http.StatusNotFound},
		{"encoded separator", http.MethodGet, "/account%2Fforgejo/callback", "", http.StatusNotFound},
		{"encoded path bytes", http.MethodGet, "/account/forgejo/%63allback", "", http.StatusNotFound},
		{"backslash separator", http.MethodGet, `/account\forgejo/callback`, "", http.StatusNotFound},
		{"absolute form", http.MethodGet, "http://thawguard.example.test/account/forgejo/callback", "", http.StatusNotFound},
		{"wrong authority", http.MethodGet, "/account/forgejo/callback", "evil.example.test", http.StatusNotFound},
		{"head method", http.MethodHead, "/account/forgejo/callback", "", http.StatusMethodNotAllowed},
		{"post method", http.MethodPost, "/account/forgejo/callback", "", http.StatusMethodNotAllowed},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tc.method, tc.target+"?state=x&code=y", nil)
			request.Host = "thawguard.example.test"
			if tc.host != "" {
				request.Host = tc.host
			}
			// Cookies must never be parsed on rejection; supply one anyway so a
			// violation would be observable through the recorded service call.
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.user.ID})
			fixture.server.Routes().ServeHTTP(recorder, request)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.status)
			}
			if len(fixture.service.callbackCalls) != 0 {
				t.Fatal("guard rejection reached the callback service")
			}
			headers := recorder.Header()
			if headers.Get("Cache-Control") != "no-store" ||
				headers.Get("Referrer-Policy") != "no-referrer" ||
				headers.Get("X-Frame-Options") != "DENY" ||
				headers.Get("X-Content-Type-Options") != "nosniff" ||
				headers.Get("Content-Security-Policy") != forgeCallbackCSP {
				t.Fatalf("guard rejection headers = %v", headers)
			}
			if tc.status == http.StatusMethodNotAllowed && headers.Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q", headers.Get("Allow"))
			}
		})
	}

	// The exact origin-form GET at the canonical authority is admitted and
	// dispatched with the raw query and both cookies.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/account/forgejo/callback?state=abc&code=def", nil)
	request.Host = "thawguard.example.test"
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.user.ID})
	request.AddCookie(&http.Cookie{Name: forgeLinkCookieName, Value: "browser-token-value"})
	fixture.server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther ||
		recorder.Header().Get("Location") != "/account?notice="+forgeLinkStaleNotice {
		t.Fatalf("admitted callback status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if recorder.Header().Get("Referrer-Policy") != "no-referrer" ||
		recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admitted callback headers = %v", recorder.Header())
	}
	if len(fixture.service.callbackCalls) != 1 {
		t.Fatalf("callback calls = %d", len(fixture.service.callbackCalls))
	}
	call := fixture.service.callbackCalls[0]
	if call.RawQuery != "state=abc&code=def" || call.SessionID != fixture.user.ID || call.BrowserToken != "browser-token-value" {
		t.Fatalf("callback input = %+v", call)
	}
	// The shared browser cookie is never deleted by callback responses.
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == forgeLinkCookieName {
			t.Fatal("callback response mutated the browser-binding cookie")
		}
	}

	// Duplicate session or browser cookies resolve to no binding.
	fixture.service.callbackCalls = nil
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/account/forgejo/callback?state=abc&code=def", nil)
	request.Host = "thawguard.example.test"
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.user.ID})
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "second-session"})
	request.AddCookie(&http.Cookie{Name: forgeLinkCookieName, Value: "one"})
	request.AddCookie(&http.Cookie{Name: forgeLinkCookieName, Value: "two"})
	fixture.server.Routes().ServeHTTP(recorder, request)
	if len(fixture.service.callbackCalls) != 1 {
		t.Fatalf("callback calls = %d", len(fixture.service.callbackCalls))
	}
	call = fixture.service.callbackCalls[0]
	if call.SessionID != "" || call.BrowserToken != "" {
		t.Fatalf("duplicate cookies resolved to bindings: %+v", call)
	}
}

func TestForgeCallbackNoticeMapping(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)
	cases := []struct {
		result forgeidentity.LinkResultCode
		notice string
	}{
		{forgeidentity.LinkLinked, forgeLinkedNotice},
		{forgeidentity.LinkProviderDenied, forgeLinkDeniedNotice},
		{forgeidentity.LinkProviderUnavailable, forgeLinkProviderNotice},
		{forgeidentity.LinkProviderInvalid, forgeLinkProviderNotice},
		{forgeidentity.LinkCollision, forgeLinkCollisionNotice},
		{forgeidentity.LinkAlreadyLinked, forgeLinkAlreadyNotice},
		{forgeidentity.LinkStale, forgeLinkStaleNotice},
		{forgeidentity.LinkConfigurationUnavailable, forgeLinkUnavailableNotice},
	}
	for _, tc := range cases {
		fixture.service.callbackResult = tc.result
		fixture.service.callbackErr = nil
		recorder := fixture.get(fixture.user, "/account/forgejo/callback?state=abc&code=def")
		if recorder.Code != http.StatusSeeOther ||
			recorder.Header().Get("Location") != "/account?notice="+tc.notice {
			t.Fatalf("result %q: status=%d location=%q", tc.result, recorder.Code, recorder.Header().Get("Location"))
		}
	}
	fixture.service.callbackErr = forgeidentity.ErrOutcomeUnknown
	recorder := fixture.get(fixture.user, "/account/forgejo/callback?state=abc&code=def")
	if recorder.Header().Get("Location") != "/account?notice="+forgeLinkUnknownNotice {
		t.Fatalf("unknown outcome location=%q", recorder.Header().Get("Location"))
	}
}

func TestAccountPageForgeCardStates(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)

	fixture.service.account = forgeidentity.AccountView{Status: forgeidentity.AccountUnavailable}
	body := fixture.get(fixture.user, "/account").Body.String()
	if !strings.Contains(body, "Forgejo identity linking is not available right now") {
		t.Fatalf("unavailable card missing: %q", body)
	}

	fixture.service.account = forgeidentity.AccountView{
		Status:             forgeidentity.AccountReady,
		ConnectionID:       3,
		ConnectionRevision: 1,
		OAuthRevision:      2,
	}
	recorder := fixture.get(fixture.user, "/account")
	body = recorder.Body.String()
	for _, want := range []string{
		`action="/account/forgejo/link"`,
		`name="expected_connection_id" value="3"`,
		`name="expected_oauth_revision" value="2"`,
		`name="current_password"`,
		"Link Forgejo account",
		"grants no repository access, role, or authority",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ready card missing %q", want)
		}
	}
	headers := recorder.Header()
	if headers.Get("Cache-Control") != "no-store" ||
		headers.Get("Referrer-Policy") != "same-origin" ||
		headers.Get("X-Frame-Options") != "DENY" ||
		headers.Get("X-Content-Type-Options") != "nosniff" ||
		headers.Get("Content-Security-Policy") != sensitiveFormCSP {
		t.Fatalf("account headers = %v", headers)
	}

	fixture.service.account = forgeidentity.AccountView{Status: forgeidentity.AccountInProgress}
	body = fixture.get(fixture.user, "/account").Body.String()
	if !strings.Contains(body, "Link attempt in progress") {
		t.Fatal("in-progress card missing")
	}

	fixture.service.account = linkedForgeIdentityView()
	body = fixture.get(fixture.user, "/account").Body.String()
	for _, want := range []string{
		"fixture-user",
		"2026-08-09 10:00:00 UTC",
		"Unlink Forgejo identity",
		`id="forgejo-unlink-confirm"`,
		`name="identity_id" value="5"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("linked card missing %q", want)
		}
	}
	if strings.Contains(body, `id="forgejo-unlink-confirm" open`) {
		t.Fatal("unlink dialog open without confirmation request")
	}
	body = fixture.get(fixture.user, "/account?unlink=confirm").Body.String()
	if !strings.Contains(body, `id="forgejo-unlink-confirm" open`) {
		t.Fatal("unlink confirmation did not open server-side")
	}

	for _, notice := range []string{
		forgeLinkedNotice, forgeLinkDeniedNotice, forgeLinkProviderNotice, forgeLinkCollisionNotice,
		forgeLinkAlreadyNotice, forgeLinkStaleNotice, forgeLinkUnknownNotice, forgeLinkPasswordNotice,
		forgeLinkUnavailableNotice, forgeLinkInProgressNotice, forgeLinkAuthorityNotice,
		forgeUnlinkedNotice, forgeUnlinkPasswordNotice, forgeUnlinkStaleNotice,
		forgeUnlinkAuthorityNotice, forgeUnlinkUnknownNotice,
	} {
		if toasts := forgeAccountNoticeToasts(url.Values{"notice": {notice}}); len(toasts) != 1 {
			t.Fatalf("notice %q has no toast", notice)
		}
	}
	if toasts := forgeAccountNoticeToasts(url.Values{"notice": {"unknown-notice"}}); toasts != nil {
		t.Fatal("unknown notice produced a toast")
	}
}

func TestForgeLinkStartContract(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)
	fixture.service.startResult = forgeidentity.LinkStart{
		AuthorizationURL: "https://forge.example.test/login/oauth/authorize?client_id=fixture",
		BrowserToken:     "fixture-browser-token",
	}
	form := url.Values{
		csrfFormField:             {fixture.user.CSRFToken},
		"current_password":        {accountWebTestPassword},
		"expected_connection_id":  {"3"},
		"expected_oauth_revision": {"2"},
	}

	// Origin is required exactly.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/account/forgejo/link", strings.NewReader(form.Encode()))
	request.Host = "thawguard.example.test"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.user.ID})
	fixture.server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(fixture.service.startCalls) != 0 {
		t.Fatalf("missing origin status=%d starts=%d", recorder.Code, len(fixture.service.startCalls))
	}

	// The exact form is enforced before any service work.
	extra := cloneValues(form)
	extra.Set("unexpected", "1")
	if response := fixture.post(fixture.user, "/account/forgejo/link", extra); response.Code != http.StatusBadRequest {
		t.Fatalf("extra field status=%d", response.Code)
	}
	missing := cloneValues(form)
	missing.Del("expected_oauth_revision")
	if response := fixture.post(fixture.user, "/account/forgejo/link", missing); response.Code != http.StatusBadRequest {
		t.Fatalf("missing field status=%d", response.Code)
	}

	// A wrong password never reaches the service.
	wrongPassword := cloneValues(form)
	wrongPassword.Set("current_password", "not the password")
	response := fixture.post(fixture.user, "/account/forgejo/link", wrongPassword)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/account?notice="+forgeLinkPasswordNotice ||
		len(fixture.service.startCalls) != 0 {
		t.Fatalf("wrong password status=%d location=%q starts=%d",
			response.Code, response.Header().Get("Location"), len(fixture.service.startCalls))
	}

	// Service error mapping.
	for _, tc := range []struct {
		err    error
		notice string
	}{
		{forgeidentity.ErrAuthorization, forgeLinkAuthorityNotice},
		{forgeidentity.ErrLinkInProgress, forgeLinkInProgressNotice},
		{forgeidentity.ErrUnavailable, forgeLinkUnavailableNotice},
		{forgeidentity.ErrConfiguration, forgeLinkUnavailableNotice},
		{forgeidentity.ErrOutcomeUnknown, forgeLinkUnknownNotice},
	} {
		fixture.service.startErr = tc.err
		response := fixture.post(fixture.user, "/account/forgejo/link", form)
		if response.Header().Get("Location") != "/account?notice="+tc.notice {
			t.Fatalf("error %v location=%q", tc.err, response.Header().Get("Location"))
		}
	}
	fixture.service.startErr = nil
	fixture.service.startCalls = nil

	response = fixture.post(fixture.user, "/account/forgejo/link", form)
	if response.Code != http.StatusOK {
		t.Fatalf("start status=%d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "https://forge.example.test/login/oauth/authorize?client_id=fixture") ||
		!strings.Contains(body, "Continue to Forgejo") {
		t.Fatalf("provider navigation body missing continuation: %q", body)
	}
	if got := response.Header().Get("Content-Security-Policy"); got != providerNavigationCSP {
		t.Fatalf("provider navigation CSP = %q", got)
	}
	if len(fixture.service.startCalls) != 1 {
		t.Fatalf("start calls = %d", len(fixture.service.startCalls))
	}
	start := fixture.service.startCalls[0]
	if start.SessionID != fixture.user.ID || start.ExpectedConnectionID != 3 || start.ExpectedOAuthRevision != 2 {
		t.Fatalf("start input = %+v", start)
	}
	var linkCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == forgeLinkCookieName {
			linkCookie = cookie
		}
	}
	if linkCookie == nil || linkCookie.Value != "fixture-browser-token" ||
		linkCookie.Path != forgeLinkCookiePath || !linkCookie.HttpOnly ||
		linkCookie.SameSite != http.SameSiteLaxMode || linkCookie.MaxAge != forgeLinkCookieMaxAge {
		t.Fatalf("browser cookie = %+v", linkCookie)
	}
}

func TestForgeUnlinkContract(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)
	form := url.Values{
		csrfFormField:      {fixture.user.CSRFToken},
		"current_password": {accountWebTestPassword},
		"identity_id":      {"5"},
	}

	wrongPassword := cloneValues(form)
	wrongPassword.Set("current_password", "not the password")
	response := fixture.post(fixture.user, "/account/forgejo/unlink", wrongPassword)
	if response.Header().Get("Location") != "/account?notice="+forgeUnlinkPasswordNotice ||
		len(fixture.service.unlinkCalls) != 0 {
		t.Fatalf("wrong password location=%q unlinks=%d",
			response.Header().Get("Location"), len(fixture.service.unlinkCalls))
	}

	for _, tc := range []struct {
		err    error
		notice string
	}{
		{forgeidentity.ErrIdentityStale, forgeUnlinkStaleNotice},
		{forgeidentity.ErrAuthorization, forgeUnlinkAuthorityNotice},
		{forgeidentity.ErrOutcomeUnknown, forgeUnlinkUnknownNotice},
	} {
		fixture.service.unlinkErr = tc.err
		response := fixture.post(fixture.user, "/account/forgejo/unlink", form)
		if response.Header().Get("Location") != "/account?notice="+tc.notice {
			t.Fatalf("error %v location=%q", tc.err, response.Header().Get("Location"))
		}
	}
	fixture.service.unlinkErr = nil
	fixture.service.unlinkCalls = nil

	response = fixture.post(fixture.user, "/account/forgejo/unlink", form)
	if response.Header().Get("Location") != "/account?notice="+forgeUnlinkedNotice {
		t.Fatalf("unlink location=%q", response.Header().Get("Location"))
	}
	if len(fixture.service.unlinkCalls) != 1 || fixture.service.unlinkCalls[0].IdentityID != 5 ||
		fixture.service.unlinkCalls[0].SessionID != fixture.user.ID {
		t.Fatalf("unlink input = %+v", fixture.service.unlinkCalls)
	}
}

func TestForgeOAuthClientAdminContract(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)
	saveForm := url.Values{
		csrfFormField:             {fixture.admin.CSRFToken},
		"client_id":               {"fixture-client"},
		"client_secret":           {"fixture-oauth-secret"},
		"expected_connection_id":  {"3"},
		"expected_revision":       {"1"},
		"expected_oauth_revision": {"0"},
	}

	// A non-Administrator cannot save.
	userForm := cloneValues(saveForm)
	userForm.Set(csrfFormField, fixture.user.CSRFToken)
	if response := fixture.post(fixture.user, "/settings/forge-access/oauth", userForm); response.Code != http.StatusForbidden {
		t.Fatalf("non-admin save status=%d", response.Code)
	}
	if len(fixture.service.saveCalls) != 0 {
		t.Fatal("non-admin save reached the service")
	}

	// Validation errors re-render without echoing credentials.
	fixture.service.saveErr = forgeidentity.ValidationError{Message: "OAuth client ID must be between 1 and 255 bytes"}
	response := fixture.post(fixture.admin, "/settings/forge-access/oauth", saveForm)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("validation status=%d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "OAuth client ID must be between 1 and 255 bytes") {
		t.Fatal("validation message missing")
	}
	if strings.Contains(body, "fixture-oauth-secret") || strings.Contains(body, `value="fixture-client"`) {
		t.Fatal("rejected save echoed submitted credentials")
	}

	for _, tc := range []struct {
		err    error
		notice string
	}{
		{forgeidentity.ErrConflict, forgeOAuthStaleNotice},
		{forgeidentity.ErrAdminOnly, forgeOAuthAuthorityNotice},
		{forgeidentity.ErrConfiguration, forgeOAuthUnavailableNotice},
		{forgeidentity.ErrOutcomeUnknown, forgeOAuthUnknownNotice},
	} {
		fixture.service.saveErr = tc.err
		response := fixture.post(fixture.admin, "/settings/forge-access/oauth", saveForm)
		if response.Header().Get("Location") != "/settings/forge-access?notice="+tc.notice {
			t.Fatalf("save error %v location=%q", tc.err, response.Header().Get("Location"))
		}
	}
	fixture.service.saveErr = nil
	fixture.service.saveCalls = nil
	response = fixture.post(fixture.admin, "/settings/forge-access/oauth", saveForm)
	if response.Header().Get("Location") != "/settings/forge-access?notice="+forgeOAuthSavedNotice {
		t.Fatalf("save location=%q", response.Header().Get("Location"))
	}
	if len(fixture.service.saveCalls) != 1 {
		t.Fatalf("save calls = %d", len(fixture.service.saveCalls))
	}
	saved := fixture.service.saveCalls[0]
	if saved.ExpectedConnectionID != 3 || saved.ExpectedConnectionRevision != 1 ||
		saved.ExpectedOAuthRevision != 0 || saved.ClientID != "fixture-client" ||
		saved.ClientSecret != "fixture-oauth-secret" {
		t.Fatalf("save input = %+v", saved)
	}

	disableForm := url.Values{
		csrfFormField:             {fixture.admin.CSRFToken},
		"expected_connection_id":  {"3"},
		"expected_revision":       {"1"},
		"expected_oauth_revision": {"2"},
		"confirm_disable":         {"disable"},
	}
	wrongConfirm := cloneValues(disableForm)
	wrongConfirm.Set("confirm_disable", "yes")
	if response := fixture.post(fixture.admin, "/settings/forge-access/oauth/disable", wrongConfirm); response.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirm status=%d", response.Code)
	}
	response = fixture.post(fixture.admin, "/settings/forge-access/oauth/disable", disableForm)
	if response.Header().Get("Location") != "/settings/forge-access?notice="+forgeOAuthDisabledNotice {
		t.Fatalf("disable location=%q", response.Header().Get("Location"))
	}
	if len(fixture.service.disableCalls) != 1 || fixture.service.disableCalls[0].ExpectedOAuthRevision != 2 {
		t.Fatalf("disable input = %+v", fixture.service.disableCalls)
	}
}

func TestForgeAccessOAuthCardStates(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)

	// Unconfigured: revision 0 fence plus the save form.
	body := fixture.get(fixture.admin, "/settings/forge-access").Body.String()
	for _, want := range []string{
		"Identity linking OAuth client",
		"Not configured",
		forgeIdentityWebPublicURL + "/account/forgejo/callback",
		`name="expected_oauth_revision" value="0"`,
		`action="/settings/forge-access/oauth"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unconfigured card missing %q", want)
		}
	}

	// Enabled: details, disable dialog, and the reset fence field.
	fixture.service.oauthFound = true
	fixture.service.oauthClient = forgeidentity.OAuthClient{
		ConnectionID: 3,
		Enabled:      true,
		ClientID:     "fixture-client",
		BoundBaseURL: "https://forge.example.test",
		Revision:     4,
	}
	body = fixture.get(fixture.admin, "/settings/forge-access").Body.String()
	for _, want := range []string{
		">Enabled<",
		"fixture-client",
		"Disable linking",
		`id="forge-oauth-disable-confirm"`,
		`name="expected_oauth_revision" value="4"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("enabled card missing %q", want)
		}
	}
	if !strings.Contains(formForAction(t, body, "/settings/forge-access/reset"), `name="expected_oauth_revision" value="4"`) {
		t.Fatal("reset dialog is missing the OAuth revision fence")
	}

	// Stale: the bound base URL no longer matches the connection.
	fixture.service.oauthClient.BoundBaseURL = "https://other.example.test"
	body = fixture.get(fixture.admin, "/settings/forge-access").Body.String()
	if !strings.Contains(body, ">Stale<") || !strings.Contains(body, "Bound installation URL is stale") {
		t.Fatal("stale card state missing")
	}

	// Disabled: destroyed credentials plus the re-enable form.
	fixture.service.oauthClient = forgeidentity.OAuthClient{ConnectionID: 3, Enabled: false, Revision: 5}
	body = fixture.get(fixture.admin, "/settings/forge-access").Body.String()
	if !strings.Contains(body, "Identity linking disabled") ||
		!strings.Contains(body, `name="expected_oauth_revision" value="5"`) {
		t.Fatal("disabled card state missing")
	}

	// Identities block the reset with a dedicated dialog.
	fixture.service.hasIdentities = true
	body = fixture.get(fixture.admin, "/settings/forge-access").Body.String()
	if !strings.Contains(body, "Reset blocked by linked Forgejo identities") ||
		!strings.Contains(body, "Reset is blocked until every linked Forgejo identity") {
		t.Fatal("identity reset block missing")
	}
	fixture.service.hasIdentities = false

	// Encryption unavailable: no save form, an explicit warning instead.
	noEncryption := NewServer(Config{
		AppName:                "Thawguard",
		PublicURL:              forgeIdentityWebPublicURL,
		AuthService:            fixture.authService,
		ForgeIdentityService:   fixture.service,
		ForgeConnectionService: fixture.connections,
		ForgeConnectionSecretEncryptionConfigured: false,
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/settings/forge-access", nil)
	request.Host = "thawguard.example.test"
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID})
	noEncryption.Routes().ServeHTTP(recorder, request)
	if !strings.Contains(recorder.Body.String(), "Saving the OAuth client is disabled until secret encryption is configured") {
		t.Fatal("encryption-unavailable state missing")
	}

	// Without the identity service the card degrades to unavailable.
	unavailable := NewServer(Config{
		AppName:                "Thawguard",
		PublicURL:              forgeIdentityWebPublicURL,
		AuthService:            fixture.authService,
		ForgeConnectionService: fixture.connections,
		ForgeConnectionSecretEncryptionConfigured: true,
	})
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/settings/forge-access", nil)
	request.Host = "thawguard.example.test"
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fixture.admin.ID})
	unavailable.Routes().ServeHTTP(recorder, request)
	if !strings.Contains(recorder.Body.String(), "Identity linking is not configured on this installation") {
		t.Fatal("service-unavailable card state missing")
	}
}

func TestUserDetailForgeIdentityAndPurge(t *testing.T) {
	fixture := newForgeIdentityWebFixture(t)
	fixture.service.identityFound = true
	fixture.service.identity = forgeidentity.Identity{
		ID:             9,
		ConnectionID:   3,
		UserID:         fixture.userRecord.ID,
		UsernameAtLink: "fixture-user",
		LinkedAt:       time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC),
	}
	target := "/users/" + int64Text(fixture.userRecord.ID)

	// An enabled owner's identity is visible but not purgeable.
	body := fixture.get(fixture.admin, target).Body.String()
	if !strings.Contains(body, "fixture-user") ||
		!strings.Contains(body, "Only the owner can unlink while the account is enabled") {
		t.Fatal("enabled owner identity section missing")
	}
	if strings.Contains(body, "Purge identity") {
		t.Fatal("purge offered for an enabled owner")
	}

	if _, err := fixture.authService.DisableUser(fixture.ctx, mustAdminID(t, fixture), fixture.userRecord.ID); err != nil {
		t.Fatal(err)
	}
	body = fixture.get(fixture.admin, target+"?forge-purge=confirm").Body.String()
	if !strings.Contains(body, "Purge identity") ||
		!strings.Contains(body, `id="user-forge-purge-confirm" open`) ||
		!strings.Contains(body, `name="identity_id" value="9"`) {
		t.Fatal("purge confirmation missing for a disabled owner")
	}

	purgeForm := url.Values{
		csrfFormField:      {fixture.admin.CSRFToken},
		"current_password": {accountWebTestPassword},
		"identity_id":      {"9"},
		"confirm_purge":    {"purge"},
	}
	wrongPassword := cloneValues(purgeForm)
	wrongPassword.Set("current_password", "not the password")
	response := fixture.post(fixture.admin, target+"/forge-identity/purge", wrongPassword)
	if response.Header().Get("Location") != target+"?notice="+forgePurgePasswordNotice ||
		len(fixture.service.purgeCalls) != 0 {
		t.Fatalf("wrong password location=%q purges=%d",
			response.Header().Get("Location"), len(fixture.service.purgeCalls))
	}
	missingConfirm := cloneValues(purgeForm)
	missingConfirm.Del("confirm_purge")
	if response := fixture.post(fixture.admin, target+"/forge-identity/purge", missingConfirm); response.Code != http.StatusBadRequest {
		t.Fatalf("missing confirm status=%d", response.Code)
	}

	for _, tc := range []struct {
		err    error
		notice string
	}{
		{forgeidentity.ErrIdentityStale, forgePurgeStaleNotice},
		{forgeidentity.ErrAdminOnly, forgePurgeAuthorityNotice},
		{forgeidentity.ErrOutcomeUnknown, forgePurgeUnknownNotice},
	} {
		fixture.service.purgeErr = tc.err
		response := fixture.post(fixture.admin, target+"/forge-identity/purge", purgeForm)
		if response.Header().Get("Location") != target+"?notice="+tc.notice {
			t.Fatalf("purge error %v location=%q", tc.err, response.Header().Get("Location"))
		}
	}
	fixture.service.purgeErr = nil
	fixture.service.purgeCalls = nil
	response = fixture.post(fixture.admin, target+"/forge-identity/purge", purgeForm)
	if response.Header().Get("Location") != target+"?notice="+forgeIdentityPurgedNotice {
		t.Fatalf("purge location=%q", response.Header().Get("Location"))
	}
	if len(fixture.service.purgeCalls) != 1 {
		t.Fatalf("purge calls = %d", len(fixture.service.purgeCalls))
	}
	purge := fixture.service.purgeCalls[0]
	if purge.TargetUserID != fixture.userRecord.ID || purge.IdentityID != 9 ||
		!purge.ConfirmPurge || purge.SessionID != fixture.admin.ID {
		t.Fatalf("purge input = %+v", purge)
	}
}

func mustAdminID(t *testing.T, fixture *forgeIdentityWebFixture) int64 {
	t.Helper()
	if fixture.admin.User.ID <= 0 {
		t.Fatal("admin fixture has no user id")
	}
	return fixture.admin.User.ID
}

func int64Text(value int64) string {
	return strconv.FormatInt(value, 10)
}
