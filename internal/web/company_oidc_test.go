package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/companyoidc"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

const companyOIDCWebPublicURL = "https://thawguard.example.test"

func TestAuthenticationSettingsRequireAdministratorAndPasswordChangeGate(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	for _, path := range []string{"/settings/authentication", "/settings/authentication/edit"} {
		signedOut := companyOIDCGET(fixture.server, path, nil)
		if signedOut.Code != http.StatusSeeOther || signedOut.Header().Get("Location") != "/login" {
			t.Fatalf("signed-out GET %s: status=%d location=%q", path, signedOut.Code, signedOut.Header().Get("Location"))
		}
	}

	viewer := mustCreateWebUser(t, fixture.ctx, fixture.authService, "oidc-viewer@example.test", false)
	viewerSession, err := fixture.authService.Login(fixture.ctx, auth.LoginParams{Email: viewer.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	viewerCookie := &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}
	for _, path := range []string{"/settings/authentication", "/settings/authentication/edit"} {
		if got := companyOIDCGET(fixture.server, path, viewerCookie); got.Code != http.StatusForbidden {
			t.Fatalf("viewer GET %s returned %d", path, got.Code)
		}
	}
	viewerForm := validCompanyOIDCWebForm(viewerSession.CSRFToken, "0", "viewer secret")
	if got := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", viewerCookie, viewerForm, []string{companyOIDCWebPublicURL}); got.Code != http.StatusForbidden {
		t.Fatalf("viewer POST returned %d", got.Code)
	}

	forced := mustCreateWebUser(t, fixture.ctx, fixture.authService, "forced-oidc-admin@example.test", true)
	forcedSession, err := fixture.authService.Login(fixture.ctx, auth.LoginParams{Email: forced.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, forced.ID); err != nil {
		t.Fatal(err)
	}
	forcedCookie := &http.Cookie{Name: sessionCookieName, Value: forcedSession.ID}
	for _, path := range []string{"/settings/authentication", "/settings/authentication/edit"} {
		got := companyOIDCGET(fixture.server, path, forcedCookie)
		if got.Code != http.StatusSeeOther || got.Header().Get("Location") != "/account/password" {
			t.Fatalf("forced GET %s: status=%d location=%q", path, got.Code, got.Header().Get("Location"))
		}
	}
	forcedForm := validCompanyOIDCWebForm(forcedSession.CSRFToken, "0", "forced secret")
	forcedPost := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", forcedCookie, forcedForm, []string{companyOIDCWebPublicURL})
	if forcedPost.Code != http.StatusSeeOther || forcedPost.Header().Get("Location") != "/account/password" {
		t.Fatalf("forced POST: status=%d location=%q", forcedPost.Code, forcedPost.Header().Get("Location"))
	}

	if got := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie()); got.Code != http.StatusOK {
		t.Fatalf("Administrator GET returned %d", got.Code)
	}
}

func TestAuthenticationDraftEmptyCreateSavedAndEditStatesKeepSecretWriteOnly(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	empty := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, empty, http.StatusOK,
		"Authentication",
		"No company connection configured",
		"Configure OIDC",
		"Local-password sign-in remains unchanged",
		"Company OIDC can later establish identity. Repository access is managed separately.",
	)
	if strings.Contains(empty.Body.String(), `name="client_secret"`) {
		t.Fatal("empty read state rendered a secret control")
	}

	create := companyOIDCGET(fixture.server, "/settings/authentication/edit", fixture.adminCookie())
	assertStatusAndBodyContains(t, create, http.StatusOK,
		"Configure company OIDC Draft",
		`name="expected_revision" value="0"`,
		"Client secret",
		"Allowed domains",
		"Save draft",
		"Verify metadata",
		"Unavailable",
		"Test sign-in",
		"Not implemented",
	)
	assertNoCompanyOIDCCheckSurface(t, create.Body.String())

	secret := "company secret <never render>"
	form := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "0", secret)
	form.Set("provider_label", "Northstar <Identity>")
	form.Set("issuer", "https://ID.example.test/tenant/%7Eexact/")
	form.Set("client_id", "northstar-client-id")
	form.Set("allowed_domains", "zeta.example\nAlpha.Example\nalpha.example\n")
	saved := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), form, []string{companyOIDCWebPublicURL})
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Location") != "/settings/authentication" {
		t.Fatalf("save status=%d location=%q body=%q", saved.Code, saved.Header().Get("Location"), saved.Body.String())
	}
	assertSecretAbsent(t, saved.Body.String(), secret)

	read := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, read, http.StatusOK,
		"Company OIDC connection",
		"Northstar &lt;Identity&gt;",
		"https://ID.example.test/tenant/%7Eexact/",
		"northstar-client-id",
		"alpha.example",
		"zeta.example",
		"Client secret stored",
		"Draft",
		"Edit draft",
		"Provider metadata has not been checked. Metadata checking is not available in this version.",
	)
	for _, editable := range []string{`name="provider_label"`, `name="issuer"`, `name="client_id"`, `name="client_secret"`, "Save draft"} {
		if strings.Contains(read.Body.String(), editable) {
			t.Fatalf("saved read state contains editable control %q", editable)
		}
	}
	assertSecretAbsent(t, read.Body.String(), secret)
	assertNoCompanyOIDCCheckSurface(t, read.Body.String())

	edit := companyOIDCGET(fixture.server, "/settings/authentication/edit", fixture.adminCookie())
	assertStatusAndBodyContains(t, edit, http.StatusOK,
		"Edit company OIDC Draft",
		`name="expected_revision" value="1"`,
		"Replace client secret",
		"Leave blank to keep the stored secret",
		"Northstar &lt;Identity&gt;",
	)
	secretControl := renderedControlTag(t, edit.Body.String(), "oidc-client-secret")
	if strings.Contains(secretControl, "value=") {
		t.Fatalf("edit secret control was populated: %s", secretControl)
	}
	assertSecretAbsent(t, edit.Body.String(), secret)
	assertNoCompanyOIDCCheckSurface(t, edit.Body.String())
}

func TestAuthenticationValidationConflictAndInternalErrorsNeverEchoSecret(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	validationSecret := "validation secret canary"
	invalid := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "0", validationSecret)
	invalid.Set("provider_label", "Preserved provider")
	invalid.Set("issuer", "http://insecure.example.test")
	invalid.Set("allowed_domains", "Preserved.Example")
	validation := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), invalid, []string{companyOIDCWebPublicURL})
	assertStatusAndBodyContains(t, validation, http.StatusBadRequest, "issuer must use HTTPS", "Preserved provider", "Preserved.Example", "Save draft")
	assertSecretAbsent(t, validation.Body.String(), validationSecret)
	if _, found, err := fixture.companyOIDC.Current(fixture.ctx); err != nil || found {
		t.Fatalf("validation failure persisted a Draft: found=%v err=%v", found, err)
	}

	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Initial IdP",
		Issuer:        "https://initial.example.test",
		ClientID:      "initial-client",
		ClientSecret:  "initial secret",
		Domains:       []string{"initial.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.companyOIDC.Edit(fixture.ctx, fixture.admin.User.ID, companyoidc.EditInput{
		ProviderLabel:    "Newer IdP",
		Issuer:           "https://newer.example.test",
		ClientID:         "newer-client",
		Domains:          []string{"newer.example"},
		ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	staleSecret := "stale replacement canary"
	staleForm := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "1", staleSecret)
	staleForm.Set("provider_label", "Stale IdP")
	conflict := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), staleForm, []string{companyOIDCWebPublicURL})
	assertStatusAndBodyContains(t, conflict, http.StatusConflict, "Draft changed before this save", "Reload the saved Draft", "No submitted client secret is retained")
	assertSecretAbsent(t, conflict.Body.String(), staleSecret)
	current, found, err := fixture.companyOIDC.Current(fixture.ctx)
	if err != nil || !found || current.Revision != 2 || current.ProviderLabel != "Newer IdP" {
		t.Fatalf("stale web save changed Draft: found=%v current=%+v err=%v", found, current, err)
	}

	failing := &recordingCompanyOIDCService{createErr: errors.New("database secret-canary raw failure")}
	server := NewServer(Config{
		AppName:                               "Thawguard",
		PublicURL:                             companyOIDCWebPublicURL,
		AuthService:                           fixture.authService,
		CompanyOIDCService:                    failing,
		CompanyOIDCSecretEncryptionConfigured: true,
	})
	internalSecret := "internal error secret canary"
	internalForm := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "0", internalSecret)
	internal := companyOIDCPOST(server, "/settings/authentication/oidc", fixture.adminCookie(), internalForm, []string{companyOIDCWebPublicURL})
	assertStatusAndBodyContains(t, internal, http.StatusInternalServerError, "Draft save result unconfirmed", "inspect the saved revision before retrying")
	assertSecretAbsent(t, internal.Body.String(), internalSecret)
	assertSecretAbsent(t, internal.Body.String(), "database secret-canary raw failure")
}

func TestAuthenticationEncryptionUnavailableKeepsSavedNonSecretDraftReadable(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Readable IdP",
		Issuer:        "https://readable.example.test",
		ClientID:      "readable-client",
		ClientSecret:  "stored secret canary",
		Domains:       []string{"readable.example"},
	}); err != nil {
		t.Fatal(err)
	}
	readOnlyService := companyoidc.NewService(fixture.database, nil)
	server := NewServer(Config{
		AppName:                               "Thawguard",
		PublicURL:                             companyOIDCWebPublicURL,
		AuthService:                           fixture.authService,
		CompanyOIDCService:                    readOnlyService,
		CompanyOIDCSecretEncryptionConfigured: false,
	})

	read := companyOIDCGET(server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, read, http.StatusOK, "Client-secret encryption unavailable", "Readable IdP", "readable-client", "Client secret stored")
	for _, control := range []string{"Edit draft", "Configure OIDC", `name="client_secret"`} {
		if strings.Contains(read.Body.String(), control) {
			t.Fatalf("encryption-unavailable state rendered %q", control)
		}
	}
	assertSecretAbsent(t, read.Body.String(), "stored secret canary")

	edit := companyOIDCGET(server, "/settings/authentication/edit", fixture.adminCookie())
	if edit.Code != http.StatusOK || strings.Contains(edit.Body.String(), "Save draft") || strings.Contains(edit.Body.String(), `name="client_secret"`) {
		t.Fatalf("unavailable edit route rendered controls: status=%d body=%q", edit.Code, edit.Body.String())
	}
	forgedSecret := "forged replacement secret"
	form := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "1", forgedSecret)
	forged := companyOIDCPOST(server, "/settings/authentication/oidc", fixture.adminCookie(), form, []string{companyOIDCWebPublicURL})
	if forged.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable forged POST returned %d", forged.Code)
	}
	assertSecretAbsent(t, forged.Body.String(), forgedSecret)
	current, found, err := readOnlyService.Current(fixture.ctx)
	if err != nil || !found || current.Revision != 1 {
		t.Fatalf("unavailable POST changed the Draft: found=%v current=%+v err=%v", found, current, err)
	}

	empty := newCompanyOIDCWebFixture(t, false)
	emptyRead := companyOIDCGET(empty.server, "/settings/authentication", empty.adminCookie())
	assertStatusAndBodyContains(t, emptyRead, http.StatusOK, "Client-secret encryption unavailable", "No company connection configured")
	if strings.Contains(emptyRead.Body.String(), "Configure OIDC") {
		t.Fatal("empty unavailable state rendered Configure OIDC")
	}
}

func TestAuthenticationSaveRequestBoundaryIsExact(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	recorderService := &recordingCompanyOIDCService{}
	fixture.server.cfg.CompanyOIDCService = recorderService
	valid := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "0", "request boundary secret")

	for _, tc := range []struct {
		name    string
		origins []string
	}{
		{name: "missing"},
		{name: "null", origins: []string{"null"}},
		{name: "mismatch", origins: []string{"https://attacker.example"}},
		{name: "duplicate", origins: []string{companyOIDCWebPublicURL, companyOIDCWebPublicURL}},
	} {
		t.Run("origin "+tc.name, func(t *testing.T) {
			recorderService.reset()
			got := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), valid, tc.origins)
			if got.Code != http.StatusForbidden || recorderService.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%q", got.Code, recorderService.calls, got.Body.String())
			}
			assertSecretAbsent(t, got.Body.String(), valid.Get("client_secret"))
		})
	}

	for _, token := range []string{"", "invalid"} {
		recorderService.reset()
		form := cloneValues(valid)
		form.Set(csrfFormField, token)
		got := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), form, []string{companyOIDCWebPublicURL})
		if got.Code != http.StatusForbidden || recorderService.calls != 0 {
			t.Fatalf("CSRF %q: status=%d calls=%d", token, got.Code, recorderService.calls)
		}
	}

	rejected := []struct {
		name string
		path string
		form url.Values
	}{
		{name: "query", path: "/settings/authentication/oidc?unexpected=1", form: cloneValues(valid)},
		{name: "unknown field", path: "/settings/authentication/oidc", form: withFormValue(valid, "unexpected", "value")},
		{name: "missing field", path: "/settings/authentication/oidc", form: withoutFormValue(valid, "client_id")},
		{name: "duplicate provider", path: "/settings/authentication/oidc", form: withDuplicateFormValue(valid, "provider_label", "second")},
		{name: "duplicate domains", path: "/settings/authentication/oidc", form: withDuplicateFormValue(valid, "allowed_domains", "second.example")},
		{name: "duplicate CSRF", path: "/settings/authentication/oidc", form: withDuplicateFormValue(valid, csrfFormField, fixture.admin.CSRFToken)},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			recorderService.reset()
			got := companyOIDCPOST(fixture.server, tc.path, fixture.adminCookie(), tc.form, []string{companyOIDCWebPublicURL})
			if got.Code != http.StatusBadRequest || recorderService.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%q", got.Code, recorderService.calls, got.Body.String())
			}
			assertSecretAbsent(t, got.Body.String(), valid.Get("client_secret"))
		})
	}

	for _, revision := range []string{"", "00", "01", "+1", "-1", " 1", "9223372036854775808"} {
		t.Run("revision "+revision, func(t *testing.T) {
			recorderService.reset()
			form := cloneValues(valid)
			form.Set("expected_revision", revision)
			got := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), form, []string{companyOIDCWebPublicURL})
			if got.Code != http.StatusBadRequest || recorderService.calls != 0 {
				t.Fatalf("status=%d calls=%d", got.Code, recorderService.calls)
			}
		})
	}

	oversized := cloneValues(valid)
	oversized.Set("allowed_domains", strings.Repeat("a", int(companyOIDCDraftMaxBodyBytes)))
	recorderService.reset()
	tooLarge := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), oversized, []string{companyOIDCWebPublicURL})
	if tooLarge.Code != http.StatusBadRequest || recorderService.calls != 0 {
		t.Fatalf("oversized body status=%d calls=%d", tooLarge.Code, recorderService.calls)
	}
	assertSecretAbsent(t, tooLarge.Body.String(), valid.Get("client_secret"))

	recorderService.reset()
	success := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), valid, []string{companyOIDCWebPublicURL})
	if success.Code != http.StatusSeeOther || recorderService.calls != 1 {
		t.Fatalf("valid request status=%d calls=%d", success.Code, recorderService.calls)
	}
}

func TestAuthenticationResponsesAlwaysCarrySensitiveHeaders(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	viewer := mustCreateWebUser(t, fixture.ctx, fixture.authService, "header-viewer@example.test", false)
	viewerSession, err := fixture.authService.Login(fixture.ctx, auth.LoginParams{Email: viewer.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	viewerCookie := &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}

	badForm := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "00", "header secret")
	badRequest := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), badForm, []string{companyOIDCWebPublicURL})

	failing := &recordingCompanyOIDCService{createErr: errors.New("failure")}
	fixture.server.cfg.CompanyOIDCService = failing
	internalForm := validCompanyOIDCWebForm(fixture.admin.CSRFToken, "0", "header internal secret")
	internal := companyOIDCPOST(fixture.server, "/settings/authentication/oidc", fixture.adminCookie(), internalForm, []string{companyOIDCWebPublicURL})

	method := httptest.NewRecorder()
	methodRequest := httptest.NewRequest(http.MethodPut, "/settings/authentication", nil)
	methodRequest.AddCookie(fixture.adminCookie())
	fixture.server.Routes().ServeHTTP(method, methodRequest)

	unknown := companyOIDCGET(fixture.server, "/settings/authentication/not-a-route", fixture.adminCookie())
	responses := map[string]*httptest.ResponseRecorder{
		"success":     companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie()),
		"redirect":    companyOIDCGET(fixture.server, "/settings/authentication", nil),
		"forbidden":   companyOIDCGET(fixture.server, "/settings/authentication", viewerCookie),
		"bad request": badRequest,
		"internal":    internal,
		"method":      method,
		"unknown":     unknown,
	}
	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			assertAuthenticationSecurityHeaders(t, response.Header())
		})
	}
}

func TestAuthenticationHasNoCheckRouteHTMXOrSignInControl(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	for _, path := range []string{"/settings/authentication", "/settings/authentication/edit"} {
		page := companyOIDCGET(fixture.server, path, fixture.adminCookie())
		if page.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d", path, page.Code)
		}
		assertNoCompanyOIDCCheckSurface(t, page.Body.String())
		for _, unsupported := range []string{"Test company sign-in", "Enable company sign-in", `href="/settings/authentication/oidc/check"`} {
			if strings.Contains(page.Body.String(), unsupported) {
				t.Fatalf("%s rendered unsupported control %q", path, unsupported)
			}
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/settings/authentication/oidc/check", nil)
		request.AddCookie(fixture.adminCookie())
		fixture.server.Routes().ServeHTTP(recorder, request)
		if recorder.Code < 400 {
			t.Fatalf("%s check route unexpectedly exists with status %d", method, recorder.Code)
		}
		assertAuthenticationSecurityHeaders(t, recorder.Header())
	}
}

func TestAuthenticationNavigationAndResponsiveSemanticStructure(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Responsive IdP",
		Issuer:        "https://responsive.example.test/tenant",
		ClientID:      "responsive-client",
		ClientSecret:  "responsive secret",
		Domains:       []string{"responsive.example"},
	}); err != nil {
		t.Fatal(err)
	}
	admin := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	body := admin.Body.String()
	for _, want := range []string{
		`href="/settings/authentication" aria-current="page"`,
		`<use href="#tg-i-key"></use>`,
		"Authentication",
		"sm:grid-cols-2",
		"lg:grid-cols-4",
		"min-w-0",
		"break-all",
		"bg-surface",
		"text-text",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Authentication page is missing %q", want)
		}
	}
	if strings.Contains(body, "style=") || strings.Contains(body, "#[0-9a-fA-F]") {
		t.Fatal("Authentication template bypassed semantic light/dark selectors")
	}

	viewerServer := NewServer(Config{AppName: "Thawguard"})
	viewer := getPageWithRoles(t, viewerServer, "/", auth.RoleSet{auth.RoleViewer})
	if strings.Contains(viewer.Body.String(), `href="/settings/authentication"`) {
		t.Fatal("non-Administrator navigation exposed Authentication")
	}
}

type companyOIDCWebFixture struct {
	ctx         context.Context
	database    *sql.DB
	authService *auth.Service
	companyOIDC *companyoidc.Service
	server      *Server
	admin       auth.Session
}

func newCompanyOIDCWebFixture(t *testing.T, encryptionAvailable bool) *companyOIDCWebFixture {
	t.Helper()
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	admin := mustSetupWebAdmin(t, ctx, authService)
	var secretStore secrets.Store
	if encryptionAvailable {
		configured, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x42}, 32))
		if err != nil {
			t.Fatal(err)
		}
		secretStore = configured
	}
	service := companyoidc.NewService(database, secretStore)
	server := NewServer(Config{
		AppName:                               "Thawguard",
		PublicURL:                             companyOIDCWebPublicURL,
		AuthService:                           authService,
		CompanyOIDCService:                    service,
		CompanyOIDCSecretEncryptionConfigured: encryptionAvailable,
	})
	return &companyOIDCWebFixture{
		ctx:         ctx,
		database:    database,
		authService: authService,
		companyOIDC: service,
		server:      server,
		admin:       admin,
	}
}

func (f *companyOIDCWebFixture) adminCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: f.admin.ID}
}

type recordingCompanyOIDCService struct {
	createErr error
	calls     int
}

func (s *recordingCompanyOIDCService) Current(context.Context) (companyoidc.Connection, bool, error) {
	return companyoidc.Connection{}, false, nil
}

func (s *recordingCompanyOIDCService) Create(context.Context, int64, companyoidc.CreateInput) error {
	s.calls++
	return s.createErr
}

func (s *recordingCompanyOIDCService) Edit(context.Context, int64, companyoidc.EditInput) error {
	s.calls++
	return nil
}

func (s *recordingCompanyOIDCService) reset() {
	s.calls = 0
}

func validCompanyOIDCWebForm(csrfToken, revision, secret string) url.Values {
	return url.Values{
		csrfFormField:       {csrfToken},
		"provider_label":    {"Example IdP"},
		"issuer":            {"https://id.example.test"},
		"client_id":         {"example-client"},
		"client_secret":     {secret},
		"allowed_domains":   {"example.test"},
		"expected_revision": {revision},
	}
}

func companyOIDCGET(server *Server, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func companyOIDCPOST(
	server *Server,
	path string,
	cookie *http.Cookie,
	form url.Values,
	origins []string,
) *httptest.ResponseRecorder {
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

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, fieldValues := range values {
		cloned[key] = append([]string(nil), fieldValues...)
	}
	return cloned
}

func withFormValue(values url.Values, key, value string) url.Values {
	cloned := cloneValues(values)
	cloned.Set(key, value)
	return cloned
}

func withoutFormValue(values url.Values, key string) url.Values {
	cloned := cloneValues(values)
	delete(cloned, key)
	return cloned
}

func withDuplicateFormValue(values url.Values, key, value string) url.Values {
	cloned := cloneValues(values)
	cloned.Add(key, value)
	return cloned
}

func assertStatusAndBodyContains(t *testing.T, recorder *httptest.ResponseRecorder, status int, values ...string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d, want %d, body=%q", recorder.Code, status, recorder.Body.String())
	}
	for _, value := range values {
		if !strings.Contains(recorder.Body.String(), value) {
			t.Fatalf("body is missing %q: %q", value, recorder.Body.String())
		}
	}
}

func assertSecretAbsent(t *testing.T, body, secret string) {
	t.Helper()
	if secret != "" && strings.Contains(body, secret) {
		t.Fatalf("response exposed secret %q", secret)
	}
}

func assertNoCompanyOIDCCheckSurface(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{"Check configuration", "/settings/authentication/oidc/check", "hx-get=", "hx-post=", "hx-target=", "hx-indicator="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Slice A rendered forbidden check or HTMX surface %q", forbidden)
		}
	}
}

func assertAuthenticationSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	want := map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "same-origin",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": sensitiveFormCSP,
	}
	for name, value := range want {
		if got := header.Get(name); got != value {
			t.Fatalf("%s = %q, want %q", name, got, value)
		}
	}
	if strings.Contains(header.Get("Content-Security-Policy"), "connect-src") {
		t.Fatal("Slice A CSP must not contain connect-src")
	}
}
