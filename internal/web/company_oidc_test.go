package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
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
	viewerCheck := companyOIDCCheckPOST(fixture.server, viewerCookie, url.Values{csrfFormField: {viewerSession.CSRFToken}}, []string{companyOIDCWebPublicURL}, false)
	if viewerCheck.Code != http.StatusForbidden || fixture.checker.calls != 0 {
		t.Fatalf("viewer check returned %d after %d checker calls", viewerCheck.Code, fixture.checker.calls)
	}
	viewerHXCheck := companyOIDCCheckPOST(fixture.server, viewerCookie, url.Values{csrfFormField: {viewerSession.CSRFToken}}, []string{companyOIDCWebPublicURL}, true)
	if viewerHXCheck.Code != http.StatusOK || viewerHXCheck.Header().Get("HX-Redirect") != companyOIDCNoticeLocation(companyOIDCCheckAuthorityNotice) || fixture.checker.calls != 0 {
		t.Fatalf("viewer HX check: status=%d redirect=%q calls=%d", viewerHXCheck.Code, viewerHXCheck.Header().Get("HX-Redirect"), fixture.checker.calls)
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
	forcedCheck := companyOIDCCheckPOST(fixture.server, forcedCookie, url.Values{csrfFormField: {forcedSession.CSRFToken}}, []string{companyOIDCWebPublicURL}, false)
	if forcedCheck.Code != http.StatusSeeOther || forcedCheck.Header().Get("Location") != "/account/password" || fixture.checker.calls != 0 {
		t.Fatalf("forced check: status=%d location=%q calls=%d", forcedCheck.Code, forcedCheck.Header().Get("Location"), fixture.checker.calls)
	}
	forcedHXCheck := companyOIDCCheckPOST(fixture.server, forcedCookie, url.Values{csrfFormField: {forcedSession.CSRFToken}}, []string{companyOIDCWebPublicURL}, true)
	if forcedHXCheck.Code != http.StatusOK || forcedHXCheck.Header().Get("HX-Redirect") != "/account/password" || fixture.checker.calls != 0 {
		t.Fatalf("forced HX check: status=%d redirect=%q calls=%d", forcedHXCheck.Code, forcedHXCheck.Header().Get("HX-Redirect"), fixture.checker.calls)
	}

	staleCookie := &http.Cookie{Name: sessionCookieName, Value: "stale-company-oidc-session"}
	staleForm := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	staleNative := companyOIDCCheckPOST(fixture.server, staleCookie, staleForm, []string{companyOIDCWebPublicURL}, false)
	if staleNative.Code != http.StatusForbidden || fixture.checker.calls != 0 {
		t.Fatalf("stale native check: status=%d calls=%d", staleNative.Code, fixture.checker.calls)
	}
	staleHX := companyOIDCCheckPOST(fixture.server, staleCookie, staleForm, []string{companyOIDCWebPublicURL}, true)
	if staleHX.Code != http.StatusOK || staleHX.Header().Get("HX-Redirect") != "/login" || fixture.checker.calls != 0 {
		t.Fatalf("stale HX check: status=%d redirect=%q calls=%d", staleHX.Code, staleHX.Header().Get("HX-Redirect"), fixture.checker.calls)
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
		"Available after save",
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
		"Metadata health reflects only the explicitly saved revision.",
		"Check configuration",
		"Never checked",
		"Public-key candidates published",
	)
	for _, editable := range []string{`name="provider_label"`, `name="issuer"`, `name="client_id"`, `name="client_secret"`, "Save draft"} {
		if strings.Contains(read.Body.String(), editable) {
			t.Fatalf("saved read state contains editable control %q", editable)
		}
	}
	assertSecretAbsent(t, read.Body.String(), secret)
	if strings.Count(read.Body.String(), "Check configuration") != 1 {
		t.Fatalf("saved read state did not render exactly one check control: %q", read.Body.String())
	}

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
	readOnlyService := companyoidc.NewService(fixture.database, nil, nil)
	server := NewServer(Config{
		AppName:                               "Thawguard",
		PublicURL:                             companyOIDCWebPublicURL,
		AuthService:                           fixture.authService,
		CompanyOIDCService:                    readOnlyService,
		CompanyOIDCSecretEncryptionConfigured: false,
	})

	read := companyOIDCGET(server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, read, http.StatusOK, "Client-secret encryption unavailable", "Readable IdP", "readable-client", "Client secret stored")
	for _, control := range []string{"Edit draft", "Configure OIDC", "Check configuration", "/settings/authentication/oidc/check", `name="client_secret"`} {
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
	forgedCheck := companyOIDCCheckPOST(
		server,
		fixture.adminCookie(),
		url.Values{csrfFormField: {fixture.admin.CSRFToken}},
		[]string{companyOIDCWebPublicURL},
		false,
	)
	if forgedCheck.Code != http.StatusSeeOther || forgedCheck.Header().Get("Location") != companyOIDCNoticeLocation(companyOIDCCheckUnavailableNotice) {
		t.Fatalf("unavailable forged check status=%d location=%q", forgedCheck.Code, forgedCheck.Header().Get("Location"))
	}
	current, found, err = readOnlyService.Current(fixture.ctx)
	if err != nil || !found || current.SetupCheck != nil {
		t.Fatalf("unavailable forged check changed evidence: found=%v current=%+v err=%v", found, current, err)
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

func TestAuthenticationCheckNativeAndHTMXFlowsRenderPersistedTruth(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Checked IdP",
		Issuer:        "https://issuer.example.test",
		ClientID:      "checked-client",
		ClientSecret:  "checked secret canary",
		Domains:       []string{"example.test"},
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	native := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, false)
	if native.Code != http.StatusSeeOther || native.Header().Get("Location") != "/settings/authentication" {
		t.Fatalf("native check status=%d location=%q body=%q", native.Code, native.Header().Get("Location"), native.Body.String())
	}
	if fixture.checker.calls != 1 || fixture.checker.issuer != "https://issuer.example.test" {
		t.Fatalf("checker calls=%d issuer=%q", fixture.checker.calls, fixture.checker.issuer)
	}
	verifiedPage := companyOIDCGET(fixture.server, native.Header().Get("Location"), fixture.adminCookie())
	assertStatusAndBodyContains(t, verifiedPage, http.StatusOK,
		"Discovery verified",
		"provider metadata and public-key candidates were read",
		"Supported public-key candidates published: 1.",
		"Company sign-in remains Draft",
		"Public-key candidates published",
		"Passed",
	)
	assertSecretAbsent(t, verifiedPage.Body.String(), "checked secret canary")

	fixture.checker.report = companyoidc.SetupCheckReport{ResultCode: companyoidc.SetupCheckJWKSInvalid}
	hx := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, true)
	if hx.Code != http.StatusOK || hx.Header().Get("HX-Redirect") != "/settings/authentication" {
		t.Fatalf("HX check status=%d redirect=%q body=%q", hx.Code, hx.Header().Get("HX-Redirect"), hx.Body.String())
	}
	if strings.Contains(hx.Body.String(), "oidc-setup-health") {
		t.Fatalf("HX check answered with a stale fragment: %q", hx.Body.String())
	}
	if vary := hx.Header().Values("Vary"); !containsString(vary, "HX-Request") {
		t.Fatalf("HX result Vary = %v", vary)
	}
	failedPage := companyOIDCGET(fixture.server, hx.Header().Get("HX-Redirect"), fixture.adminCookie())
	assertStatusAndBodyContains(t, failedPage, http.StatusOK,
		"Check failed",
		"advertised JWK Set was not a valid bounded JSON key set",
		"Discovery readable",
		"Issuer exact",
		"Required authorization-code metadata",
		"Public-key candidates published",
		"Failed",
	)

	observed := "https://issuer.example.test/"
	fixture.checker.report = companyoidc.SetupCheckReport{
		ResultCode:     companyoidc.SetupCheckIssuerMismatch,
		ObservedIssuer: &observed,
	}
	mismatchPost := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, false)
	if mismatchPost.Code != http.StatusSeeOther {
		t.Fatalf("mismatch POST returned %d", mismatchPost.Code)
	}
	mismatchPage := companyOIDCGET(fixture.server, mismatchPost.Header().Get("Location"), fixture.adminCookie())
	assertStatusAndBodyContains(t, mismatchPage, http.StatusOK,
		"published issuer did not exactly match the saved issuer",
		"Saved issuer",
		"Published issuer",
		`https://issuer.example.test<span class="oidc-issuer-trailing-slash">/</span>`,
	)
	for _, forbidden := range []string{"credentials were verified", "signatures were verified", "claims were verified", "client registration was verified", "sign-in was verified"} {
		if strings.Contains(strings.ToLower(mismatchPage.Body.String()), forbidden) {
			t.Fatalf("metadata UI made unsupported claim %q", forbidden)
		}
	}
}

func TestAuthenticationCheckRequestBoundaryIsExactAndBounded(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Boundary IdP",
		Issuer:        "https://boundary.example.test",
		ClientID:      "boundary-client",
		ClientSecret:  "boundary secret",
		Domains:       []string{"boundary.example"},
	}); err != nil {
		t.Fatal(err)
	}
	valid := url.Values{csrfFormField: {fixture.admin.CSRFToken}}

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
			before := fixture.checker.calls
			response := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), valid, tc.origins, false)
			if response.Code != http.StatusForbidden || fixture.checker.calls != before {
				t.Fatalf("status=%d checker calls=%d before=%d", response.Code, fixture.checker.calls, before)
			}
			assertAuthenticationSecurityHeaders(t, response.Header())
		})
	}

	missingCSRF := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), url.Values{}, []string{companyOIDCWebPublicURL}, false)
	if missingCSRF.Code != http.StatusForbidden || fixture.checker.calls != 0 {
		t.Fatalf("missing CSRF status=%d calls=%d", missingCSRF.Code, fixture.checker.calls)
	}
	badCSRF := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), url.Values{csrfFormField: {"invalid"}}, []string{companyOIDCWebPublicURL}, false)
	if badCSRF.Code != http.StatusForbidden || fixture.checker.calls != 0 {
		t.Fatalf("bad CSRF status=%d calls=%d", badCSRF.Code, fixture.checker.calls)
	}

	rejected := []struct {
		name string
		path string
		form url.Values
	}{
		{name: "query", path: "/settings/authentication/oidc/check?repeat=1", form: cloneValues(valid)},
		{name: "empty query", path: "/settings/authentication/oidc/check?", form: cloneValues(valid)},
		{name: "unknown field", path: "/settings/authentication/oidc/check", form: withFormValue(valid, "issuer", "https://unsaved.example.test")},
		{name: "duplicate CSRF", path: "/settings/authentication/oidc/check", form: withDuplicateFormValue(valid, csrfFormField, fixture.admin.CSRFToken)},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			before := fixture.checker.calls
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", companyOIDCWebPublicURL)
			request.AddCookie(fixture.adminCookie())
			fixture.server.Routes().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || fixture.checker.calls != before {
				t.Fatalf("status=%d calls=%d before=%d body=%q", recorder.Code, fixture.checker.calls, before, recorder.Body.String())
			}
		})
	}

	oversized := cloneValues(valid)
	oversized.Set("unexpected", strings.Repeat("a", int(companyOIDCCheckMaxBodyBytes)))
	tooLarge := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), oversized, []string{companyOIDCWebPublicURL}, false)
	if tooLarge.Code != http.StatusBadRequest || fixture.checker.calls != 0 {
		t.Fatalf("oversized status=%d calls=%d", tooLarge.Code, fixture.checker.calls)
	}

	success := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), valid, []string{companyOIDCWebPublicURL}, false)
	if success.Code != http.StatusSeeOther || fixture.checker.calls != 1 || fixture.checker.issuer != "https://boundary.example.test" {
		t.Fatalf("valid check status=%d calls=%d issuer=%q", success.Code, fixture.checker.calls, fixture.checker.issuer)
	}
}

func TestAuthenticationCheckFailuresRedirectWithoutRepeatableOrSensitivePOSTBodies(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	tests := []struct {
		name   string
		err    error
		notice string
	}{
		{name: "stale revision", err: companyoidc.ErrCheckStale, notice: companyOIDCCheckStaleNotice},
		{name: "missing Draft", err: companyoidc.ErrNoDraft, notice: companyOIDCCheckStaleNotice},
		{name: "encryption unavailable", err: companyoidc.ErrConfiguration, notice: companyOIDCCheckUnavailableNotice},
		{name: "authority changed", err: companyoidc.ErrAuthorization, notice: companyOIDCCheckAuthorityNotice},
		{name: "unknown commit outcome", err: companyoidc.ErrCheckOutcomeUnknown, notice: companyOIDCCheckUnknownNotice},
		{name: "internal", err: errors.New("raw database and provider canary"), notice: companyOIDCCheckUnknownNotice},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &recordingCompanyOIDCService{checkErr: tc.err}
			fixture.server.cfg.CompanyOIDCService = service
			wantLocation := companyOIDCNoticeLocation(tc.notice)
			for _, hx := range []bool{false, true} {
				response := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, hx)
				if hx {
					if response.Code != http.StatusOK || response.Header().Get("HX-Redirect") != wantLocation {
						t.Fatalf("HX status=%d redirect=%q", response.Code, response.Header().Get("HX-Redirect"))
					}
				} else if response.Code != http.StatusSeeOther || response.Header().Get("Location") != wantLocation {
					t.Fatalf("native status=%d location=%q", response.Code, response.Header().Get("Location"))
				}
				if strings.Contains(response.Body.String(), "raw database") || response.Code == http.StatusInternalServerError {
					t.Fatalf("check failure exposed an unswappable internal body: %q", response.Body.String())
				}
				if vary := response.Header().Values("Vary"); !containsString(vary, "HX-Request") {
					t.Fatalf("failure Vary = %v", vary)
				}
			}
			if service.checkCalls != 2 {
				t.Fatalf("service check calls = %d, want 2", service.checkCalls)
			}
		})
	}

	fixture.server.cfg.CompanyOIDCService = &recordingCompanyOIDCService{checkErr: errors.New("raw database and provider canary")}
	redirect := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, false)
	noticePage := companyOIDCGET(fixture.server, redirect.Header().Get("Location"), fixture.adminCookie())
	assertStatusAndBodyContains(t, noticePage, http.StatusOK, "could not confirm whether a current check was recorded")
	if strings.Contains(noticePage.Body.String(), "raw database and provider canary") {
		t.Fatal("sanitized GET notice exposed the internal error")
	}
}

func TestAuthenticationCheckSessionLookupFailureUsesSanitizedRedirect(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	want := companyOIDCNoticeLocation(companyOIDCCheckUnknownNotice)
	for _, hx := range []bool{false, true} {
		response := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, hx)
		if hx {
			if response.Code != http.StatusOK || response.Header().Get("HX-Redirect") != want {
				t.Fatalf("HX session failure status=%d redirect=%q", response.Code, response.Header().Get("HX-Redirect"))
			}
		} else if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want {
			t.Fatalf("native session failure status=%d location=%q", response.Code, response.Header().Get("Location"))
		}
		if response.Code == http.StatusInternalServerError || strings.Contains(response.Body.String(), "database") {
			t.Fatalf("session failure exposed an internal response: %q", response.Body.String())
		}
	}
}

func TestAuthenticationCheckHXDemotedAdministratorGetsVisibleAuthorityRedirect(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	secondAdmin := mustCreateWebUser(t, fixture.ctx, fixture.authService, "second-oidc-admin@example.test", true)
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Demotion IdP",
		Issuer:        "https://demotion.example.test",
		ClientID:      "demotion-client",
		ClientSecret:  "demotion secret",
		Domains:       []string{"demotion.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.authService.SetUserAdmin(fixture.ctx, auth.SetUserAdminParams{
		ActorUserID: secondAdmin.ID,
		UserID:      fixture.admin.User.ID,
		Admin:       false,
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	hx := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, true)
	wantRedirect := companyOIDCNoticeLocation(companyOIDCCheckAuthorityNotice)
	if hx.Code != http.StatusOK || hx.Header().Get("HX-Redirect") != wantRedirect {
		t.Fatalf("demoted HX check: status=%d redirect=%q want=%q", hx.Code, hx.Header().Get("HX-Redirect"), wantRedirect)
	}
	if fixture.checker.calls != 0 {
		t.Fatalf("demoted HX check made %d checker calls", fixture.checker.calls)
	}

	native := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, false)
	if native.Code != http.StatusForbidden {
		t.Fatalf("demoted native check returned %d", native.Code)
	}
	if fixture.checker.calls != 0 {
		t.Fatalf("demoted native check made %d checker calls", fixture.checker.calls)
	}

	var evidenceCount, auditCount int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM company_oidc_setup_checks`).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.QueryRow(
		`SELECT count(*) FROM audit_events WHERE action = ?`,
		audit.ActionOIDCConnectionMetadataChecked,
	).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 0 || auditCount != 0 {
		t.Fatalf("demoted checks wrote evidence=%d metadata audits=%d", evidenceCount, auditCount)
	}
}

func TestAuthenticationCheckHXSuccessRedirectsAndFollowupRendersLatestTruth(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	checkedAt := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	one := int64(1)
	completed := companyoidc.SetupCheck{
		ConfigRevision:          1,
		ResultCode:              companyoidc.SetupCheckVerified,
		PublicKeyCandidateCount: &one,
		CheckedAt:               checkedAt,
	}
	newer := companyoidc.SetupCheck{
		ConfigRevision: 1,
		ResultCode:     companyoidc.SetupCheckJWKSInvalid,
		CheckedAt:      checkedAt.Add(time.Second),
	}
	service := &recordingCompanyOIDCService{
		checkResult: completed,
		current: companyoidc.Connection{
			Issuer:     "https://id.example.test",
			Revision:   1,
			SetupCheck: &newer,
		},
		currentFound: true,
	}
	fixture.server.cfg.CompanyOIDCService = service
	response := companyOIDCCheckPOST(
		fixture.server,
		fixture.adminCookie(),
		url.Values{csrfFormField: {fixture.admin.CSRFToken}},
		[]string{companyOIDCWebPublicURL},
		true,
	)
	if response.Code != http.StatusOK || response.Header().Get("HX-Redirect") != "/settings/authentication" {
		t.Fatalf("HX check status=%d redirect=%q body=%q", response.Code, response.Header().Get("HX-Redirect"), response.Body.String())
	}
	if strings.Contains(response.Body.String(), "oidc-setup-health") {
		t.Fatalf("HX check answered with a stale fragment: %q", response.Body.String())
	}
	followup := companyOIDCGET(fixture.server, response.Header().Get("HX-Redirect"), fixture.adminCookie())
	assertStatusAndBodyContains(t, followup, http.StatusOK, "Check failed", "advertised JWK Set was not a valid bounded JSON key set")
	if strings.Contains(followup.Body.String(), "Discovery verified") {
		t.Fatalf("followup page did not render the latest same-revision evidence: %q", followup.Body.String())
	}
}

func TestAuthenticationEditClearsDisplayedCheckToNeverCheckedSinceSave(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Editable IdP",
		Issuer:        "https://editable.example.test",
		ClientID:      "editable-client",
		ClientSecret:  "editable secret",
		Domains:       []string{"editable.example"},
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}}
	if response := companyOIDCCheckPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, false); response.Code != http.StatusSeeOther {
		t.Fatalf("initial check returned %d", response.Code)
	}
	if err := fixture.companyOIDC.Edit(fixture.ctx, fixture.admin.User.ID, companyoidc.EditInput{
		ProviderLabel:    "Edited IdP",
		Issuer:           "https://editable.example.test",
		ClientID:         "editable-client",
		Domains:          []string{"editable.example"},
		ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	page := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, page, http.StatusOK, "Never checked since last saved edit", "saved revision has no current check result")
	if strings.Contains(page.Body.String(), "Discovery verified") {
		t.Fatal("edited Draft retained the previous verified claim")
	}
}

func TestCompanyOIDCNoEvidenceCopyDoesNotInventAPreviousCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		revision int64
	}{
		{name: "edited before first check", revision: 2},
		{name: "upgraded Slice A Draft", revision: 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := companyOIDCSetupHealth(companyoidc.Connection{Revision: tc.revision})
			if view.Heading != "Never checked since last saved edit" || !strings.Contains(view.Summary, "has no current check result") {
				t.Fatalf("no-evidence view = %+v", view)
			}
			if strings.Contains(strings.ToLower(view.Summary), "previous result") || strings.Contains(strings.ToLower(view.Summary), "cleared") {
				t.Fatalf("no-evidence copy invented prior evidence: %q", view.Summary)
			}
		})
	}
}

func TestCompanyOIDCSetupHealthMapsEveryFixedResultToAllowlistedCopy(t *testing.T) {
	checkedAt := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	countOne := int64(1)
	countZero := int64(0)
	observed := "https://other.example.test/"
	tests := []struct {
		code       companyoidc.SetupCheckResultCode
		observed   *string
		candidates *int64
		copy       string
	}{
		{code: companyoidc.SetupCheckVerified, candidates: &countOne, copy: "provider metadata and public-key candidates were read"},
		{code: companyoidc.SetupCheckDiscoveryUnavailable, copy: "discovery document was not available"},
		{code: companyoidc.SetupCheckDiscoveryInvalid, copy: "discovery response was not a bounded JSON object"},
		{code: companyoidc.SetupCheckIssuerInvalid, copy: "published an invalid issuer"},
		{code: companyoidc.SetupCheckIssuerMismatch, observed: &observed, copy: "did not exactly match"},
		{code: companyoidc.SetupCheckMetadataIncompatible, copy: "required authorization-code metadata"},
		{code: companyoidc.SetupCheckJWKSUnavailable, copy: "JWK Set was not available"},
		{code: companyoidc.SetupCheckJWKSInvalid, copy: "JWK Set was not a valid bounded JSON key set"},
		{code: companyoidc.SetupCheckJWKSNoCandidate, candidates: &countZero, copy: "did not publish a supported RSA public-key candidate"},
	}
	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			view := companyOIDCSetupHealth(companyoidc.Connection{
				Issuer:   "https://id.example.test",
				Revision: 3,
				SetupCheck: &companyoidc.SetupCheck{
					ConfigRevision:          3,
					ResultCode:              tc.code,
					ObservedIssuer:          tc.observed,
					PublicKeyCandidateCount: tc.candidates,
					CheckedAt:               checkedAt,
				},
			})
			if !strings.Contains(view.Summary, tc.copy) || view.CheckedAt != "2026-07-28 15:00:00 UTC" {
				t.Fatalf("view for %s = %+v", tc.code, view)
			}
			for i, row := range companyoidc.SetupCheckRows(&companyoidc.SetupCheck{ResultCode: tc.code}) {
				want := "Not checked"
				if row.State == companyoidc.SetupCheckRowPassed {
					want = "Passed"
				} else if row.State == companyoidc.SetupCheckRowFailed {
					want = "Failed"
				}
				if view.Rows[i].Status != want {
					t.Fatalf("row %d status = %q, want %q", i, view.Rows[i].Status, want)
				}
			}
		})
	}
}

func TestAuthenticationCheckExistsOnlyOnSavedReadStateAndFutureStepsStayInert(t *testing.T) {
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
	if err := fixture.companyOIDC.Create(fixture.ctx, fixture.admin.User.ID, companyoidc.CreateInput{
		ProviderLabel: "Saved IdP",
		Issuer:        "https://saved.example.test",
		ClientID:      "saved-client",
		ClientSecret:  "saved secret",
		Domains:       []string{"saved.example"},
	}); err != nil {
		t.Fatal(err)
	}
	saved := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	body := saved.Body.String()
	for _, want := range []string{
		`action="/settings/authentication/oidc/check"`,
		`hx-post="/settings/authentication/oidc/check"`,
		`hx-indicator="#oidc-setup-health"`,
		`hx-disabled-elt="find button"`,
		"Check configuration",
		"Test sign-in",
		"Enable",
		"Not implemented",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("saved state is missing %q", want)
		}
	}
	if strings.Count(body, "Check configuration") != 1 {
		t.Fatalf("saved state rendered duplicate check controls: %q", body)
	}
	if strings.Contains(body, "hx-target=") || strings.Contains(body, "hx-swap=") {
		t.Fatal("check form still targets an in-page fragment instead of redirecting")
	}
	for _, label := range []string{"Test sign-in", "Enable"} {
		position := strings.Index(body, label)
		if position < 0 {
			t.Fatalf("missing future step %q", label)
		}
		start := strings.LastIndex(body[:position], "<li")
		endOffset := strings.Index(body[position:], "</li>")
		if start < 0 || endOffset < 0 {
			t.Fatalf("could not isolate future step %q", label)
		}
		item := body[start : position+endOffset]
		if strings.Contains(item, "<a ") || strings.Contains(item, "<button") || strings.Contains(item, "tabindex=") || !strings.Contains(item, `aria-disabled="true"`) {
			t.Fatalf("future step %q is focusable or active: %s", label, item)
		}
	}

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/settings/authentication/oidc/check", nil)
		request.AddCookie(fixture.adminCookie())
		fixture.server.Routes().ServeHTTP(recorder, request)
		if recorder.Code < 400 {
			t.Fatalf("%s check route returned %d", method, recorder.Code)
		}
		assertAuthenticationSecurityHeaders(t, recorder.Header())
	}
}

func TestCompanyOIDCTestStartUsesPlainExternalRedirectAndExactInput(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	service := &recordingCompanyOIDCService{startResult: companyoidc.TestSignInStart{
		AuthorizationURL: "https://id.example.test/authorize?request=exact",
	}}
	fixture.server.cfg.CompanyOIDCService = service
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"7"}}

	for _, hx := range []bool{false, true} {
		service.reset()
		response := companyOIDCTestPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, hx)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != service.startResult.AuthorizationURL {
			t.Fatalf("start redirect: status=%d location=%q", response.Code, response.Header().Get("Location"))
		}
		if response.Header().Get("HX-Redirect") != "" || service.startCalls != 1 {
			t.Fatalf("Test sign-in unexpectedly used an HTMX redirect: headers=%v calls=%d", response.Header(), service.startCalls)
		}
		want := companyoidc.TestSignInStartInput{
			ActorUserID:      fixture.admin.User.ID,
			SessionID:        fixture.admin.ID,
			ExpectedRevision: 7,
			CallbackURI:      companyOIDCWebPublicURL + companyoidc.TestSignInCallbackPath,
		}
		if service.startInput != want {
			t.Fatalf("start input = %#v, want %#v", service.startInput, want)
		}
		assertAuthenticationSecurityHeaders(t, response.Header())
	}
}

func TestCompanyOIDCTestStartEnforcesFormAndAdministratorGates(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	service := &recordingCompanyOIDCService{startResult: companyoidc.TestSignInStart{AuthorizationURL: "https://id.example.test/authorize"}}
	fixture.server.cfg.CompanyOIDCService = service
	valid := url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"1"}}

	tests := []struct {
		name    string
		path    string
		form    url.Values
		origins []string
		status  int
	}{
		{name: "missing origin", path: "/settings/authentication/oidc/test", form: valid, status: http.StatusForbidden},
		{name: "wrong origin", path: "/settings/authentication/oidc/test", form: valid, origins: []string{"https://other.example.test"}, status: http.StatusForbidden},
		{name: "duplicate origin", path: "/settings/authentication/oidc/test", form: valid, origins: []string{companyOIDCWebPublicURL, companyOIDCWebPublicURL}, status: http.StatusForbidden},
		{name: "query forbidden", path: "/settings/authentication/oidc/test?extension=1", form: valid, origins: []string{companyOIDCWebPublicURL}, status: http.StatusBadRequest},
		{name: "bad csrf", path: "/settings/authentication/oidc/test", form: url.Values{csrfFormField: {"wrong"}, "expected_revision": {"1"}}, origins: []string{companyOIDCWebPublicURL}, status: http.StatusForbidden},
		{name: "missing revision", path: "/settings/authentication/oidc/test", form: url.Values{csrfFormField: {fixture.admin.CSRFToken}}, origins: []string{companyOIDCWebPublicURL}, status: http.StatusBadRequest},
		{name: "zero revision", path: "/settings/authentication/oidc/test", form: url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"0"}}, origins: []string{companyOIDCWebPublicURL}, status: http.StatusBadRequest},
		{name: "noncanonical revision", path: "/settings/authentication/oidc/test", form: url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"01"}}, origins: []string{companyOIDCWebPublicURL}, status: http.StatusBadRequest},
		{name: "duplicate revision", path: "/settings/authentication/oidc/test", form: url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"1", "2"}}, origins: []string{companyOIDCWebPublicURL}, status: http.StatusBadRequest},
		{name: "unknown field", path: "/settings/authentication/oidc/test", form: url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"1"}, "code": {"canary"}}, origins: []string{companyOIDCWebPublicURL}, status: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service.reset()
			response := companyOIDCPOST(fixture.server, tc.path, fixture.adminCookie(), tc.form, tc.origins)
			if response.Code != tc.status || service.startCalls != 0 {
				t.Fatalf("status=%d calls=%d, want status=%d calls=0", response.Code, service.startCalls, tc.status)
			}
			assertAuthenticationSecurityHeaders(t, response.Header())
		})
	}

	service.reset()
	oversized := url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {strings.Repeat("1", int(companyOIDCTestMaxBodyBytes))}}
	if response := companyOIDCPOST(fixture.server, "/settings/authentication/oidc/test", fixture.adminCookie(), oversized, []string{companyOIDCWebPublicURL}); response.Code != http.StatusBadRequest || service.startCalls != 0 {
		t.Fatalf("oversized body: status=%d calls=%d", response.Code, service.startCalls)
	}

	service.reset()
	if response := companyOIDCPOST(fixture.server, "/settings/authentication/oidc/test", nil, valid, []string{companyOIDCWebPublicURL}); response.Code != http.StatusForbidden || response.Header().Get("Location") != "" || service.startCalls != 0 {
		t.Fatalf("signed-out start: status=%d location=%q calls=%d", response.Code, response.Header().Get("Location"), service.startCalls)
	}

	viewer := mustCreateWebUser(t, fixture.ctx, fixture.authService, "test-sign-in-viewer@example.test", false)
	viewerSession, err := fixture.authService.Login(fixture.ctx, auth.LoginParams{Email: viewer.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	service.reset()
	viewerForm := url.Values{csrfFormField: {viewerSession.CSRFToken}, "expected_revision": {"1"}}
	if response := companyOIDCPOST(fixture.server, "/settings/authentication/oidc/test", &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}, viewerForm, []string{companyOIDCWebPublicURL}); response.Code != http.StatusForbidden || service.startCalls != 0 {
		t.Fatalf("viewer start: status=%d calls=%d", response.Code, service.startCalls)
	}

	forced := mustCreateWebUser(t, fixture.ctx, fixture.authService, "test-sign-in-forced@example.test", true)
	forcedSession, err := fixture.authService.Login(fixture.ctx, auth.LoginParams{Email: forced.Email, Password: accountWebTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, forced.ID); err != nil {
		t.Fatal(err)
	}
	service.reset()
	forcedForm := url.Values{csrfFormField: {forcedSession.CSRFToken}, "expected_revision": {"1"}}
	response := companyOIDCPOST(fixture.server, "/settings/authentication/oidc/test", &http.Cookie{Name: sessionCookieName, Value: forcedSession.ID}, forcedForm, []string{companyOIDCWebPublicURL})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account/password" || service.startCalls != 0 {
		t.Fatalf("forced-password start: status=%d location=%q calls=%d", response.Code, response.Header().Get("Location"), service.startCalls)
	}
}

func TestCompanyOIDCTestStartMapsOnlyStableNotices(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	form := url.Values{csrfFormField: {fixture.admin.CSRFToken}, "expected_revision": {"1"}}
	tests := []struct {
		name   string
		err    error
		notice string
	}{
		{name: "configuration", err: companyoidc.ErrConfiguration, notice: companyOIDCTestConfigurationNotice},
		{name: "provider unavailable", err: companyoidc.ErrTestProviderUnavailable, notice: companyOIDCTestProviderUnavailable},
		{name: "provider invalid", err: companyoidc.ErrTestProviderInvalid, notice: companyOIDCTestProviderInvalid},
		{name: "transaction", err: companyoidc.ErrTestSignInUnavailable, notice: companyOIDCTestTransactionNotice},
		{name: "unknown outcome", err: companyoidc.ErrTestTransactionOutcomeUnknown, notice: companyOIDCTestUnknownNotice},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &recordingCompanyOIDCService{startErr: tc.err}
			fixture.server.cfg.CompanyOIDCService = service
			response := companyOIDCTestPOST(fixture.server, fixture.adminCookie(), form, []string{companyOIDCWebPublicURL}, false)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != companyOIDCNoticeLocation(tc.notice) || service.startCalls != 1 {
				t.Fatalf("status=%d location=%q calls=%d", response.Code, response.Header().Get("Location"), service.startCalls)
			}
		})
	}
}

func TestCompanyOIDCTestCallbackClaimsAfterOnlyStateAndBindingExtraction(t *testing.T) {
	const state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	queries := []string{
		"state=" + state + "&code=one",
		"state=" + state,
		"state=" + state + "&code=one&error=access_denied",
		"state=" + state + "&code=one&code=two",
		"state=" + state + "&error=one&error=two",
		"state=" + state + "&code=%ZZ",
		"state=" + state + "&code=one&extension=first&extension=second",
	}
	cookieCases := []struct {
		name      string
		cookies   []*http.Cookie
		wantValue string
	}{
		{name: "exact", cookies: []*http.Cookie{{Name: sessionCookieName, Value: "session-exact"}}, wantValue: "session-exact"},
		{name: "missing"},
		{name: "empty", cookies: []*http.Cookie{{Name: sessionCookieName, Value: ""}}},
		{name: "duplicate", cookies: []*http.Cookie{{Name: sessionCookieName, Value: "one"}, {Name: sessionCookieName, Value: "two"}}},
	}
	for _, query := range queries {
		for _, cookieCase := range cookieCases {
			t.Run(cookieCase.name+"/"+url.QueryEscape(query), func(t *testing.T) {
				service := &recordingCompanyOIDCService{callbackResult: companyoidc.TestSignInProviderInvalid}
				server := NewServer(Config{AppName: "Thawguard", PublicURL: companyOIDCWebPublicURL, CompanyOIDCService: service})
				request := httptest.NewRequest(http.MethodGet, companyoidc.TestSignInCallbackPath, nil)
				request.URL.RawQuery = query
				for _, cookie := range cookieCase.cookies {
					request.AddCookie(cookie)
				}
				response := httptest.NewRecorder()
				server.Routes().ServeHTTP(response, request)
				if service.callbackCalls != 1 || service.callbackInput.State != state || service.callbackInput.SessionID != cookieCase.wantValue || service.callbackInput.RawQuery != query {
					t.Fatalf("callback was not passed intact to claim service: calls=%d input=%#v", service.callbackCalls, service.callbackInput)
				}
				if response.Code != http.StatusSeeOther || response.Header().Get("Location") != companyOIDCNoticeLocation(companyOIDCTestProviderInvalid) {
					t.Fatalf("callback redirect: status=%d location=%q", response.Code, response.Header().Get("Location"))
				}
				assertAuthenticationSecurityHeaders(t, response.Header())
			})
		}
	}
}

func TestCompanyOIDCTestCallbackRejectsHEADBeforeClaim(t *testing.T) {
	const state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	service := &recordingCompanyOIDCService{callbackResult: companyoidc.TestSignInVerified}
	server := NewServer(Config{AppName: "Thawguard", PublicURL: companyOIDCWebPublicURL, CompanyOIDCService: service})
	request := httptest.NewRequest(http.MethodHead, companyoidc.TestSignInCallbackPath+"?state="+state+"&code=one", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-canary"})
	response := httptest.NewRecorder()

	server.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("HEAD callback: status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
	if response.Header().Get("Location") != "" || service.callbackCalls != 0 {
		t.Fatalf("HEAD callback redirected or reached service: location=%q calls=%d", response.Header().Get("Location"), service.callbackCalls)
	}
	assertAuthenticationSecurityHeaders(t, response.Header())
}

func TestCompanyOIDCTestCallbackRejectsInvalidStateBeforeClaim(t *testing.T) {
	const state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		name  string
		query string
	}{
		{name: "missing", query: "code=canary"},
		{name: "empty", query: "state=&code=canary"},
		{name: "noncanonical", query: "state=short&code=canary"},
		{name: "duplicate", query: "state=" + state + "&state=" + state + "&code=canary"},
		{name: "malformed state", query: "state=%ZZ&code=canary"},
		{name: "oversized", query: "state=" + state + "&extension=" + strings.Repeat("x", 8<<10)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &recordingCompanyOIDCService{}
			server := NewServer(Config{AppName: "Thawguard", PublicURL: companyOIDCWebPublicURL, CompanyOIDCService: service})
			request := httptest.NewRequest(http.MethodGet, companyoidc.TestSignInCallbackPath, nil)
			request.URL.RawQuery = tc.query
			response := httptest.NewRecorder()
			server.Routes().ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != companyOIDCNoticeLocation(companyOIDCTestTransactionNotice) || service.callbackCalls != 0 {
				t.Fatalf("status=%d location=%q calls=%d", response.Code, response.Header().Get("Location"), service.callbackCalls)
			}
		})
	}
}

func TestCompanyOIDCTestCallbackUsesCleanPRGAndStableResultNotices(t *testing.T) {
	const state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		result companyoidc.TestSignInResultCode
		err    error
		notice string
	}{
		{result: companyoidc.TestSignInVerified, notice: companyOIDCTestVerifiedNotice},
		{result: companyoidc.TestSignInProviderDenied, notice: companyOIDCTestProviderDeniedNotice},
		{result: companyoidc.TestSignInProviderUnavailable, notice: companyOIDCTestProviderUnavailable},
		{result: companyoidc.TestSignInProviderInvalid, notice: companyOIDCTestProviderInvalid},
		{result: companyoidc.TestSignInConfigurationUnavailable, notice: companyOIDCTestConfigurationNotice},
		{err: companyoidc.ErrTestSignInUnavailable, notice: companyOIDCTestTransactionNotice},
		{err: companyoidc.ErrTestTransactionOutcomeUnknown, notice: companyOIDCTestUnknownNotice},
	}
	for _, tc := range tests {
		service := &recordingCompanyOIDCService{callbackResult: tc.result, callbackErr: tc.err}
		var logs bytes.Buffer
		server := NewServer(Config{
			AppName:            "Thawguard",
			PublicURL:          companyOIDCWebPublicURL,
			CompanyOIDCService: service,
			Logger:             slog.New(slog.NewTextHandler(&logs, nil)),
		})
		query := "state=" + state + "&code=code-canary&provider_extension=raw-query-canary"
		request := httptest.NewRequest(http.MethodGet, companyoidc.TestSignInCallbackPath, nil)
		request.URL.RawQuery = query
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-canary"})
		response := httptest.NewRecorder()
		server.Routes().ServeHTTP(response, request)
		location := companyOIDCNoticeLocation(tc.notice)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != location || service.callbackCalls != 1 {
			t.Fatalf("result=%q err=%v status=%d location=%q calls=%d", tc.result, tc.err, response.Code, response.Header().Get("Location"), service.callbackCalls)
		}
		visible := response.Body.String() + response.Header().Get("Location") + logs.String()
		for _, canary := range []string{state, "code-canary", "raw-query-canary", "session-canary"} {
			if strings.Contains(visible, canary) {
				t.Fatalf("callback PRG or log exposed %q: %q", canary, visible)
			}
		}
	}
}

func TestCompanyOIDCTestRoutesCarryAuthenticationSecurityHeaders(t *testing.T) {
	const state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	service := &recordingCompanyOIDCService{callbackResult: companyoidc.TestSignInVerified}
	server := NewServer(Config{AppName: "Thawguard", PublicURL: companyOIDCWebPublicURL, CompanyOIDCService: service})
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, companyoidc.TestSignInCallbackPath+"?state="+state+"&code=one", nil),
		httptest.NewRequest(http.MethodGet, companyoidc.TestSignInCallbackPath+"?state=bad", nil),
		httptest.NewRequest(http.MethodGet, "/settings/authentication/not-found", nil),
		httptest.NewRequest(http.MethodGet, "/settings/authentication/oidc/test", nil),
		httptest.NewRequest(http.MethodPost, companyoidc.TestSignInCallbackPath, nil),
	}
	for _, request := range requests {
		response := httptest.NewRecorder()
		server.Routes().ServeHTTP(response, request)
		assertAuthenticationSecurityHeaders(t, response.Header())
	}
}

func TestAuthenticationRendersExactCallbackAndOnlyEnablesCurrentVerifiedDraft(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	verified := companyoidc.Connection{
		ProviderLabel: "Verified IdP",
		Issuer:        "https://id.example.test",
		ClientID:      "client",
		Domains:       []string{"example.test"},
		Revision:      4,
		SetupCheck: &companyoidc.SetupCheck{
			ConfigRevision: 4,
			ResultCode:     companyoidc.SetupCheckVerified,
			CheckedAt:      time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		},
	}
	service := &recordingCompanyOIDCService{current: verified, currentFound: true}
	fixture.server.cfg.CompanyOIDCService = service
	response := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, response, http.StatusOK,
		companyOIDCWebPublicURL+companyoidc.TestSignInCallbackPath,
		"Register this exact URI with the provider",
		"requests only the <code>openid email</code> scopes",
		`method="post" action="/settings/authentication/oidc/test"`,
		`name="expected_revision" value="4"`,
		"a signed, verified email in a saved allowed domain",
		"This creates no identity, user, or Thawguard session and does not enable the connection",
	)
	body := response.Body.String()
	formStart := strings.Index(body, `<form method="post" action="/settings/authentication/oidc/test"`)
	if formStart < 0 {
		t.Fatal("Test sign-in form was not rendered")
	}
	formEnd := strings.Index(body[formStart:], "</form>")
	if formEnd < 0 {
		t.Fatal("Test sign-in form was not rendered")
	}
	if form := body[formStart : formStart+formEnd]; strings.Contains(form, "hx-") {
		t.Fatalf("Test sign-in form requires JavaScript: %s", form)
	}

	for _, tc := range []struct {
		name       string
		connection companyoidc.Connection
		encryption bool
		copy       string
	}{
		{name: "missing evidence", connection: companyoidc.Connection{Revision: 4}, encryption: true, copy: "Complete a current metadata check"},
		{name: "stale evidence", connection: companyoidc.Connection{Revision: 4, SetupCheck: &companyoidc.SetupCheck{ConfigRevision: 3, ResultCode: companyoidc.SetupCheckVerified}}, encryption: true, copy: "Complete a current metadata check"},
		{name: "failed evidence", connection: companyoidc.Connection{Revision: 4, SetupCheck: &companyoidc.SetupCheck{ConfigRevision: 4, ResultCode: companyoidc.SetupCheckDiscoveryInvalid}}, encryption: true, copy: "Complete a current metadata check"},
		{name: "encryption unavailable", connection: verified, encryption: false, copy: "Configure client-secret encryption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service.current = tc.connection
			fixture.server.cfg.CompanyOIDCSecretEncryptionConfigured = tc.encryption
			page := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
			if strings.Contains(page.Body.String(), `action="/settings/authentication/oidc/test"`) || !strings.Contains(page.Body.String(), tc.copy) {
				t.Fatalf("availability state rendered incorrectly: %q", page.Body.String())
			}
		})
	}
}

func TestAuthenticationReadyStateShowsInertEnableEvidenceAndRetestForm(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	ready := companyoidc.Connection{
		ProviderLabel: "Ready IdP",
		Issuer:        "https://id.example.test",
		ClientID:      "client",
		Domains:       []string{"example.test"},
		Revision:      4,
		SetupCheck: &companyoidc.SetupCheck{
			ConfigRevision: 4,
			ResultCode:     companyoidc.SetupCheckVerified,
			CheckedAt:      time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		},
		TestSignInEvidence: &companyoidc.TestSignInEvidence{
			ConfigRevision: 4,
			VerifiedAt:     time.Date(2026, 7, 30, 9, 15, 42, 123456789, time.UTC),
		},
	}
	fixture.server.cfg.CompanyOIDCService = &recordingCompanyOIDCService{current: ready, currentFound: true}
	response := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, response, http.StatusOK,
		"Test sign-in verified for saved revision 4 at 2026-07-30 09:15:42 UTC.",
		"Requirements met; enabling is not implemented. The connection remains Draft and disabled.",
		`method="post" action="/settings/authentication/oidc/test"`,
		`name="expected_revision" value="4"`,
	)
	if body := response.Body.String(); strings.Contains(body, "oidc/enable") {
		t.Fatal("Ready state referenced an Enable route")
	}
	assertAuthenticationSecurityHeaders(t, response.Header())
}

func TestAuthenticationSuspendedReadinessKeepsEvidenceAndRestores(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	evidence := &companyoidc.TestSignInEvidence{
		ConfigRevision: 4,
		VerifiedAt:     time.Date(2026, 7, 30, 9, 15, 42, 0, time.UTC),
	}
	verifiedCheck := &companyoidc.SetupCheck{ConfigRevision: 4, ResultCode: companyoidc.SetupCheckVerified}
	service := &recordingCompanyOIDCService{currentFound: true}
	fixture.server.cfg.CompanyOIDCService = service
	const evidenceLine = "Test sign-in verified for saved revision 4 at 2026-07-30 09:15:42 UTC."
	const readyCopy = "Requirements met; enabling is not implemented."
	for _, tc := range []struct {
		name       string
		connection companyoidc.Connection
		encryption bool
	}{
		{name: "stale metadata check", connection: companyoidc.Connection{
			Revision:           4,
			SetupCheck:         &companyoidc.SetupCheck{ConfigRevision: 3, ResultCode: companyoidc.SetupCheckVerified},
			TestSignInEvidence: evidence,
		}, encryption: true},
		{name: "failed metadata check", connection: companyoidc.Connection{
			Revision:           4,
			SetupCheck:         &companyoidc.SetupCheck{ConfigRevision: 4, ResultCode: companyoidc.SetupCheckDiscoveryInvalid},
			TestSignInEvidence: evidence,
		}, encryption: true},
		{name: "encryption unavailable", connection: companyoidc.Connection{
			Revision:           4,
			SetupCheck:         verifiedCheck,
			TestSignInEvidence: evidence,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service.current = tc.connection
			fixture.server.cfg.CompanyOIDCSecretEncryptionConfigured = tc.encryption
			page := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
			assertStatusAndBodyContains(t, page, http.StatusOK, evidenceLine)
			body := page.Body.String()
			if strings.Contains(body, `action="/settings/authentication/oidc/test"`) || strings.Contains(body, readyCopy) {
				t.Fatalf("suspended readiness still offered testing or enabling: %q", body)
			}
		})
	}

	service.current = companyoidc.Connection{
		Revision:           4,
		SetupCheck:         verifiedCheck,
		TestSignInEvidence: evidence,
	}
	fixture.server.cfg.CompanyOIDCSecretEncryptionConfigured = true
	restored := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
	assertStatusAndBodyContains(t, restored, http.StatusOK,
		evidenceLine,
		readyCopy,
		`action="/settings/authentication/oidc/test"`,
	)
}

func TestAuthenticationSetupProgressHasExactlyOneCurrentStep(t *testing.T) {
	fixture := newCompanyOIDCWebFixture(t, true)
	unverified := companyoidc.Connection{Revision: 4}
	verified := companyoidc.Connection{
		Revision: 4,
		SetupCheck: &companyoidc.SetupCheck{
			ConfigRevision: 4,
			ResultCode:     companyoidc.SetupCheckVerified,
		},
	}
	ready := verified
	ready.TestSignInEvidence = &companyoidc.TestSignInEvidence{
		ConfigRevision: 4,
		VerifiedAt:     time.Date(2026, 7, 30, 9, 15, 42, 0, time.UTC),
	}
	tests := []struct {
		name             string
		connection       companyoidc.Connection
		found            bool
		encryption       bool
		currentStep      string
		metadataComplete bool
		ready            bool
	}{
		{name: "configure", encryption: true, currentStep: "Configure"},
		{name: "saved unverified", connection: unverified, found: true, encryption: true, currentStep: "Verify metadata"},
		{name: "encryption unavailable", connection: unverified, found: true, currentStep: "Verify metadata"},
		{name: "verified", connection: verified, found: true, encryption: true, currentStep: "Test sign-in", metadataComplete: true},
		{name: "ready", connection: ready, found: true, encryption: true, currentStep: "Enable", metadataComplete: true, ready: true},
		{name: "readiness suspended by stale metadata", connection: companyoidc.Connection{
			Revision:           4,
			SetupCheck:         &companyoidc.SetupCheck{ConfigRevision: 3, ResultCode: companyoidc.SetupCheckVerified},
			TestSignInEvidence: ready.TestSignInEvidence,
		}, found: true, encryption: true, currentStep: "Verify metadata"},
		{name: "readiness suspended by encryption loss", connection: ready, found: true, currentStep: "Verify metadata"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture.server.cfg.CompanyOIDCService = &recordingCompanyOIDCService{
				current:      tc.connection,
				currentFound: tc.found,
			}
			fixture.server.cfg.CompanyOIDCSecretEncryptionConfigured = tc.encryption
			response := companyOIDCGET(fixture.server, "/settings/authentication", fixture.adminCookie())
			if response.Code != http.StatusOK {
				t.Fatalf("Authentication returned %d", response.Code)
			}
			body := response.Body.String()
			progressStart := strings.Index(body, `aria-label="Company sign-in setup progress"`)
			if progressStart < 0 {
				t.Fatal("setup progress was not rendered")
			}
			progressEnd := strings.Index(body[progressStart:], "</nav>")
			if progressEnd < 0 {
				t.Fatal("setup progress was not rendered")
			}
			progress := body[progressStart : progressStart+progressEnd]
			const current = `aria-current="step"`
			if count := strings.Count(progress, current); count != 1 {
				t.Fatalf("current step count = %d, want 1: %s", count, progress)
			}
			currentPosition := strings.Index(progress, current)
			currentStart := strings.LastIndex(progress[:currentPosition], "<li")
			currentEnd := strings.Index(progress[currentPosition:], "</li>")
			if currentStart < 0 || currentEnd < 0 {
				t.Fatal("current progress item could not be isolated")
			}
			currentItem := progress[currentStart : currentPosition+currentEnd]
			if !strings.Contains(currentItem, tc.currentStep) {
				t.Fatalf("current item does not contain %q: %s", tc.currentStep, currentItem)
			}
			if tc.metadataComplete {
				metadataPosition := strings.Index(progress, "Verify metadata")
				if metadataPosition < 0 {
					t.Fatal("metadata progress item was not rendered")
				}
				metadataStart := strings.LastIndex(progress[:metadataPosition], "<li")
				metadataEnd := strings.Index(progress[metadataPosition:], "</li>")
				if metadataStart < 0 || metadataEnd < 0 {
					t.Fatal("metadata progress item could not be isolated")
				}
				metadataItem := progress[metadataStart : metadataPosition+metadataEnd]
				if !strings.Contains(metadataItem, "bg-success-soft") ||
					!strings.Contains(metadataItem, `href="#tg-i-check"`) ||
					!strings.Contains(metadataItem, "Metadata verified") ||
					strings.Contains(metadataItem, current) {
					t.Fatalf("verified metadata item is not completed: %s", metadataItem)
				}
			}
			if tc.ready {
				testPosition := strings.Index(progress, "Verified for saved Draft")
				if testPosition < 0 {
					t.Fatalf("Test sign-in step is not completed: %s", progress)
				}
				testStart := strings.LastIndex(progress[:testPosition], "<li")
				testEnd := strings.Index(progress[testPosition:], "</li>")
				if testStart < 0 || testEnd < 0 {
					t.Fatal("completed Test sign-in item could not be isolated")
				}
				testItem := progress[testStart : testPosition+testEnd]
				if !strings.Contains(testItem, "bg-success-soft") ||
					!strings.Contains(testItem, `href="#tg-i-check"`) ||
					strings.Contains(testItem, current) {
					t.Fatalf("completed Test sign-in item is not completed: %s", testItem)
				}
				if !strings.Contains(currentItem, `aria-disabled="true"`) ||
					!strings.Contains(currentItem, "Not implemented") {
					t.Fatalf("Enable step is not inert: %s", currentItem)
				}
				for _, control := range []string{"<a", "<button", "<form", "href="} {
					if strings.Contains(currentItem, control) {
						t.Fatalf("Enable step rendered an actionable control %q: %s", control, currentItem)
					}
				}
			}
		})
	}
}

func TestCompanyOIDCTestNoticeCopyIsTruthfulAndSanitized(t *testing.T) {
	tests := []struct {
		notice string
		copy   string
	}{
		{notice: companyOIDCTestVerifiedNotice, copy: "Configured client credentials were accepted"},
		{notice: companyOIDCTestProviderDeniedNotice, copy: "provider denied this Test sign-in"},
		{notice: companyOIDCTestProviderUnavailable, copy: "provider was unavailable"},
		{notice: companyOIDCTestProviderInvalid, copy: "invalid sign-in response or did not supply a signed, verified email in a saved allowed domain"},
		{notice: companyOIDCTestConfigurationNotice, copy: "could not use the saved client configuration"},
		{notice: companyOIDCTestTransactionNotice, copy: "transaction, session, or Draft revision is no longer available"},
		{notice: companyOIDCTestUnknownNotice, copy: "could not confirm the Test sign-in outcome"},
	}
	for _, tc := range tests {
		toasts := companyOIDCNoticeToasts(url.Values{"notice": {tc.notice}})
		if len(toasts) != 1 || !strings.Contains(toasts[0].Message, tc.copy) {
			t.Fatalf("notice %q = %#v", tc.notice, toasts)
		}
		for _, forbidden := range []string{"user credentials were verified", "identity was created", "allowed-domain", "sign-in is enabled"} {
			if strings.Contains(strings.ToLower(toasts[0].Message), forbidden) {
				t.Fatalf("notice %q made forbidden claim %q", tc.notice, forbidden)
			}
		}
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
	checker     *companyOIDCWebChecker
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
	count := int64(1)
	checker := &companyOIDCWebChecker{report: companyoidc.SetupCheckReport{
		ResultCode:              companyoidc.SetupCheckVerified,
		PublicKeyCandidateCount: &count,
	}}
	service := companyoidc.NewService(database, secretStore, checker.check)
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
		checker:     checker,
		server:      server,
		admin:       admin,
	}
}

type companyOIDCWebChecker struct {
	report companyoidc.SetupCheckReport
	calls  int
	issuer string
}

func (checker *companyOIDCWebChecker) check(_ context.Context, issuer string) companyoidc.SetupCheckReport {
	checker.calls++
	checker.issuer = issuer
	return checker.report
}

func (f *companyOIDCWebFixture) adminCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: f.admin.ID}
}

type recordingCompanyOIDCService struct {
	createErr      error
	checkErr       error
	checkResult    companyoidc.SetupCheck
	current        companyoidc.Connection
	currentFound   bool
	currentErr     error
	calls          int
	checkCalls     int
	startCalls     int
	startInput     companyoidc.TestSignInStartInput
	startResult    companyoidc.TestSignInStart
	startErr       error
	callbackInput  companyoidc.TestSignInCallbackInput
	callbackCalls  int
	callbackResult companyoidc.TestSignInResultCode
	callbackErr    error
}

func (s *recordingCompanyOIDCService) Current(context.Context) (companyoidc.Connection, bool, error) {
	return s.current, s.currentFound, s.currentErr
}

func (s *recordingCompanyOIDCService) Create(context.Context, int64, companyoidc.CreateInput) error {
	s.calls++
	return s.createErr
}

func (s *recordingCompanyOIDCService) Edit(context.Context, int64, companyoidc.EditInput) error {
	s.calls++
	return nil
}

func (s *recordingCompanyOIDCService) Check(context.Context, int64) (companyoidc.SetupCheck, error) {
	s.checkCalls++
	return s.checkResult, s.checkErr
}

func (s *recordingCompanyOIDCService) StartTestSignIn(
	_ context.Context,
	input companyoidc.TestSignInStartInput,
) (companyoidc.TestSignInStart, error) {
	s.startCalls++
	s.startInput = input
	return s.startResult, s.startErr
}

func (s *recordingCompanyOIDCService) CompleteTestSignIn(
	_ context.Context,
	input companyoidc.TestSignInCallbackInput,
) (companyoidc.TestSignInResultCode, error) {
	s.callbackCalls++
	s.callbackInput = input
	return s.callbackResult, s.callbackErr
}

func (s *recordingCompanyOIDCService) reset() {
	s.calls = 0
	s.checkCalls = 0
	s.startCalls = 0
	s.callbackCalls = 0
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

func companyOIDCCheckPOST(
	server *Server,
	cookie *http.Cookie,
	form url.Values,
	origins []string,
	hx bool,
) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/settings/authentication/oidc/check",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if hx {
		request.Header.Set("HX-Request", "true")
	}
	for _, origin := range origins {
		request.Header.Add("Origin", origin)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func companyOIDCTestPOST(
	server *Server,
	cookie *http.Cookie,
	form url.Values,
	origins []string,
	hx bool,
) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/settings/authentication/oidc/test",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if hx {
		request.Header.Set("HX-Request", "true")
	}
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
		"Content-Security-Policy": authenticationCSP,
	}
	for name, value := range want {
		if got := header.Get(name); got != value {
			t.Fatalf("%s = %q, want %q", name, got, value)
		}
	}
	if !strings.Contains(header.Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatal("Authentication CSP must allow only same-origin htmx connections")
	}
}
