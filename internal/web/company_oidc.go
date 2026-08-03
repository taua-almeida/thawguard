package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/companyoidc"
)

const (
	companyOIDCDraftMaxBodyBytes int64 = 32 << 10
	companyOIDCCheckMaxBodyBytes int64 = 8 << 10
	companyOIDCTestMaxBodyBytes  int64 = 8 << 10
	companyOIDCCheckPath               = "/settings/authentication/oidc/check"

	companyOIDCCheckStaleNotice       = "oidc-check-stale"
	companyOIDCCheckUnknownNotice     = "oidc-check-unknown"
	companyOIDCCheckUnavailableNotice = "oidc-check-unavailable"
	companyOIDCCheckAuthorityNotice   = "oidc-check-authority"

	companyOIDCTestVerifiedNotice       = "oidc-test-verified"
	companyOIDCTestProviderDeniedNotice = "oidc-test-provider-denied"
	companyOIDCTestProviderUnavailable  = "oidc-test-provider-unavailable"
	companyOIDCTestProviderInvalid      = "oidc-test-provider-invalid"
	companyOIDCTestConfigurationNotice  = "oidc-test-configuration-unavailable"
	companyOIDCTestTransactionNotice    = "oidc-test-transaction-unavailable"
	companyOIDCTestUnknownNotice        = "oidc-test-unknown"
)

type companyOIDCFormView struct {
	ProviderLabel    string
	Issuer           string
	ClientID         string
	DomainsText      string
	ExpectedRevision string
}

type authenticationPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	Connection          companyoidc.Connection
	HasConnection       bool
	EncryptionAvailable bool
	ShowForm            bool
	Editing             bool
	Form                companyOIDCFormView
	FormError           string
	TerminalHeading     string
	TerminalMessage     string
	TerminalTone        string
	SetupHealth         companyOIDCSetupHealthView
	CallbackURI         string
	MetadataVerified    bool
	TestSignInAvailable bool
	TestSignInReason    string
	TestSignInCompleted bool
	TestSignInRevision  int64
	TestSignInTime      string
	ReadyToEnable       bool
}

type companyOIDCSetupHealthView struct {
	Heading            string
	Summary            string
	Tone               string
	CheckedAt          string
	CandidateSummary   string
	Rows               [4]companyOIDCSetupCheckRowView
	ShowIssuerMismatch bool
	SavedIssuer        companyOIDCIssuerView
	ObservedIssuer     companyOIDCIssuerView
}

type companyOIDCSetupCheckRowView struct {
	Label  string
	Status string
	Tone   string
}

type companyOIDCIssuerView struct {
	Prefix           string
	HasTrailingSlash bool
}

func (s *Server) handleAuthenticationSettings(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	s.renderAuthenticationRead(w, r, http.StatusOK, session)
}

func (s *Server) handleAuthenticationSettingsEdit(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		s.renderAuthenticationRead(w, r, http.StatusOK, session)
		return
	}
	connection, found, ok := s.currentCompanyOIDCConnection(w, r, session)
	if !ok {
		return
	}
	data := s.authenticationPageBase(session)
	data.Connection = connection
	data.HasConnection = found
	data.ShowForm = true
	data.Editing = found
	data.Form.ExpectedRevision = "0"
	if found {
		data.Form = companyOIDCFormView{
			ProviderLabel:    connection.ProviderLabel,
			Issuer:           connection.Issuer,
			ClientID:         connection.ClientID,
			DomainsText:      strings.Join(connection.Domains, "\n"),
			ExpectedRevision: strconv.FormatInt(connection.Revision, 10),
		}
	}
	s.renderPageStatus(w, http.StatusOK, "layouts/authentication", data)
}

func (s *Server) handleCompanyOIDCDraftSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCDraftMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	form, revision, parseErr := parseCompanyOIDCDraftForm(r.URL, r.PostForm)
	if parseErr != nil {
		s.renderAuthenticationTerminal(
			w,
			http.StatusBadRequest,
			session,
			"Draft request not processed",
			"The submitted form is invalid. Reload Authentication settings and try again.",
			"danger",
		)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		s.renderAuthenticationRead(w, r, http.StatusServiceUnavailable, session)
		return
	}
	if s.cfg.CompanyOIDCService == nil {
		s.renderAuthenticationTerminal(
			w,
			http.StatusServiceUnavailable,
			session,
			"Authentication settings unavailable",
			"Company OIDC settings are not configured on this installation.",
			"warning",
		)
		return
	}

	secret := r.PostForm.Get("client_secret")
	var err error
	if revision == 0 {
		err = s.cfg.CompanyOIDCService.Create(r.Context(), *session.UserID, companyoidc.CreateInput{
			ProviderLabel: form.ProviderLabel,
			Issuer:        form.Issuer,
			ClientID:      form.ClientID,
			ClientSecret:  secret,
			Domains:       domainsFromTextarea(form.DomainsText),
		})
	} else {
		err = s.cfg.CompanyOIDCService.Edit(r.Context(), *session.UserID, companyoidc.EditInput{
			ProviderLabel:           form.ProviderLabel,
			Issuer:                  form.Issuer,
			ClientID:                form.ClientID,
			ReplacementClientSecret: secret,
			Domains:                 domainsFromTextarea(form.DomainsText),
			ExpectedRevision:        revision,
		})
	}
	if err == nil {
		http.Redirect(w, r, "/settings/authentication", http.StatusSeeOther)
		return
	}

	switch {
	case companyoidc.IsValidationError(err):
		data := s.authenticationPageBase(session)
		data.ShowForm = true
		data.Editing = revision > 0
		data.Form = form
		data.FormError = err.Error()
		s.renderPageStatus(w, http.StatusBadRequest, "layouts/authentication", data)
	case errors.Is(err, companyoidc.ErrConflict):
		s.renderAuthenticationTerminal(
			w,
			http.StatusConflict,
			session,
			"Draft changed before this save",
			"Another save changed the company OIDC Draft. Reload the saved Draft before editing again. No submitted client secret is retained.",
			"warning",
		)
	case errors.Is(err, companyoidc.ErrConfiguration):
		s.renderAuthenticationRead(w, r, http.StatusServiceUnavailable, session)
	case errors.Is(err, companyoidc.ErrAuthorization):
		s.renderAuthenticationTerminal(
			w,
			http.StatusForbidden,
			session,
			"Administrator access changed",
			"Your account no longer has current Administrator authority to save this Draft. Reload Authentication settings.",
			"danger",
		)
	default:
		s.renderAuthenticationTerminal(
			w,
			http.StatusInternalServerError,
			session,
			"Draft save result unconfirmed",
			"Thawguard could not confirm whether the Draft was saved. Reload Authentication settings and inspect the saved revision before retrying. Re-enter any client secret only after reloading.",
			"danger",
		)
	}
}

func (s *Server) handleCompanyOIDCCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCCheckMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	if err := parseCompanyOIDCCheckForm(r.URL, r.PostForm); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		s.redirectCompanyOIDCCheck(w, r, companyOIDCCheckUnavailableNotice)
		return
	}
	if s.cfg.CompanyOIDCService == nil {
		s.redirectCompanyOIDCCheck(w, r, companyOIDCCheckUnknownNotice)
		return
	}

	if _, err := s.cfg.CompanyOIDCService.Check(r.Context(), *session.UserID); err != nil {
		notice := companyOIDCCheckUnknownNotice
		switch {
		case errors.Is(err, companyoidc.ErrCheckStale), errors.Is(err, companyoidc.ErrNoDraft):
			notice = companyOIDCCheckStaleNotice
		case errors.Is(err, companyoidc.ErrConfiguration):
			notice = companyOIDCCheckUnavailableNotice
		case errors.Is(err, companyoidc.ErrAuthorization):
			notice = companyOIDCCheckAuthorityNotice
		}
		s.redirectCompanyOIDCCheck(w, r, notice)
		return
	}
	s.redirectCompanyOIDCCheckLocation(w, r, "/settings/authentication")
}

func (s *Server) handleCompanyOIDCTestStart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCTestMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	revision, err := parseCompanyOIDCTestForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		redirectCompanyOIDCTest(w, r, companyOIDCTestConfigurationNotice)
		return
	}
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCTest(w, r, companyOIDCTestUnknownNotice)
		return
	}
	start, err := s.cfg.CompanyOIDCService.StartTestSignIn(r.Context(), companyoidc.TestSignInStartInput{
		ActorUserID:      *session.UserID,
		SessionID:        session.ID,
		ExpectedRevision: revision,
		CallbackURI:      s.cfg.PublicURL + companyoidc.TestSignInCallbackPath,
	})
	if err != nil {
		notice := companyOIDCTestTransactionNotice
		switch {
		case errors.Is(err, companyoidc.ErrConfiguration):
			notice = companyOIDCTestConfigurationNotice
		case errors.Is(err, companyoidc.ErrTestProviderUnavailable):
			notice = companyOIDCTestProviderUnavailable
		case errors.Is(err, companyoidc.ErrTestProviderInvalid):
			notice = companyOIDCTestProviderInvalid
		case errors.Is(err, companyoidc.ErrTestTransactionOutcomeUnknown):
			notice = companyOIDCTestUnknownNotice
		}
		redirectCompanyOIDCTest(w, r, notice)
		return
	}
	http.Redirect(w, r, start.AuthorizationURL, http.StatusSeeOther)
}

func (s *Server) handleCompanyOIDCTestCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	state, ok := companyoidc.TestSignInStateFromRawQuery(r.URL.RawQuery)
	if !ok {
		redirectCompanyOIDCTest(w, r, companyOIDCTestTransactionNotice)
		return
	}
	sessionID := exactTestSignInSessionCookie(r)
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCTest(w, r, companyOIDCTestTransactionNotice)
		return
	}
	result, err := s.cfg.CompanyOIDCService.CompleteTestSignIn(r.Context(), companyoidc.TestSignInCallbackInput{
		State:     state,
		SessionID: sessionID,
		RawQuery:  r.URL.RawQuery,
	})
	if err != nil {
		notice := companyOIDCTestTransactionNotice
		if errors.Is(err, companyoidc.ErrTestTransactionOutcomeUnknown) {
			notice = companyOIDCTestUnknownNotice
		}
		redirectCompanyOIDCTest(w, r, notice)
		return
	}
	notice := map[companyoidc.TestSignInResultCode]string{
		companyoidc.TestSignInVerified:                 companyOIDCTestVerifiedNotice,
		companyoidc.TestSignInProviderDenied:           companyOIDCTestProviderDeniedNotice,
		companyoidc.TestSignInProviderUnavailable:      companyOIDCTestProviderUnavailable,
		companyoidc.TestSignInProviderInvalid:          companyOIDCTestProviderInvalid,
		companyoidc.TestSignInConfigurationUnavailable: companyOIDCTestConfigurationNotice,
	}[result]
	if notice == "" {
		notice = companyOIDCTestUnknownNotice
	}
	redirectCompanyOIDCTest(w, r, notice)
}

func redirectCompanyOIDCTest(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, companyOIDCNoticeLocation(notice), http.StatusSeeOther)
}

func exactTestSignInSessionCookie(r *http.Request) string {
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionCookieName {
			continue
		}
		count++
		value = cookie.Value
	}
	if count != 1 || value == "" {
		return ""
	}
	return value
}

func (s *Server) renderAuthenticationRead(w http.ResponseWriter, r *http.Request, status int, session sessionState) {
	connection, found, ok := s.currentCompanyOIDCConnection(w, r, session)
	if !ok {
		return
	}
	data := s.authenticationPageBase(session)
	data.Connection = connection
	data.HasConnection = found
	if found {
		data.SetupHealth = companyOIDCSetupHealth(connection)
		data.CallbackURI = s.cfg.PublicURL + companyoidc.TestSignInCallbackPath
		data.MetadataVerified = connection.SetupCheck != nil &&
			connection.SetupCheck.ConfigRevision == connection.Revision &&
			connection.SetupCheck.ResultCode == companyoidc.SetupCheckVerified
		data.TestSignInReason = "Complete a current metadata check and resolve its result before testing sign-in."
		if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
			data.TestSignInReason = "Configure client-secret encryption before testing sign-in."
		} else if data.MetadataVerified {
			data.TestSignInAvailable = true
			data.TestSignInReason = ""
		}
		if connection.TestSignInEvidence != nil {
			data.TestSignInCompleted = true
			data.TestSignInRevision = connection.TestSignInEvidence.ConfigRevision
			data.TestSignInTime = connection.TestSignInEvidence.VerifiedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		data.ReadyToEnable = data.TestSignInAvailable && data.TestSignInCompleted
	}
	data.Toasts = companyOIDCNoticeToasts(r.URL.Query())
	s.renderPageStatus(w, status, "layouts/authentication", data)
}

func (s *Server) currentCompanyOIDCConnection(
	w http.ResponseWriter,
	r *http.Request,
	session sessionState,
) (companyoidc.Connection, bool, bool) {
	if s.cfg.CompanyOIDCService == nil {
		s.renderAuthenticationTerminal(
			w,
			http.StatusServiceUnavailable,
			session,
			"Authentication settings unavailable",
			"Company OIDC settings are not configured on this installation.",
			"warning",
		)
		return companyoidc.Connection{}, false, false
	}
	connection, found, err := s.cfg.CompanyOIDCService.Current(r.Context())
	if err != nil {
		s.renderAuthenticationTerminal(
			w,
			http.StatusInternalServerError,
			session,
			"Authentication settings unavailable",
			"Thawguard could not load the company OIDC Draft. No secret value was retrieved. Try again after checking the installation database.",
			"danger",
		)
		return companyoidc.Connection{}, false, false
	}
	return connection, found, true
}

func (s *Server) authenticationPageBase(session sessionState) authenticationPageData {
	return authenticationPageData{
		AppName:             s.cfg.AppName,
		PageTitle:           "Authentication",
		ActivePage:          "authentication",
		CurrentUser:         currentUserFromSession(session),
		CSRFToken:           session.CSRFToken,
		CSRFField:           csrfFormField,
		EncryptionAvailable: s.cfg.CompanyOIDCSecretEncryptionConfigured,
	}
}

func (s *Server) renderAuthenticationTerminal(
	w http.ResponseWriter,
	status int,
	session sessionState,
	heading string,
	message string,
	tone string,
) {
	data := s.authenticationPageBase(session)
	data.TerminalHeading = heading
	data.TerminalMessage = message
	data.TerminalTone = tone
	s.renderPageStatus(w, status, "layouts/authentication", data)
}

func parseCompanyOIDCDraftForm(requestURL *url.URL, values url.Values) (companyOIDCFormView, int64, error) {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return companyOIDCFormView{}, 0, errors.New("query values are not allowed")
	}
	allowed := map[string]bool{
		csrfFormField:       true,
		"provider_label":    true,
		"issuer":            true,
		"client_id":         true,
		"client_secret":     true,
		"allowed_domains":   true,
		"expected_revision": true,
	}
	for key, fieldValues := range values {
		if !allowed[key] || len(fieldValues) != 1 {
			return companyOIDCFormView{}, 0, errors.New("unexpected or duplicate form field")
		}
	}
	for field := range allowed {
		if len(values[field]) != 1 {
			return companyOIDCFormView{}, 0, errors.New("required form field is missing")
		}
	}
	revision, err := canonicalExpectedRevision(values.Get("expected_revision"))
	if err != nil {
		return companyOIDCFormView{}, 0, err
	}
	return companyOIDCFormView{
		ProviderLabel:    values.Get("provider_label"),
		Issuer:           values.Get("issuer"),
		ClientID:         values.Get("client_id"),
		DomainsText:      values.Get("allowed_domains"),
		ExpectedRevision: values.Get("expected_revision"),
	}, revision, nil
}

func canonicalExpectedRevision(value string) (int64, error) {
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision < 0 || strconv.FormatInt(revision, 10) != value {
		return 0, errors.New("expected revision is invalid")
	}
	return revision, nil
}

func domainsFromTextarea(value string) []string {
	return strings.Split(value, "\n")
}

func parseCompanyOIDCCheckForm(requestURL *url.URL, values url.Values) error {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return errors.New("query values are not allowed")
	}
	if len(values) != 1 || len(values[csrfFormField]) != 1 {
		return errors.New("check form must contain exactly one CSRF field")
	}
	return nil
}

func parseCompanyOIDCTestForm(requestURL *url.URL, values url.Values) (int64, error) {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return 0, errors.New("query values are not allowed")
	}
	if len(values) != 2 || len(values[csrfFormField]) != 1 || len(values["expected_revision"]) != 1 {
		return 0, errors.New("Test sign-in form is malformed")
	}
	revision, err := canonicalExpectedRevision(values.Get("expected_revision"))
	if err != nil || revision == 0 {
		return 0, errors.New("expected revision is invalid")
	}
	return revision, nil
}

func (s *Server) redirectCompanyOIDCCheck(w http.ResponseWriter, r *http.Request, notice string) {
	s.redirectCompanyOIDCCheckLocation(w, r, companyOIDCNoticeLocation(notice))
}

func (s *Server) redirectCompanyOIDCCheckLocation(w http.ResponseWriter, r *http.Request, location string) {
	if isHXRequest(r) {
		w.Header().Set("HX-Redirect", location)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func isCompanyOIDCCheckHX(r *http.Request) bool {
	return r.URL.Path == companyOIDCCheckPath && isHXRequest(r)
}

func companyOIDCNoticeLocation(notice string) string {
	switch notice {
	case companyOIDCCheckStaleNotice,
		companyOIDCCheckUnknownNotice,
		companyOIDCCheckUnavailableNotice,
		companyOIDCCheckAuthorityNotice,
		companyOIDCTestVerifiedNotice,
		companyOIDCTestProviderDeniedNotice,
		companyOIDCTestProviderUnavailable,
		companyOIDCTestProviderInvalid,
		companyOIDCTestConfigurationNotice,
		companyOIDCTestTransactionNotice,
		companyOIDCTestUnknownNotice:
		return "/settings/authentication?notice=" + notice
	default:
		return "/settings/authentication?notice=" + companyOIDCCheckUnknownNotice
	}
}

func companyOIDCNoticeToasts(values url.Values) []toastView {
	if len(values) != 1 || len(values["notice"]) != 1 {
		return nil
	}
	message := ""
	tone := "warning"
	switch values.Get("notice") {
	case companyOIDCCheckStaleNotice:
		message = "The saved Draft changed before this check could be recorded. Run Check configuration again."
	case companyOIDCCheckUnknownNotice:
		message = "Thawguard could not confirm whether a current check was recorded. Inspect the saved evidence before retrying."
		tone = "danger"
	case companyOIDCCheckUnavailableNotice:
		message = "Metadata checking is unavailable until client-secret encryption is configured."
	case companyOIDCCheckAuthorityNotice:
		message = "Administrator authority changed before this check could be recorded."
		tone = "danger"
	case companyOIDCTestVerifiedNotice:
		message = "Configured client credentials were accepted. Thawguard verified the OIDC authorization/code flow and signed ID token. The connection remains Draft and disabled."
		tone = "success"
	case companyOIDCTestProviderDeniedNotice:
		message = "The provider denied this Test sign-in. The connection remains Draft and disabled."
	case companyOIDCTestProviderUnavailable:
		message = "The provider was unavailable during Test sign-in. No identity or session was created."
	case companyOIDCTestProviderInvalid:
		message = "The provider returned an invalid Test sign-in response. Review the provider configuration before trying again."
		tone = "danger"
	case companyOIDCTestConfigurationNotice:
		message = "Test sign-in could not use the saved client configuration. Check client-secret encryption and the saved provider credentials."
		tone = "danger"
	case companyOIDCTestTransactionNotice:
		message = "The Test sign-in transaction, session, or Draft revision is no longer available. Start a new Test sign-in from Authentication settings."
	case companyOIDCTestUnknownNotice:
		message = "Thawguard could not confirm the Test sign-in outcome. Review Activity before trying again."
		tone = "danger"
	default:
		return nil
	}
	return []toastView{{Message: message, Tone: tone, DismissHref: "/settings/authentication"}}
}

func companyOIDCSetupHealth(connection companyoidc.Connection) companyOIDCSetupHealthView {
	check := connection.SetupCheck
	view := companyOIDCSetupHealthView{
		Heading: "Never checked",
		Summary: "Run a fresh check against the explicitly saved Draft. Client credentials and sign-in are not tested.",
		Tone:    "info",
	}
	if check == nil && connection.Revision > 1 {
		view.Heading = "Never checked since last saved edit"
		view.Summary = "This saved revision has no current check result. Run a fresh check against the saved Draft."
	}
	for i, row := range companyoidc.SetupCheckRows(check) {
		view.Rows[i] = companyOIDCSetupCheckRowView{Label: row.Label, Status: "Not checked", Tone: "neutral"}
		switch row.State {
		case companyoidc.SetupCheckRowPassed:
			view.Rows[i].Status = "Passed"
			view.Rows[i].Tone = "success"
		case companyoidc.SetupCheckRowFailed:
			view.Rows[i].Status = "Failed"
			view.Rows[i].Tone = "danger"
		}
	}
	if check == nil {
		return view
	}

	view.CheckedAt = check.CheckedAt.UTC().Format("2006-01-02 15:04:05 UTC")
	if check.ResultCode == companyoidc.SetupCheckVerified {
		view.Heading = "Discovery verified"
		view.Summary = "Thawguard confirmed that provider metadata and public-key candidates were read. Company sign-in remains Draft."
		view.Tone = "success"
		if check.PublicKeyCandidateCount != nil {
			view.CandidateSummary = fmt.Sprintf("Supported public-key candidates published: %d.", *check.PublicKeyCandidateCount)
		}
		return view
	}

	view.Heading = "Check failed"
	view.Tone = "danger"
	view.Summary = companyOIDCCheckFailureSummary(check.ResultCode)
	if check.ResultCode == companyoidc.SetupCheckIssuerMismatch && check.ObservedIssuer != nil {
		view.ShowIssuerMismatch = true
		view.SavedIssuer = companyOIDCIssuerDisplay(connection.Issuer)
		view.ObservedIssuer = companyOIDCIssuerDisplay(*check.ObservedIssuer)
	}
	return view
}

func companyOIDCCheckFailureSummary(code companyoidc.SetupCheckResultCode) string {
	switch code {
	case companyoidc.SetupCheckDiscoveryUnavailable:
		return "The discovery document was not available from a direct HTTP 200 response."
	case companyoidc.SetupCheckDiscoveryInvalid:
		return "The discovery response was not a bounded JSON object with the required content type."
	case companyoidc.SetupCheckIssuerInvalid:
		return "The discovery document published an invalid issuer."
	case companyoidc.SetupCheckIssuerMismatch:
		return "The published issuer did not exactly match the saved issuer."
	case companyoidc.SetupCheckMetadataIncompatible:
		return "The provider did not publish the required authorization-code metadata."
	case companyoidc.SetupCheckJWKSUnavailable:
		return "The advertised JWK Set was not available from a direct HTTP 200 response."
	case companyoidc.SetupCheckJWKSInvalid:
		return "The advertised JWK Set was not a valid bounded JSON key set."
	case companyoidc.SetupCheckJWKSNoCandidate:
		return "The JWK Set was readable but did not publish a supported RSA public-key candidate."
	default:
		return "The saved provider metadata could not be checked."
	}
}

func companyOIDCIssuerDisplay(issuer string) companyOIDCIssuerView {
	if strings.HasSuffix(issuer, "/") {
		return companyOIDCIssuerView{Prefix: strings.TrimSuffix(issuer, "/"), HasTrailingSlash: true}
	}
	return companyOIDCIssuerView{Prefix: issuer}
}
