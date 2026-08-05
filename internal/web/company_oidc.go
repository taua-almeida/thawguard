package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/companyoidc"
)

const (
	companyOIDCDraftMaxBodyBytes      int64 = 32 << 10
	companyOIDCCheckMaxBodyBytes      int64 = 8 << 10
	companyOIDCTestMaxBodyBytes       int64 = 8 << 10
	companyOIDCLinkMaxBodyBytes       int64 = 8 << 10
	companyOIDCActivationMaxBodyBytes int64 = 8 << 10
	companyOIDCLoginMaxBodyBytes      int64 = 8 << 10
	companyOIDCCheckPath                    = "/settings/authentication/oidc/check"

	companyLoginCookieName   = "thawguard_company_login"
	companyLoginCookiePath   = "/settings/authentication/oidc"
	companyLoginCookieMaxAge = 600

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

	companyOIDCEnabledGuardNotice = "oidc-enabled-guard"

	companyOIDCLinkedNotice          = "oidc-linked"
	companyOIDCLinkPasswordNotice    = "oidc-link-password"
	companyOIDCLinkUnavailableNotice = "oidc-link-unavailable"
	companyOIDCLinkAuthorityNotice   = "oidc-link-authority"
	companyOIDCLinkProviderNotice    = "oidc-link-provider"
	companyOIDCLinkTransactionNotice = "oidc-link-transaction"
	companyOIDCLinkUnknownNotice     = "oidc-link-unknown"

	companyOIDCEnabledNotice           = "oidc-enabled"
	companyOIDCEnableStaleNotice       = "oidc-enable-stale"
	companyOIDCEnableNotReadyNotice    = "oidc-enable-not-ready"
	companyOIDCEnableUnavailableNotice = "oidc-enable-unavailable"
	companyOIDCEnableAuthorityNotice   = "oidc-enable-authority"
	companyOIDCEnableUnknownNotice     = "oidc-enable-unknown"

	companyOIDCDisabledNotice         = "oidc-disabled"
	companyOIDCDisableStaleNotice     = "oidc-disable-stale"
	companyOIDCDisableAuthorityNotice = "oidc-disable-authority"
	companyOIDCDisableUnknownNotice   = "oidc-disable-unknown"

	companyOIDCUnlinkedNotice        = "oidc-unlinked"
	companyOIDCUnlinkPasswordNotice  = "oidc-unlink-password"
	companyOIDCUnlinkEnabledNotice   = "oidc-unlink-enabled"
	companyOIDCUnlinkStaleNotice     = "oidc-unlink-stale"
	companyOIDCUnlinkAuthorityNotice = "oidc-unlink-authority"
	companyOIDCUnlinkUnknownNotice   = "oidc-unlink-unknown"

	companyLoginFailedNotice      = "company-login-failed"
	companyLoginUnavailableNotice = "company-login-unavailable"
	companyLoginDisabledNotice    = "company-login-disabled"
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

	Connection              companyoidc.Connection
	HasConnection           bool
	EncryptionAvailable     bool
	ShowForm                bool
	Editing                 bool
	Form                    companyOIDCFormView
	FormError               string
	TerminalHeading         string
	TerminalMessage         string
	TerminalTone            string
	SetupHealth             companyOIDCSetupHealthView
	CallbackURI             string
	MetadataVerified        bool
	TestSignInAvailable     bool
	TestSignInReason        string
	TestSignInCompleted     bool
	TestSignInRevision      int64
	TestSignInTime          string
	ReadyToEnable           bool
	Enabled                 bool
	CompanyLoginOperational bool
	Linked                  bool
	LinkedEmail             string
	LinkedAt                string
	LinkedMatches           bool
	LinkedIsSelf            bool
	CanLink                 bool
	CanEnable               bool
	CanUnlink               bool
}

type companyOIDCProviderNavigationData struct {
	AppName          string
	PageTitle        string
	Theme            string
	AuthorizationURL string
	ReturnHref       string
	ReturnLabel      string
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
	connection, found, ok := s.currentCompanyOIDCConnection(w, r, session)
	if !ok {
		return
	}
	if found && connection.Enabled {
		http.Redirect(w, r, companyOIDCNoticeLocation(companyOIDCEnabledGuardNotice), http.StatusSeeOther)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		s.renderAuthenticationRead(w, r, http.StatusOK, session)
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
	case errors.Is(err, companyoidc.ErrEnabled):
		s.renderAuthenticationTerminal(
			w,
			http.StatusConflict,
			session,
			"Company login is enabled",
			"The connection cannot be edited while company login is enabled. Disable company login first, then edit the Draft. No submitted client secret is retained.",
			"warning",
		)
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
		case errors.Is(err, companyoidc.ErrEnabled):
			notice = companyOIDCEnabledGuardNotice
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
	revision, err := parseCompanyOIDCRevisionForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		redirectCompanyOIDCNotice(w, r, companyOIDCTestConfigurationNotice)
		return
	}
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCTestUnknownNotice)
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
		case errors.Is(err, companyoidc.ErrEnabled):
			notice = companyOIDCEnabledGuardNotice
		case errors.Is(err, companyoidc.ErrConfiguration):
			notice = companyOIDCTestConfigurationNotice
		case errors.Is(err, companyoidc.ErrTestProviderUnavailable):
			notice = companyOIDCTestProviderUnavailable
		case errors.Is(err, companyoidc.ErrTestProviderInvalid):
			notice = companyOIDCTestProviderInvalid
		case errors.Is(err, companyoidc.ErrTestTransactionOutcomeUnknown):
			notice = companyOIDCTestUnknownNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	s.renderCompanyOIDCProviderNavigation(w, r, start.AuthorizationURL, "")
}

// handleCompanyOIDCCallback serves the single registered callback URI for
// every company OIDC flow. The state shape alone decides which flow a
// callback belongs to, before any database access, so link, login, and Test
// transactions can never consume one another's callbacks.
func (s *Server) handleCompanyOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	kind, state := companyoidc.CallbackStateFromRawQuery(r.URL.RawQuery)
	switch kind {
	case companyoidc.CallbackStateTest:
		s.completeCompanyOIDCTestCallback(w, r, state)
	case companyoidc.CallbackStateLink:
		s.completeCompanyOIDCLinkCallback(w, r, state)
	case companyoidc.CallbackStateLogin:
		s.completeCompanyOIDCLoginCallback(w, r, state)
	default:
		redirectCompanyOIDCNotice(w, r, companyOIDCTestTransactionNotice)
	}
}

func (s *Server) completeCompanyOIDCTestCallback(w http.ResponseWriter, r *http.Request, state string) {
	sessionID := exactTestSignInSessionCookie(r)
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCTestTransactionNotice)
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
		redirectCompanyOIDCNotice(w, r, notice)
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
	redirectCompanyOIDCNotice(w, r, notice)
}

func (s *Server) completeCompanyOIDCLinkCallback(w http.ResponseWriter, r *http.Request, state string) {
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCLinkTransactionNotice)
		return
	}
	result, err := s.cfg.CompanyOIDCService.CompleteLink(r.Context(), companyoidc.LinkCallbackInput{
		State:     state,
		SessionID: exactTestSignInSessionCookie(r),
		RawQuery:  r.URL.RawQuery,
	})
	if err != nil {
		notice := companyOIDCLinkTransactionNotice
		if errors.Is(err, companyoidc.ErrLinkOutcomeUnknown) {
			notice = companyOIDCLinkUnknownNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	notice := map[companyoidc.TestSignInResultCode]string{
		companyoidc.TestSignInVerified:                 companyOIDCLinkedNotice,
		companyoidc.TestSignInProviderDenied:           companyOIDCLinkProviderNotice,
		companyoidc.TestSignInProviderUnavailable:      companyOIDCLinkProviderNotice,
		companyoidc.TestSignInProviderInvalid:          companyOIDCLinkProviderNotice,
		companyoidc.TestSignInConfigurationUnavailable: companyOIDCLinkUnavailableNotice,
	}[result]
	if notice == "" {
		notice = companyOIDCLinkUnknownNotice
	}
	redirectCompanyOIDCNotice(w, r, notice)
}

// completeCompanyOIDCLoginCallback finishes an anonymous company sign-in. The
// browser-binding cookie is read once and cleared on every terminal outcome,
// and an already-authenticated browser is redirected without consuming the
// login transaction it is not entitled to.
func (s *Server) completeCompanyOIDCLoginCallback(w http.ResponseWriter, r *http.Request, state string) {
	browserToken := exactCompanyLoginCookie(r)
	s.clearCompanyLoginCookie(w, r)
	if session, ok, err := s.currentSession(r); err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	} else if ok {
		http.Redirect(w, r, postLoginPath(session.MustChangePassword), http.StatusSeeOther)
		return
	}
	if s.cfg.CompanyOIDCService == nil || s.cfg.AuthService == nil {
		redirectCompanyLogin(w, r, companyLoginFailedNotice)
		return
	}
	completion, result, err := s.cfg.CompanyOIDCService.CompleteLogin(r.Context(), companyoidc.LoginCallbackInput{
		State:        state,
		BrowserToken: browserToken,
		RawQuery:     r.URL.RawQuery,
	})
	if err != nil || result != companyoidc.TestSignInVerified {
		redirectCompanyLogin(w, r, companyLoginFailedNotice)
		return
	}
	session, err := s.cfg.AuthService.CreateCompanyOIDCSession(r.Context(), auth.CreateCompanyOIDCSessionParams{
		UserID:               completion.UserID,
		ConnectionRevision:   completion.ConnectionRevision,
		ActivationGeneration: completion.ActivationGeneration,
	})
	if err != nil {
		redirectCompanyLogin(w, r, companyLoginFailedNotice)
		return
	}
	s.setSessionCookie(w, r, sessionStateFromAuth(session))
	http.Redirect(w, r, postLoginPath(session.User.MustChangePassword), http.StatusSeeOther)
}

func (s *Server) handleCompanyOIDCLinkStart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCLinkMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	revision, password, err := parseCompanyOIDCPasswordForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured || s.cfg.CompanyOIDCService == nil || s.cfg.AuthService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCLinkUnavailableNotice)
		return
	}
	if err := s.cfg.AuthService.VerifyCurrentPassword(r.Context(), *session.UserID, password); err != nil {
		notice := companyOIDCLinkUnknownNotice
		if auth.IsAuthenticationError(err) {
			notice = companyOIDCLinkPasswordNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	start, err := s.cfg.CompanyOIDCService.StartLink(r.Context(), companyoidc.LinkStartInput{
		ActorUserID:      *session.UserID,
		SessionID:        session.ID,
		ExpectedRevision: revision,
		CallbackURI:      s.cfg.PublicURL + companyoidc.TestSignInCallbackPath,
	})
	if err != nil {
		notice := companyOIDCLinkUnknownNotice
		switch {
		case errors.Is(err, companyoidc.ErrLinkAuthorization):
			notice = companyOIDCLinkAuthorityNotice
		case errors.Is(err, companyoidc.ErrConflict),
			errors.Is(err, companyoidc.ErrNoDraft),
			errors.Is(err, companyoidc.ErrNotReady),
			errors.Is(err, companyoidc.ErrEnabled),
			errors.Is(err, companyoidc.ErrLinkUnavailable),
			errors.Is(err, companyoidc.ErrConfiguration):
			notice = companyOIDCLinkUnavailableNotice
		case errors.Is(err, companyoidc.ErrTestProviderUnavailable),
			errors.Is(err, companyoidc.ErrTestProviderInvalid):
			notice = companyOIDCLinkProviderNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	s.renderCompanyOIDCProviderNavigation(w, r, start.AuthorizationURL, "")
}

func (s *Server) handleCompanyOIDCEnable(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCActivationMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	revision, err := parseCompanyOIDCRevisionForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		redirectCompanyOIDCNotice(w, r, companyOIDCEnableUnavailableNotice)
		return
	}
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCEnableUnknownNotice)
		return
	}
	if err := s.cfg.CompanyOIDCService.Enable(r.Context(), companyoidc.EnableInput{
		ActorUserID:      *session.UserID,
		ExpectedRevision: revision,
	}); err != nil {
		notice := companyOIDCEnableUnknownNotice
		switch {
		case errors.Is(err, companyoidc.ErrConfiguration):
			notice = companyOIDCEnableUnavailableNotice
		case errors.Is(err, companyoidc.ErrAuthorization):
			notice = companyOIDCEnableAuthorityNotice
		case errors.Is(err, companyoidc.ErrConflict):
			notice = companyOIDCEnableStaleNotice
		case errors.Is(err, companyoidc.ErrNotReady):
			notice = companyOIDCEnableNotReadyNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	redirectCompanyOIDCNotice(w, r, companyOIDCEnabledNotice)
}

func (s *Server) handleCompanyOIDCDisable(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCActivationMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	revision, err := parseCompanyOIDCRevisionForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.CompanyOIDCService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCDisableUnknownNotice)
		return
	}
	if err := s.cfg.CompanyOIDCService.Disable(r.Context(), companyoidc.DisableInput{
		ActorUserID:      *session.UserID,
		ExpectedRevision: revision,
	}); err != nil {
		notice := companyOIDCDisableUnknownNotice
		switch {
		case errors.Is(err, companyoidc.ErrAuthorization):
			notice = companyOIDCDisableAuthorityNotice
		case errors.Is(err, companyoidc.ErrConflict):
			notice = companyOIDCDisableStaleNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	// Disabling revokes every company OIDC session, including the acting one
	// when the Administrator signed in through the provider. Send that browser
	// to the login page instead of a settings redirect its dead session can no
	// longer render.
	if session.CompanyOIDC {
		s.clearSessionCookie(w, r)
		redirectCompanyLogin(w, r, companyLoginDisabledNotice)
		return
	}
	redirectCompanyOIDCNotice(w, r, companyOIDCDisabledNotice)
}

func (s *Server) handleCompanyOIDCUnlink(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCLinkMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	revision, password, err := parseCompanyOIDCPasswordForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.CompanyOIDCService == nil || s.cfg.AuthService == nil {
		redirectCompanyOIDCNotice(w, r, companyOIDCUnlinkUnknownNotice)
		return
	}
	if err := s.cfg.AuthService.VerifyCurrentPassword(r.Context(), *session.UserID, password); err != nil {
		notice := companyOIDCUnlinkUnknownNotice
		if auth.IsAuthenticationError(err) {
			notice = companyOIDCUnlinkPasswordNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	if err := s.cfg.CompanyOIDCService.Unlink(r.Context(), companyoidc.UnlinkInput{
		ActorUserID:      *session.UserID,
		SessionID:        session.ID,
		ExpectedRevision: revision,
	}); err != nil {
		notice := companyOIDCUnlinkUnknownNotice
		switch {
		case errors.Is(err, companyoidc.ErrEnabled):
			notice = companyOIDCUnlinkEnabledNotice
		case errors.Is(err, companyoidc.ErrConflict):
			notice = companyOIDCUnlinkStaleNotice
		case errors.Is(err, companyoidc.ErrLinkAuthorization):
			notice = companyOIDCUnlinkAuthorityNotice
		}
		redirectCompanyOIDCNotice(w, r, notice)
		return
	}
	redirectCompanyOIDCNotice(w, r, companyOIDCUnlinkedNotice)
}

// handleCompanyOIDCLoginStart begins an anonymous company sign-in from the
// login page. Every gate that needs no network access runs before discovery,
// and an authenticated browser is redirected without starting a transaction.
func (s *Server) handleCompanyOIDCLoginStart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, companyOIDCLoginMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if session, ok, err := s.currentSession(r); err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	} else if ok {
		http.Redirect(w, r, postLoginPath(session.MustChangePassword), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := parseCompanyOIDCLoginForm(r.URL, r.PostForm); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.validCompanyLoginCSRFToken(r) {
		redirectCompanyLogin(w, r, companyLoginUnavailableNotice)
		return
	}
	if !s.cfg.CompanyOIDCSecretEncryptionConfigured || s.cfg.CompanyOIDCService == nil || s.cfg.AuthService == nil {
		redirectCompanyLogin(w, r, companyLoginUnavailableNotice)
		return
	}
	start, err := s.cfg.CompanyOIDCService.StartLogin(r.Context(), companyoidc.LoginStartInput{
		CallbackURI: s.cfg.PublicURL + companyoidc.TestSignInCallbackPath,
	})
	if err != nil {
		redirectCompanyLogin(w, r, companyLoginUnavailableNotice)
		return
	}
	s.renderCompanyOIDCProviderNavigation(w, r, start.AuthorizationURL, start.BrowserToken)
}

func (s *Server) renderCompanyOIDCProviderNavigation(
	w http.ResponseWriter,
	r *http.Request,
	authorizationURL string,
	browserToken string,
) {
	signedOut := browserToken != ""
	returnHref := "/settings/authentication"
	returnLabel := "Back to Authentication settings"
	if signedOut {
		returnHref = "/login"
		returnLabel = "Back to sign in"
	}
	data := companyOIDCProviderNavigationData{
		AppName:          s.cfg.AppName,
		PageTitle:        "Continue to company sign-in",
		AuthorizationURL: authorizationURL,
		ReturnHref:       returnHref,
		ReturnLabel:      returnLabel,
	}
	var page bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&page, "layouts/company-oidc-provider-navigation", data); err != nil {
		s.renderCompanyOIDCProviderNavigationFailure(w, signedOut)
		return
	}

	w.Header().Set("Content-Security-Policy", providerNavigationCSP)
	if signedOut {
		s.setCompanyLoginCookie(w, r, browserToken)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Bytes())
}

func (s *Server) renderCompanyOIDCProviderNavigationFailure(w http.ResponseWriter, signedOut bool) {
	actionHref := "/settings/authentication"
	actionLabel := "Back to Authentication settings"
	if signedOut {
		actionHref = "/login"
		actionLabel = "Back to sign in"
	}
	s.renderPageStatus(w, http.StatusInternalServerError, "layouts/error", authErrorData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Company sign-in could not continue",
		Status:      http.StatusInternalServerError,
		Heading:     "Company sign-in could not continue",
		Message:     "Thawguard could not display the page that continues to the company provider. A one-time sign-in request may already exist and will expire on its own. Return and start a new attempt.",
		ActionHref:  actionHref,
		ActionLabel: actionLabel,
	})
}

func redirectCompanyOIDCNotice(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, companyOIDCNoticeLocation(notice), http.StatusSeeOther)
}

func redirectCompanyLogin(w http.ResponseWriter, r *http.Request, notice string) {
	switch notice {
	case companyLoginFailedNotice, companyLoginUnavailableNotice, companyLoginDisabledNotice:
	default:
		notice = companyLoginFailedNotice
	}
	http.Redirect(w, r, "/login?notice="+notice, http.StatusSeeOther)
}

// companyLoginAvailable reports whether the login page should offer company
// sign-in. It defers to the service's operational availability check, so the
// page never advertises a path that cannot complete.
func (s *Server) companyLoginAvailable(r *http.Request) bool {
	if s.cfg.CompanyOIDCService == nil || !s.cfg.CompanyOIDCSecretEncryptionConfigured {
		return false
	}
	return s.cfg.CompanyOIDCService.LoginAvailable(r.Context())
}

// companyLoginNoticeMessage maps the login-page notice parameter to generic
// copy. Both messages are identical for every account and every failure
// cause, so the notice discloses nothing about accounts or provider state.
func companyLoginNoticeMessage(values url.Values) string {
	switch values.Get("notice") {
	case companyLoginFailedNotice:
		return "Company sign-in was not completed. Try again, or sign in with your password."
	case companyLoginUnavailableNotice:
		return "Company sign-in is not available right now. Sign in with your password."
	case companyLoginDisabledNotice:
		return "Company login is disabled. Sign in with your password."
	}
	return ""
}

func (s *Server) setCompanyLoginCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     companyLoginCookieName,
		Value:    token,
		Path:     companyLoginCookiePath,
		MaxAge:   companyLoginCookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie(r),
	})
}

func (s *Server) clearCompanyLoginCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     companyLoginCookieName,
		Value:    "",
		Path:     companyLoginCookiePath,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie(r),
	})
}

// exactCompanyLoginCookie mirrors exactTestSignInSessionCookie: a request
// carrying zero or multiple browser-binding cookies resolves to no token.
func exactCompanyLoginCookie(r *http.Request) string {
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name != companyLoginCookieName {
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
		if connection.Enabled {
			data.TestSignInAvailable = false
			data.TestSignInReason = "Disable company login before testing sign-in."
		}
		if connection.TestSignInEvidence != nil {
			data.TestSignInCompleted = true
			data.TestSignInRevision = connection.TestSignInEvidence.ConfigRevision
			data.TestSignInTime = connection.TestSignInEvidence.VerifiedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		data.Enabled = connection.Enabled
		if connection.Enabled && s.cfg.CompanyOIDCSecretEncryptionConfigured {
			data.CompanyLoginOperational = s.cfg.CompanyOIDCService.LoginAvailable(r.Context())
		}
		if identity := connection.Identity; identity != nil {
			data.Linked = true
			data.LinkedEmail = identity.Email
			data.LinkedAt = identity.LinkedAt.UTC().Format("2006-01-02 15:04:05 UTC")
			data.LinkedMatches = identity.MatchesConnection
			data.LinkedIsSelf = session.UserID != nil && *session.UserID == identity.UserID
		}
		evidenceCurrent := connection.TestSignInEvidence != nil &&
			connection.TestSignInEvidence.ConfigRevision == connection.Revision
		ready := s.cfg.CompanyOIDCSecretEncryptionConfigured && data.MetadataVerified && evidenceCurrent
		data.ReadyToEnable = ready
		data.CanLink = ready && !data.Linked && !connection.Enabled
		canEnable := ready && data.Linked && data.LinkedMatches && !connection.Enabled
		if canEnable {
			// The service recheck is offline: it never performs discovery or
			// other provider network work.
			canEnable = s.cfg.CompanyOIDCService.EnableReady(r.Context())
		}
		data.CanEnable = canEnable
		data.CanUnlink = data.Linked && !connection.Enabled && data.LinkedIsSelf
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

func parseCompanyOIDCRevisionForm(requestURL *url.URL, values url.Values) (int64, error) {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return 0, errors.New("query values are not allowed")
	}
	if len(values) != 2 || len(values[csrfFormField]) != 1 || len(values["expected_revision"]) != 1 {
		return 0, errors.New("revision form is malformed")
	}
	revision, err := canonicalExpectedRevision(values.Get("expected_revision"))
	if err != nil || revision == 0 {
		return 0, errors.New("expected revision is invalid")
	}
	return revision, nil
}

func parseCompanyOIDCPasswordForm(requestURL *url.URL, values url.Values) (int64, string, error) {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return 0, "", errors.New("query values are not allowed")
	}
	if len(values) != 3 || len(values[csrfFormField]) != 1 ||
		len(values["expected_revision"]) != 1 || len(values["current_password"]) != 1 {
		return 0, "", errors.New("password confirmation form is malformed")
	}
	revision, err := canonicalExpectedRevision(values.Get("expected_revision"))
	if err != nil || revision == 0 {
		return 0, "", errors.New("expected revision is invalid")
	}
	return revision, values.Get("current_password"), nil
}

func parseCompanyOIDCLoginForm(requestURL *url.URL, values url.Values) error {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return errors.New("query values are not allowed")
	}
	if len(values) != 1 || len(values[csrfFormField]) != 1 {
		return errors.New("company login form must contain exactly one CSRF field")
	}
	return nil
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
		companyOIDCTestUnknownNotice,
		companyOIDCEnabledGuardNotice,
		companyOIDCLinkedNotice,
		companyOIDCLinkPasswordNotice,
		companyOIDCLinkUnavailableNotice,
		companyOIDCLinkAuthorityNotice,
		companyOIDCLinkProviderNotice,
		companyOIDCLinkTransactionNotice,
		companyOIDCLinkUnknownNotice,
		companyOIDCEnabledNotice,
		companyOIDCEnableStaleNotice,
		companyOIDCEnableNotReadyNotice,
		companyOIDCEnableUnavailableNotice,
		companyOIDCEnableAuthorityNotice,
		companyOIDCEnableUnknownNotice,
		companyOIDCDisabledNotice,
		companyOIDCDisableStaleNotice,
		companyOIDCDisableAuthorityNotice,
		companyOIDCDisableUnknownNotice,
		companyOIDCUnlinkedNotice,
		companyOIDCUnlinkPasswordNotice,
		companyOIDCUnlinkEnabledNotice,
		companyOIDCUnlinkStaleNotice,
		companyOIDCUnlinkAuthorityNotice,
		companyOIDCUnlinkUnknownNotice:
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
		message = "Configured client credentials were accepted. Thawguard verified the OIDC authorization/code flow, signed ID token, and a signed, verified email in a saved allowed domain. The connection remains Draft and disabled."
		tone = "success"
	case companyOIDCTestProviderDeniedNotice:
		message = "The provider denied this Test sign-in. The connection remains Draft and disabled."
	case companyOIDCTestProviderUnavailable:
		message = "The provider was unavailable during Test sign-in. No identity or session was created."
	case companyOIDCTestProviderInvalid:
		message = "The provider returned an invalid sign-in response or did not supply a signed, verified email in a saved allowed domain. Review the provider configuration before trying again."
		tone = "danger"
	case companyOIDCTestConfigurationNotice:
		message = "Test sign-in could not use the saved client configuration. Check client-secret encryption and the saved provider credentials."
		tone = "danger"
	case companyOIDCTestTransactionNotice:
		message = "The Test sign-in transaction, session, or Draft revision is no longer available. Start a new Test sign-in from Authentication settings."
	case companyOIDCTestUnknownNotice:
		message = "Thawguard could not confirm the Test sign-in outcome. Review Activity before trying again."
		tone = "danger"
	case companyOIDCEnabledGuardNotice:
		message = "This action is unavailable while company login is enabled. Disable company login first."
	case companyOIDCLinkedNotice:
		message = "Your company identity is linked. Company login stays disabled until it is explicitly enabled."
		tone = "success"
	case companyOIDCLinkPasswordNotice:
		message = "The current password was not accepted. No company identity was linked."
	case companyOIDCLinkUnavailableNotice:
		message = "Company identity linking is unavailable. Confirm the connection is verified, tested, disabled, and not already linked, then try again."
	case companyOIDCLinkAuthorityNotice:
		message = "Administrator authority or session state changed before linking could start. No company identity was linked."
		tone = "danger"
	case companyOIDCLinkProviderNotice:
		message = "The provider did not complete this linking attempt. No company identity was linked."
	case companyOIDCLinkTransactionNotice:
		message = "The linking transaction, session, or connection state is no longer current. Start linking again from Authentication settings."
	case companyOIDCLinkUnknownNotice:
		message = "Thawguard could not confirm the linking outcome. Review the linked identity and Activity before trying again."
		tone = "danger"
	case companyOIDCEnabledNotice:
		message = "Company login is enabled for the linked Administrator. Local password sign-in remains available."
		tone = "success"
	case companyOIDCEnableStaleNotice:
		message = "The connection changed before company login could be enabled. Review the saved connection and try again."
	case companyOIDCEnableNotReadyNotice:
		message = "Company login requires a current verified metadata check, current Test sign-in evidence, and a linked Administrator that matches this connection."
	case companyOIDCEnableUnavailableNotice:
		message = "Company login cannot be enabled until client-secret encryption and the saved configuration are available."
	case companyOIDCEnableAuthorityNotice:
		message = "Administrator authority changed before company login could be enabled."
		tone = "danger"
	case companyOIDCEnableUnknownNotice:
		message = "Thawguard could not confirm whether company login was enabled. Review the connection state and Activity before retrying."
		tone = "danger"
	case companyOIDCDisabledNotice:
		message = "Company login is disabled. All company sign-in sessions were revoked."
		tone = "success"
	case companyOIDCDisableStaleNotice:
		message = "The connection changed before company login could be disabled. Reload and try again."
	case companyOIDCDisableAuthorityNotice:
		message = "Administrator authority changed before company login could be disabled."
		tone = "danger"
	case companyOIDCDisableUnknownNotice:
		message = "Thawguard could not confirm whether company login was disabled. Review the connection state and Activity before retrying."
		tone = "danger"
	case companyOIDCUnlinkedNotice:
		message = "The linked company identity was removed. Pending company sign-ins and company sessions were revoked."
		tone = "success"
	case companyOIDCUnlinkPasswordNotice:
		message = "The current password was not accepted. The company identity remains linked."
	case companyOIDCUnlinkEnabledNotice:
		message = "Disable company login before unlinking the company identity."
	case companyOIDCUnlinkStaleNotice:
		message = "The connection changed before the identity could be unlinked. Reload and try again."
	case companyOIDCUnlinkAuthorityNotice:
		message = "Only the linked Administrator can unlink their own company identity."
		tone = "danger"
	case companyOIDCUnlinkUnknownNotice:
		message = "Thawguard could not confirm the unlink outcome. Review the linked identity and Activity before trying again."
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
