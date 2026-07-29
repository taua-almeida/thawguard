package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/companyoidc"
)

const companyOIDCDraftMaxBodyBytes int64 = 32 << 10

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

func (s *Server) renderAuthenticationRead(w http.ResponseWriter, r *http.Request, status int, session sessionState) {
	connection, found, ok := s.currentCompanyOIDCConnection(w, r, session)
	if !ok {
		return
	}
	data := s.authenticationPageBase(session)
	data.Connection = connection
	data.HasConnection = found
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
