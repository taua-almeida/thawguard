package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeidentity"
)

// Forgejo identity linking: the /account card and ceremony endpoints, the
// strict fixed callback, and the Administrator OAuth client and purge
// surfaces. Linking proves identity only and grants no repository role.

const (
	forgeIdentityLinkMaxBodyBytes  int64 = 8 << 10
	forgeIdentityOAuthMaxBodyBytes int64 = 8 << 10
	forgeIdentityPurgeMaxBodyBytes int64 = 8 << 10

	forgeLinkCookieName   = "thawguard_forgejo_link"
	forgeLinkCookiePath   = "/account/forgejo"
	forgeLinkCookieMaxAge = 600

	forgeOAuthConfirmDisableValue = "disable"
	forgeIdentityConfirmPurge     = "purge"

	// forgeCallbackCSP locks the callback responses down entirely; they only
	// ever redirect.
	forgeCallbackCSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

	forgeLinkedNotice           = "forgejo-linked"
	forgeLinkDeniedNotice       = "forgejo-link-denied"
	forgeLinkProviderNotice     = "forgejo-link-provider"
	forgeLinkCollisionNotice    = "forgejo-link-collision"
	forgeLinkAlreadyNotice      = "forgejo-link-already"
	forgeLinkStaleNotice        = "forgejo-link-stale"
	forgeLinkUnknownNotice      = "forgejo-link-unknown"
	forgeLinkPasswordNotice     = "forgejo-link-password"
	forgeLinkUnavailableNotice  = "forgejo-link-unavailable"
	forgeLinkInProgressNotice   = "forgejo-link-progress"
	forgeLinkAuthorityNotice    = "forgejo-link-authority"
	forgeUnlinkedNotice         = "forgejo-unlinked"
	forgeUnlinkPasswordNotice   = "forgejo-unlink-password"
	forgeUnlinkStaleNotice      = "forgejo-unlink-stale"
	forgeUnlinkAuthorityNotice  = "forgejo-unlink-authority"
	forgeUnlinkUnknownNotice    = "forgejo-unlink-unknown"
	forgeOAuthSavedNotice       = "forge-oauth-saved"
	forgeOAuthDisabledNotice    = "forge-oauth-disabled"
	forgeOAuthStaleNotice       = "forge-oauth-stale"
	forgeOAuthAuthorityNotice   = "forge-oauth-authority"
	forgeOAuthUnavailableNotice = "forge-oauth-unavailable"
	forgeOAuthUnknownNotice     = "forge-oauth-unknown"
	forgeIdentityPurgedNotice   = "forge-identity-purged"
	forgePurgePasswordNotice    = "forge-purge-password"
	forgePurgeStaleNotice       = "forge-purge-stale"
	forgePurgeAuthorityNotice   = "forge-purge-authority"
	forgePurgeUnknownNotice     = "forge-purge-unknown"
)

// ForgeIdentityService is the narrow consumer boundary of the Forgejo
// identity linking slice.
type ForgeIdentityService interface {
	OAuthClient(ctx context.Context) (forgeidentity.OAuthClient, bool, error)
	SaveOAuthClient(ctx context.Context, actorUserID int64, input forgeidentity.SaveOAuthClientInput) error
	DisableOAuthClient(ctx context.Context, actorUserID int64, input forgeidentity.DisableOAuthClientInput) error
	AccountForUser(ctx context.Context, userID int64) (forgeidentity.AccountView, error)
	StartLink(ctx context.Context, input forgeidentity.StartLinkInput) (forgeidentity.LinkStart, error)
	CancelStart(ctx context.Context, handle forgeidentity.StartHandle) error
	CompleteLinkCallback(ctx context.Context, input forgeidentity.CallbackInput) (forgeidentity.LinkResultCode, error)
	Unlink(ctx context.Context, input forgeidentity.UnlinkInput) error
	Purge(ctx context.Context, input forgeidentity.PurgeInput) error
	IdentityForUser(ctx context.Context, userID int64) (forgeidentity.Identity, bool, error)
	HasIdentities(ctx context.Context) (bool, error)
}

type forgeIdentityView struct {
	ID       string
	Username string
	LinkedAt string
}

type accountPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	// ForgeStatus is one of "unavailable", "ready", "in_progress", "linked".
	ForgeStatus        string
	ForgeIdentity      *forgeIdentityView
	ForgeConnectionID  string
	ForgeOAuthRevision string
	UnlinkConfirmOpen  bool
}

type forgeProviderNavigationData struct {
	AppName          string
	PageTitle        string
	Theme            string
	AuthorizationURL string
}

// isForgeIdentityHeaderPath matches every Forgejo identity surface whose
// responses, including errors, carry the sensitive no-store header set. The
// exact callback path is excluded: the pre-mux guard already set its
// stricter no-referrer headers.
func isForgeIdentityHeaderPath(requestPath string) bool {
	if requestPath == "/account" {
		return true
	}
	if requestPath != forgeidentity.CallbackPath &&
		(requestPath == "/account/forgejo" || strings.HasPrefix(requestPath, "/account/forgejo/")) {
		return true
	}
	rest, ok := strings.CutPrefix(requestPath, "/users/")
	if !ok {
		return false
	}
	userID, suffix, ok := strings.Cut(rest, "/")
	return ok && userID != "" && suffix == "forge-identity/purge"
}

// forgeIdentityCallbackGuard runs before ServeMux path cleaning. It admits
// only an origin-form exact-path GET for the fixed callback at the
// canonical PublicURL authority and answers every equivalent spelling
// itself, without parsing the callback query, session, or cookies. It
// reports whether it wrote the response.
func (s *Server) forgeIdentityCallbackGuard(w http.ResponseWriter, r *http.Request) bool {
	if !forgeCallbackTargeted(r) {
		return false
	}
	setForgeCallbackHeaders(w)
	if r.URL.IsAbs() || !strings.HasPrefix(r.RequestURI, "/") {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	rawPath := r.RequestURI
	if separator := strings.IndexByte(rawPath, '?'); separator >= 0 {
		rawPath = rawPath[:separator]
	}
	// The raw request target, its parsed form, and its escaped form must all
	// be exactly the fixed path: trailing slashes, duplicate separators, dot
	// segments, and encoded separators or backslashes are rejected here
	// instead of being cleaned into a match.
	if rawPath != forgeidentity.CallbackPath ||
		r.URL.Path != forgeidentity.CallbackPath ||
		r.URL.EscapedPath() != forgeidentity.CallbackPath ||
		r.URL.RawPath != "" {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if !s.publicURLAuthorityMatches(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	return false
}

// forgeCallbackTargeted reports whether the request aims at the callback in
// any cleaned-equivalent or separator-encoded spelling.
func forgeCallbackTargeted(r *http.Request) bool {
	for _, candidate := range []string{r.URL.Path, strings.ReplaceAll(r.URL.Path, `\`, "/")} {
		if candidate == "" {
			continue
		}
		if candidate == forgeidentity.CallbackPath || path.Clean(candidate) == forgeidentity.CallbackPath {
			return true
		}
	}
	return false
}

// publicURLAuthorityMatches requires the request authority to equal the
// canonical PublicURL authority exactly. Forwarded headers are never
// consulted; the only supported deployments preserve the inbound Host.
func (s *Server) publicURLAuthorityMatches(r *http.Request) bool {
	parsed, err := url.Parse(s.cfg.PublicURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	return r.Host == parsed.Host
}

func setForgeCallbackHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", forgeCallbackCSP)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	s.renderAccount(w, r, http.StatusOK, session)
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, session sessionState) {
	data := accountPageData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Account",
		ActivePage:  "account",
		CurrentUser: currentUserFromSession(session),
		CSRFToken:   session.CSRFToken,
		CSRFField:   csrfFormField,
		ForgeStatus: string(forgeidentity.AccountUnavailable),
		Toasts:      forgeAccountNoticeToasts(r.URL.Query()),
	}
	// Linking requires a local credential; without one the card only ever
	// shows the unavailable state.
	if s.cfg.ForgeIdentityService != nil && session.UserID != nil && session.HasLocalPassword {
		view, err := s.cfg.ForgeIdentityService.AccountForUser(r.Context(), *session.UserID)
		if err != nil {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
			return
		}
		data.ForgeStatus = string(view.Status)
		data.ForgeConnectionID = strconv.FormatInt(view.ConnectionID, 10)
		data.ForgeOAuthRevision = strconv.FormatInt(view.OAuthRevision, 10)
		if view.Identity != nil {
			data.ForgeIdentity = &forgeIdentityView{
				ID:       strconv.FormatInt(view.Identity.ID, 10),
				Username: view.Identity.UsernameAtLink,
				LinkedAt: view.Identity.LinkedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			}
			data.UnlinkConfirmOpen = r.URL.Query().Get("unlink") == "confirm"
		}
	}
	s.renderPageStatus(w, status, "layouts/account", data)
}

func (s *Server) handleForgeIdentityLinkStart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeIdentityLinkMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireActionForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	password, connectionID, oauthRevision, err := parseForgeLinkStartForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeIdentityService == nil || s.cfg.AuthService == nil || !session.HasLocalPassword {
		redirectForgeAccountNotice(w, r, forgeLinkUnavailableNotice)
		return
	}
	if err := s.cfg.AuthService.VerifyCurrentPassword(r.Context(), *session.UserID, password); err != nil {
		notice := forgeLinkUnknownNotice
		if auth.IsAuthenticationError(err) {
			notice = forgeLinkPasswordNotice
		}
		redirectForgeAccountNotice(w, r, notice)
		return
	}
	start, err := s.cfg.ForgeIdentityService.StartLink(r.Context(), forgeidentity.StartLinkInput{
		ActorUserID:           *session.UserID,
		SessionID:             session.ID,
		ExpectedConnectionID:  connectionID,
		ExpectedOAuthRevision: oauthRevision,
	})
	if err != nil {
		notice := forgeLinkUnknownNotice
		switch {
		case errors.Is(err, forgeidentity.ErrAuthorization):
			notice = forgeLinkAuthorityNotice
		case errors.Is(err, forgeidentity.ErrLinkInProgress):
			notice = forgeLinkInProgressNotice
		case errors.Is(err, forgeidentity.ErrUnavailable), errors.Is(err, forgeidentity.ErrConfiguration):
			notice = forgeLinkUnavailableNotice
		}
		redirectForgeAccountNotice(w, r, notice)
		return
	}
	s.renderForgeProviderNavigation(w, r, start)
}

// renderForgeProviderNavigation renders the buffered same-origin provider
// continuation page fully before emitting the browser-binding cookie. If
// rendering fails after the pending row committed, exactly that row is
// cancelled through its request-local handle.
func (s *Server) renderForgeProviderNavigation(w http.ResponseWriter, r *http.Request, start forgeidentity.LinkStart) {
	data := forgeProviderNavigationData{
		AppName:          s.cfg.AppName,
		PageTitle:        "Continue to Forgejo",
		AuthorizationURL: start.AuthorizationURL,
	}
	var page strings.Builder
	if err := pageTemplates.ExecuteTemplate(&page, "layouts/forge-provider-navigation", data); err != nil {
		_ = s.cfg.ForgeIdentityService.CancelStart(r.Context(), start.Handle)
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/error", authErrorData{
			AppName:     s.cfg.AppName,
			PageTitle:   "Forgejo linking could not continue",
			Status:      http.StatusInternalServerError,
			Heading:     "Forgejo linking could not continue",
			Message:     "Thawguard could not display the page that continues to Forgejo. The prepared link attempt was cancelled. Return to your account and start again.",
			ActionHref:  "/account",
			ActionLabel: "Back to account",
		})
		return
	}
	w.Header().Set("Content-Security-Policy", providerNavigationCSP)
	s.setForgeLinkCookie(w, r, start.BrowserToken)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page.String()))
}

// handleForgeIdentityCallback serves the guarded fixed callback. The guard
// already rejected every non-canonical spelling; the shared browser cookie
// is deliberately never deleted here — it expires on its own.
func (s *Server) handleForgeIdentityCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ForgeIdentityService == nil {
		redirectForgeAccountNotice(w, r, forgeLinkStaleNotice)
		return
	}
	result, err := s.cfg.ForgeIdentityService.CompleteLinkCallback(r.Context(), forgeidentity.CallbackInput{
		RawQuery:     r.URL.RawQuery,
		SessionID:    exactForgeSessionCookie(r),
		BrowserToken: exactForgeLinkCookie(r),
	})
	if err != nil {
		redirectForgeAccountNotice(w, r, forgeLinkUnknownNotice)
		return
	}
	notice := map[forgeidentity.LinkResultCode]string{
		forgeidentity.LinkLinked:                   forgeLinkedNotice,
		forgeidentity.LinkProviderDenied:           forgeLinkDeniedNotice,
		forgeidentity.LinkProviderUnavailable:      forgeLinkProviderNotice,
		forgeidentity.LinkProviderInvalid:          forgeLinkProviderNotice,
		forgeidentity.LinkCollision:                forgeLinkCollisionNotice,
		forgeidentity.LinkAlreadyLinked:            forgeLinkAlreadyNotice,
		forgeidentity.LinkStale:                    forgeLinkStaleNotice,
		forgeidentity.LinkConfigurationUnavailable: forgeLinkUnavailableNotice,
	}[result]
	if notice == "" {
		notice = forgeLinkUnknownNotice
	}
	redirectForgeAccountNotice(w, r, notice)
}

func (s *Server) handleForgeIdentityUnlink(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeIdentityLinkMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireActionForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	password, identityID, err := parseForgeUnlinkForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeIdentityService == nil || s.cfg.AuthService == nil {
		redirectForgeAccountNotice(w, r, forgeUnlinkUnknownNotice)
		return
	}
	if err := s.cfg.AuthService.VerifyCurrentPassword(r.Context(), *session.UserID, password); err != nil {
		notice := forgeUnlinkUnknownNotice
		if auth.IsAuthenticationError(err) {
			notice = forgeUnlinkPasswordNotice
		}
		redirectForgeAccountNotice(w, r, notice)
		return
	}
	if err := s.cfg.ForgeIdentityService.Unlink(r.Context(), forgeidentity.UnlinkInput{
		ActorUserID: *session.UserID,
		SessionID:   session.ID,
		IdentityID:  identityID,
	}); err != nil {
		notice := forgeUnlinkUnknownNotice
		switch {
		case errors.Is(err, forgeidentity.ErrAuthorization):
			notice = forgeUnlinkAuthorityNotice
		case errors.Is(err, forgeidentity.ErrIdentityStale):
			notice = forgeUnlinkStaleNotice
		}
		redirectForgeAccountNotice(w, r, notice)
		return
	}
	redirectForgeAccountNotice(w, r, forgeUnlinkedNotice)
}

func (s *Server) handleForgeOAuthClientSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeIdentityOAuthMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	input, err := parseForgeOAuthSaveForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeIdentityService == nil || !s.cfg.ForgeConnectionSecretEncryptionConfigured {
		redirectForgeAccessNotice(w, r, forgeOAuthUnavailableNotice)
		return
	}
	if err := s.cfg.ForgeIdentityService.SaveOAuthClient(r.Context(), *session.UserID, input); err != nil {
		switch {
		case forgeidentity.IsValidationError(err):
			// Credentials are never echoed back; the form re-renders empty.
			s.renderForgeAccess(w, r, http.StatusBadRequest, session, forgeAccessRenderState{OAuthFormError: err.Error()})
		case errors.Is(err, forgeidentity.ErrConflict):
			redirectForgeAccessNotice(w, r, forgeOAuthStaleNotice)
		case errors.Is(err, forgeidentity.ErrAdminOnly):
			redirectForgeAccessNotice(w, r, forgeOAuthAuthorityNotice)
		case errors.Is(err, forgeidentity.ErrConfiguration):
			redirectForgeAccessNotice(w, r, forgeOAuthUnavailableNotice)
		default:
			redirectForgeAccessNotice(w, r, forgeOAuthUnknownNotice)
		}
		return
	}
	redirectForgeAccessNotice(w, r, forgeOAuthSavedNotice)
}

func (s *Server) handleForgeOAuthClientDisable(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeIdentityOAuthMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	input, err := parseForgeOAuthDisableForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeIdentityService == nil {
		redirectForgeAccessNotice(w, r, forgeOAuthUnknownNotice)
		return
	}
	if err := s.cfg.ForgeIdentityService.DisableOAuthClient(r.Context(), *session.UserID, input); err != nil {
		switch {
		case errors.Is(err, forgeidentity.ErrConflict):
			redirectForgeAccessNotice(w, r, forgeOAuthStaleNotice)
		case errors.Is(err, forgeidentity.ErrAdminOnly):
			redirectForgeAccessNotice(w, r, forgeOAuthAuthorityNotice)
		default:
			redirectForgeAccessNotice(w, r, forgeOAuthUnknownNotice)
		}
		return
	}
	redirectForgeAccessNotice(w, r, forgeOAuthDisabledNotice)
}

func (s *Server) handleForgeIdentityPurge(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeIdentityPurgeMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	targetUserID, valid := userIDFromPath(r)
	if !valid {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	password, identityID, err := parseForgePurgeForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeIdentityService == nil || s.cfg.AuthService == nil {
		redirectForgeUserNotice(w, r, targetUserID, forgePurgeUnknownNotice)
		return
	}
	if err := s.cfg.AuthService.VerifyCurrentPassword(r.Context(), *session.UserID, password); err != nil {
		notice := forgePurgeUnknownNotice
		if auth.IsAuthenticationError(err) {
			notice = forgePurgePasswordNotice
		}
		redirectForgeUserNotice(w, r, targetUserID, notice)
		return
	}
	if err := s.cfg.ForgeIdentityService.Purge(r.Context(), forgeidentity.PurgeInput{
		ActorUserID:  *session.UserID,
		SessionID:    session.ID,
		TargetUserID: targetUserID,
		IdentityID:   identityID,
		ConfirmPurge: true,
	}); err != nil {
		notice := forgePurgeUnknownNotice
		switch {
		case errors.Is(err, forgeidentity.ErrAdminOnly):
			notice = forgePurgeAuthorityNotice
		case errors.Is(err, forgeidentity.ErrIdentityStale):
			notice = forgePurgeStaleNotice
		}
		redirectForgeUserNotice(w, r, targetUserID, notice)
		return
	}
	redirectForgeUserNotice(w, r, targetUserID, forgeIdentityPurgedNotice)
}

func (s *Server) setForgeLinkCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     forgeLinkCookieName,
		Value:    token,
		Path:     forgeLinkCookiePath,
		MaxAge:   forgeLinkCookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie(r),
	})
}

// exactForgeLinkCookie resolves to a token only when the request carries
// exactly one browser-binding cookie.
func exactForgeLinkCookie(r *http.Request) string {
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name != forgeLinkCookieName {
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

// exactForgeSessionCookie resolves to a session id only when the request
// carries exactly one session cookie.
func exactForgeSessionCookie(r *http.Request) string {
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

func parseForgeLinkStartForm(requestURL *url.URL, values url.Values) (string, int64, int64, error) {
	fields := []string{csrfFormField, "current_password", "expected_connection_id", "expected_oauth_revision"}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return "", 0, 0, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return "", 0, 0, errors.New("expected connection id is invalid")
	}
	oauthRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_oauth_revision"))
	if err != nil {
		return "", 0, 0, errors.New("expected OAuth revision is invalid")
	}
	return values.Get("current_password"), connectionID, oauthRevision, nil
}

func parseForgeUnlinkForm(requestURL *url.URL, values url.Values) (string, int64, error) {
	fields := []string{csrfFormField, "current_password", "identity_id"}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return "", 0, err
	}
	identityID, err := canonicalPositiveForgeAccessValue(values.Get("identity_id"))
	if err != nil {
		return "", 0, errors.New("identity id is invalid")
	}
	return values.Get("current_password"), identityID, nil
}

func parseForgeOAuthSaveForm(requestURL *url.URL, values url.Values) (forgeidentity.SaveOAuthClientInput, error) {
	fields := []string{
		csrfFormField,
		"client_id",
		"client_secret",
		"expected_connection_id",
		"expected_revision",
		"expected_oauth_revision",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeidentity.SaveOAuthClientInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeidentity.SaveOAuthClientInput{}, errors.New("expected connection id is invalid")
	}
	revision, err := canonicalPositiveForgeAccessValue(values.Get("expected_revision"))
	if err != nil {
		return forgeidentity.SaveOAuthClientInput{}, errors.New("expected revision is invalid")
	}
	oauthRevision, err := canonicalExpectedRevision(values.Get("expected_oauth_revision"))
	if err != nil {
		return forgeidentity.SaveOAuthClientInput{}, errors.New("expected OAuth revision is invalid")
	}
	return forgeidentity.SaveOAuthClientInput{
		ExpectedConnectionID:       connectionID,
		ExpectedConnectionRevision: revision,
		ExpectedOAuthRevision:      oauthRevision,
		ClientID:                   values.Get("client_id"),
		ClientSecret:               values.Get("client_secret"),
	}, nil
}

func parseForgeOAuthDisableForm(requestURL *url.URL, values url.Values) (forgeidentity.DisableOAuthClientInput, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_revision",
		"expected_oauth_revision",
		"confirm_disable",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeidentity.DisableOAuthClientInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeidentity.DisableOAuthClientInput{}, errors.New("expected connection id is invalid")
	}
	revision, err := canonicalPositiveForgeAccessValue(values.Get("expected_revision"))
	if err != nil {
		return forgeidentity.DisableOAuthClientInput{}, errors.New("expected revision is invalid")
	}
	oauthRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_oauth_revision"))
	if err != nil {
		return forgeidentity.DisableOAuthClientInput{}, errors.New("expected OAuth revision is invalid")
	}
	if values.Get("confirm_disable") != forgeOAuthConfirmDisableValue {
		return forgeidentity.DisableOAuthClientInput{}, errors.New("disable confirmation is invalid")
	}
	return forgeidentity.DisableOAuthClientInput{
		ExpectedConnectionID:       connectionID,
		ExpectedConnectionRevision: revision,
		ExpectedOAuthRevision:      oauthRevision,
	}, nil
}

func parseForgePurgeForm(requestURL *url.URL, values url.Values) (string, int64, error) {
	fields := []string{csrfFormField, "current_password", "identity_id", "confirm_purge"}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return "", 0, err
	}
	identityID, err := canonicalPositiveForgeAccessValue(values.Get("identity_id"))
	if err != nil {
		return "", 0, errors.New("identity id is invalid")
	}
	if values.Get("confirm_purge") != forgeIdentityConfirmPurge {
		return "", 0, errors.New("purge confirmation is invalid")
	}
	return values.Get("current_password"), identityID, nil
}

func redirectForgeAccountNotice(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, "/account?notice="+notice, http.StatusSeeOther)
}

func redirectForgeUserNotice(w http.ResponseWriter, r *http.Request, userID int64, notice string) {
	http.Redirect(w, r, "/users/"+strconv.FormatInt(userID, 10)+"?notice="+notice, http.StatusSeeOther)
}

func forgeAccountNoticeToasts(values url.Values) []toastView {
	if len(values) != 1 || len(values["notice"]) != 1 {
		return nil
	}
	message := ""
	tone := "warning"
	switch values.Get("notice") {
	case forgeLinkedNotice:
		message = "Your Forgejo identity is linked. Linking proves identity only; it grants no repository access or role."
		tone = "success"
	case forgeLinkDeniedNotice:
		message = "Forgejo did not approve this linking attempt. No identity was linked."
	case forgeLinkProviderNotice:
		message = "Forgejo did not complete this linking attempt. No identity was linked."
	case forgeLinkCollisionNotice:
		message = "That Forgejo account is already linked elsewhere on this installation. No identity was linked."
		tone = "danger"
	case forgeLinkAlreadyNotice:
		message = "This account already has a linked Forgejo identity."
	case forgeLinkStaleNotice:
		message = "The link attempt, session, or configuration is no longer current. Start linking again from this page."
	case forgeLinkUnknownNotice:
		message = "Thawguard could not confirm the linking outcome. Review this page and Activity before trying again."
		tone = "danger"
	case forgeLinkPasswordNotice:
		message = "The current password was not accepted. No link attempt was started."
	case forgeLinkUnavailableNotice:
		message = "Forgejo identity linking is not available right now."
	case forgeLinkInProgressNotice:
		message = "A link attempt is already in progress for this account. It expires on its own within ten minutes."
	case forgeLinkAuthorityNotice:
		message = "Your account or session state changed before linking could start. No link attempt was started."
		tone = "danger"
	case forgeUnlinkedNotice:
		message = "The Forgejo identity was unlinked."
		tone = "success"
	case forgeUnlinkPasswordNotice:
		message = "The current password was not accepted. The identity remains linked."
	case forgeUnlinkStaleNotice:
		message = "The identity is no longer in the state this page showed. Reload and review before trying again."
	case forgeUnlinkAuthorityNotice:
		message = "Your account or session state changed before the identity could be unlinked."
		tone = "danger"
	case forgeUnlinkUnknownNotice:
		message = "Thawguard could not confirm the unlink outcome. Review this page and Activity before trying again."
		tone = "danger"
	default:
		return nil
	}
	return []toastView{{Message: message, Tone: tone, DismissHref: "/account"}}
}
