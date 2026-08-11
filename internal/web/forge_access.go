package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
	"github.com/taua-almeida/thawguard/internal/forgeidentity"
)

// Forge access is the Administrator-only Forgejo connection and repository
// identity-binding surface. Bindings are inert metadata: they do not add or
// mutate repositories, grant authority, route operations, or prove scopes.

const (
	// forgeAccessSaveMaxBodyBytes caps POST /settings/forge-access before
	// parsing: short fields plus a 2048-byte URL and a 1024-byte PAT.
	forgeAccessSaveMaxBodyBytes   int64 = 16 << 10
	forgeAccessActionMaxBodyBytes int64 = 8 << 10

	// forgeAccessPreviewPageSize is the fixed preview page length.
	forgeAccessPreviewPageSize = 20
	// forgeAccessSearchMaxBytes bounds the preview search input.
	forgeAccessSearchMaxBytes = 100

	forgeAccessPATAttestedValue  = "attested"
	forgeAccessConfirmResetValue = "delete"

	forgeAccessSavedNotice           = "forge-saved"
	forgeAccessSaveStaleNotice       = "forge-save-stale"
	forgeAccessSaveAuthorityNotice   = "forge-save-authority"
	forgeAccessSaveUnavailableNotice = "forge-save-unavailable"
	forgeAccessSaveUnknownNotice     = "forge-save-unknown"

	forgeAccessCheckedNotice          = "forge-checked"
	forgeAccessCheckStaleNotice       = "forge-check-stale"
	forgeAccessCheckIncompleteNotice  = "forge-check-incomplete"
	forgeAccessCheckUnavailableNotice = "forge-check-unavailable"
	forgeAccessCheckAuthorityNotice   = "forge-check-authority"
	forgeAccessCheckUnknownNotice     = "forge-check-unknown"

	forgeAccessResetNotice           = "forge-reset"
	forgeAccessResetStaleNotice      = "forge-reset-stale"
	forgeAccessResetBindingsNotice   = "forge-reset-bindings"
	forgeAccessResetIdentitiesNotice = "forge-reset-identities"
	forgeAccessResetAuthorityNotice  = "forge-reset-authority"
	forgeAccessResetUnknownNotice    = "forge-reset-unknown"
)

// ForgeConnectionService is the narrow consumer boundary of the Forge
// connection preview slice.
type ForgeConnectionService interface {
	Current(ctx context.Context) (forgeconnection.Connection, bool, error)
	RepositoryBindings(ctx context.Context, connectionID int64) (forgeconnection.RepositoryBindingReadModel, error)
	Create(ctx context.Context, actorUserID int64, input forgeconnection.CreateInput) error
	Edit(ctx context.Context, actorUserID int64, input forgeconnection.EditInput) error
	Reset(ctx context.Context, actorUserID int64, input forgeconnection.ResetInput) error
	Check(ctx context.Context, actorUserID int64, expectedConnectionID, expectedRevision int64) (forgeconnection.SetupCheck, error)
	BindRepository(ctx context.Context, actorUserID int64, input forgeconnection.BindRepositoryInput) error
	UnbindRepository(ctx context.Context, actorUserID int64, input forgeconnection.UnbindRepositoryInput) error
}

type forgeAccessFormView struct {
	DisplayName      string
	BaseURL          string
	OrganizationSlug string
	// ExpectedConnectionID pins mutations to one never-reused internal id;
	// "0" only on the create form.
	ExpectedConnectionID string
	ExpectedRevision     string
}

type forgeAccessCheckStateView struct {
	// State: "never", "incomplete", "current", or "stale".
	State      string
	Heading    string
	Summary    string
	Tone       string
	ResultText string
	CheckedAt  string
	Version    string
}

type forgeAccessRepositoryRowView struct {
	RepositoryID        int64
	RepositoryCreatedAt string
	LocalFullName       string
	LocalDefaultBranch  string
	LocalStateLabel     string
	LocalStateTone      string
	RemoteFullName      string
	// RemoteMissingLabel is the observed-repository cell text when no single
	// remote locator can be displayed.
	RemoteMissingLabel  string
	RemoteDefaultBranch string
	VisibilityLabel     string
	VisibilityTone      string
	ObservedAt          string
	BindingLabel        string
	BindingTone         string
	BindingSummary      string
	CanBind             bool
	CanUnbind           bool
}

type forgeAccessPreviewQuery struct {
	Search  string
	Status  string
	Binding string
	Page    int
}

type forgeAccessPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	ServiceAvailable    bool
	EncryptionAvailable bool
	HasConnection       bool
	Connection          forgeconnection.Connection
	Bound               bool
	OrganizationLabel   string
	PATAttestedAt       string
	ShowForm            bool
	Editing             bool
	Form                forgeAccessFormView
	FormError           string

	CheckState forgeAccessCheckStateView
	CheckReady bool

	PreviewAvailable bool
	PreviewStale     bool
	PreviewLabel     string
	PreviewRows      []forgeAccessRepositoryRowView
	PreviewEmpty     bool
	PreviewNoMatch   bool
	PreviewChips     []filterChip
	BindingChips     []filterChip
	PreviewSearch    string
	PreviewStatus    string
	BindingFilter    string
	PreviewPager     *tablePager
	PreviewTotal     int
	HasBindings      bool
	BindConfirm      *forgeAccessRepositoryRowView
	UnbindConfirm    *forgeAccessRepositoryRowView

	ResetConfirmOpen bool
	LoadError        string

	// OAuth client card for Forgejo identity linking. States: unavailable
	// (no service), unconfigured, enabled, disabled, stale (bound base URL
	// no longer matches the connection), plus encryption-unavailable and
	// outcome-unknown notices.
	OAuthAvailable          bool
	OAuthConfigured         bool
	OAuthEnabled            bool
	OAuthStale              bool
	OAuthClientID           string
	OAuthRevision           string
	OAuthCallbackURI        string
	OAuthFormOpen           bool
	OAuthFormError          string
	OAuthDisableConfirmOpen bool
	HasIdentities           bool

	// Shadow is the manual shadow-access snapshot summary card.
	Shadow               forgeShadowSectionView
	ShadowRunConfirmOpen bool
}

// forgeAccessRenderState carries one render's submitted-form and error
// state so rejected saves re-render without echoing credentials.
type forgeAccessRenderState struct {
	SubmittedForm     forgeAccessFormView
	FormError         string
	ShowSubmittedForm bool
	OAuthFormError    string
}

func (s *Server) handleForgeAccess(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	s.renderForgeAccess(w, r, http.StatusOK, session, forgeAccessRenderState{})
}

func (s *Server) handleForgeAccessSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeAccessSaveMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	form, connectionID, revision, attested, pat, err := parseForgeAccessSaveForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeConnectionService == nil || !s.cfg.ForgeConnectionSecretEncryptionConfigured {
		redirectForgeAccessNotice(w, r, forgeAccessSaveUnavailableNotice)
		return
	}

	if revision == 0 {
		err = s.cfg.ForgeConnectionService.Create(r.Context(), *session.UserID, forgeconnection.CreateInput{
			DisplayName:      form.DisplayName,
			BaseURL:          form.BaseURL,
			OrganizationSlug: form.OrganizationSlug,
			ServicePAT:       pat,
			PATAttested:      attested,
		})
	} else {
		err = s.cfg.ForgeConnectionService.Edit(r.Context(), *session.UserID, forgeconnection.EditInput{
			DisplayName:            form.DisplayName,
			BaseURL:                form.BaseURL,
			OrganizationSlug:       form.OrganizationSlug,
			ReplacementPAT:         pat,
			ReplacementPATAttested: attested,
			ExpectedConnectionID:   connectionID,
			ExpectedRevision:       revision,
		})
	}
	switch {
	case err == nil:
		http.Redirect(w, r, "/settings/forge-access?notice="+forgeAccessSavedNotice, http.StatusSeeOther)
	case forgeconnection.IsValidationError(err):
		// Re-render the form with the submitted non-secret values; the PAT
		// is never redisplayed.
		s.renderForgeAccess(w, r, http.StatusBadRequest, session, forgeAccessRenderState{
			SubmittedForm:     form,
			FormError:         err.Error(),
			ShowSubmittedForm: true,
		})
	case errors.Is(err, forgeconnection.ErrConflict):
		redirectForgeAccessNotice(w, r, forgeAccessSaveStaleNotice)
	case errors.Is(err, forgeconnection.ErrConfiguration):
		redirectForgeAccessNotice(w, r, forgeAccessSaveUnavailableNotice)
	case errors.Is(err, forgeconnection.ErrAuthorization):
		redirectForgeAccessNotice(w, r, forgeAccessSaveAuthorityNotice)
	default:
		redirectForgeAccessNotice(w, r, forgeAccessSaveUnknownNotice)
	}
}

func (s *Server) handleForgeAccessCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeAccessActionMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	connectionID, revision, err := parseForgeAccessRevisionForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeConnectionService == nil || !s.cfg.ForgeConnectionSecretEncryptionConfigured {
		redirectForgeAccessNotice(w, r, forgeAccessCheckUnavailableNotice)
		return
	}
	if _, err := s.cfg.ForgeConnectionService.Check(r.Context(), *session.UserID, connectionID, revision); err != nil {
		notice := forgeAccessCheckUnknownNotice
		switch {
		case errors.Is(err, forgeconnection.ErrConflict),
			errors.Is(err, forgeconnection.ErrNoConnection),
			errors.Is(err, forgeconnection.ErrCheckStale):
			notice = forgeAccessCheckStaleNotice
		case errors.Is(err, forgeconnection.ErrCheckIncomplete):
			notice = forgeAccessCheckIncompleteNotice
		case errors.Is(err, forgeconnection.ErrConfiguration):
			notice = forgeAccessCheckUnavailableNotice
		case errors.Is(err, forgeconnection.ErrAuthorization):
			notice = forgeAccessCheckAuthorityNotice
		}
		redirectForgeAccessNotice(w, r, notice)
		return
	}
	redirectForgeAccessNotice(w, r, forgeAccessCheckedNotice)
}

func (s *Server) handleForgeAccessReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeAccessActionMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	connectionID, revision, bindingRevision, oauthRevision, err := parseForgeAccessResetForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeConnectionService == nil {
		redirectForgeAccessNotice(w, r, forgeAccessResetUnknownNotice)
		return
	}
	if err := s.cfg.ForgeConnectionService.Reset(r.Context(), *session.UserID, forgeconnection.ResetInput{
		ExpectedConnectionID:    connectionID,
		ExpectedRevision:        revision,
		ExpectedBindingRevision: bindingRevision,
		ExpectedOAuthRevision:   oauthRevision,
		ConfirmReset:            true,
	}); err != nil {
		notice := forgeAccessResetUnknownNotice
		switch {
		case errors.Is(err, forgeconnection.ErrConflict):
			notice = forgeAccessResetStaleNotice
		case errors.Is(err, forgeconnection.ErrBindingsExist):
			notice = forgeAccessResetBindingsNotice
		case errors.Is(err, forgeconnection.ErrIdentitiesExist):
			notice = forgeAccessResetIdentitiesNotice
		case errors.Is(err, forgeconnection.ErrAuthorization):
			notice = forgeAccessResetAuthorityNotice
		}
		redirectForgeAccessNotice(w, r, notice)
		return
	}
	redirectForgeAccessNotice(w, r, forgeAccessResetNotice)
}

// renderForgeAccess assembles the whole page: connection metadata, check
// evidence state, the OAuth client card, and the retained preview with its
// bounded search, status filter, and fixed 20-row pagination.
func (s *Server) renderForgeAccess(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	session sessionState,
	state forgeAccessRenderState,
) {
	submittedForm := state.SubmittedForm
	formError := state.FormError
	showSubmittedForm := state.ShowSubmittedForm
	data := forgeAccessPageData{
		AppName:             s.cfg.AppName,
		PageTitle:           "Forge access",
		ActivePage:          "forge-access",
		CurrentUser:         currentUserFromSession(session),
		CSRFToken:           session.CSRFToken,
		CSRFField:           csrfFormField,
		ServiceAvailable:    s.cfg.ForgeConnectionService != nil,
		EncryptionAvailable: s.cfg.ForgeConnectionSecretEncryptionConfigured,
		Toasts:              forgeAccessNoticeToasts(r.URL.Query()),
	}
	if !data.ServiceAvailable {
		data.LoadError = "Forge access is not configured on this installation."
		s.renderPageStatus(w, http.StatusServiceUnavailable, "layouts/forge-access", data)
		return
	}
	connection, found, err := s.cfg.ForgeConnectionService.Current(r.Context())
	if err != nil {
		data.LoadError = "Thawguard could not load the saved Forge connection. No secret value was retrieved. Try again after checking the installation database."
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/forge-access", data)
		return
	}
	data.HasConnection = found
	if !found {
		data.ShowForm = data.EncryptionAvailable
		data.Form = forgeAccessFormView{ExpectedConnectionID: "0", ExpectedRevision: "0"}
		if showSubmittedForm {
			data.Form = submittedForm
			data.FormError = formError
		}
		s.renderPageStatus(w, status, "layouts/forge-access", data)
		return
	}

	data.Connection = connection
	data.Bound = connection.Bound()
	data.OrganizationLabel = connection.OrganizationSlug
	if connection.Organization != nil {
		data.OrganizationLabel = connection.Organization.Slug
	}
	data.PATAttestedAt = connection.PATAttestedAt.UTC().Format("2006-01-02 15:04:05 UTC")
	data.CheckState = forgeAccessCheckState(connection)
	data.CheckReady = data.EncryptionAvailable
	data.ResetConfirmOpen = r.URL.Query().Get("reset") == "confirm"
	data.ShadowRunConfirmOpen = r.URL.Query().Get("shadow") == "run"
	if !s.loadForgeAccessOAuthClient(w, &data, connection, r, state.OAuthFormError) {
		return
	}
	s.loadForgeAccessShadowSection(r.Context(), &data)
	if showSubmittedForm {
		data.ShowForm = true
		data.Editing = true
		data.Form = submittedForm
		data.FormError = formError
	} else if r.URL.Query().Get("edit") == "1" && data.EncryptionAvailable {
		data.ShowForm = true
		data.Editing = true
		data.Form = forgeAccessFormView{
			DisplayName:          connection.DisplayName,
			BaseURL:              connection.BaseURL,
			OrganizationSlug:     connection.OrganizationSlug,
			ExpectedConnectionID: strconv.FormatInt(connection.ID, 10),
			ExpectedRevision:     strconv.FormatInt(connection.Revision, 10),
		}
	}

	repositories, err := s.cfg.ForgeConnectionService.RepositoryBindings(r.Context(), connection.ID)
	if err != nil && !errors.Is(err, forgeconnection.ErrNoConnection) {
		data.LoadError = "Thawguard could not load repository binding states."
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/forge-access", data)
		return
	}
	// ErrNoConnection means a concurrent reset removed the connection after
	// Current loaded it; render the empty model and let the next load show
	// the no-connection state.
	s.buildForgeAccessPreview(&data, connection, repositories, r.URL.Query())
	s.renderPageStatus(w, status, "layouts/forge-access", data)
}

// loadForgeAccessShadowSection fills the shadow-access summary card. A load
// failure degrades the card to its error state instead of failing the page.
func (s *Server) loadForgeAccessShadowSection(ctx context.Context, data *forgeAccessPageData) {
	if s.cfg.ForgeAccessShadowService == nil {
		return
	}
	view, err := s.cfg.ForgeAccessShadowService.View(ctx)
	if err != nil {
		data.Shadow = forgeShadowSectionView{Available: true, LoadError: true}
		return
	}
	data.Shadow = forgeShadowSection(view)
}

// loadForgeAccessOAuthClient fills the OAuth client card state. The
// expected OAuth revision also fences the connection reset, so it is
// resolved even when the card itself is unavailable ("0" fails closed).
// It reports false when it already wrote an error response.
func (s *Server) loadForgeAccessOAuthClient(
	w http.ResponseWriter,
	data *forgeAccessPageData,
	connection forgeconnection.Connection,
	r *http.Request,
	oauthFormError string,
) bool {
	data.OAuthRevision = "0"
	data.OAuthAvailable = s.cfg.ForgeIdentityService != nil
	if !data.OAuthAvailable {
		return true
	}
	client, configured, err := s.cfg.ForgeIdentityService.OAuthClient(r.Context())
	if err != nil {
		data.LoadError = "Thawguard could not load the Forgejo OAuth client configuration. No secret value was retrieved."
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/forge-access", *data)
		return false
	}
	hasIdentities, err := s.cfg.ForgeIdentityService.HasIdentities(r.Context())
	if err != nil {
		data.LoadError = "Thawguard could not load the linked Forgejo identity state."
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/forge-access", *data)
		return false
	}
	data.HasIdentities = hasIdentities
	data.OAuthConfigured = configured
	data.OAuthCallbackURI = s.cfg.PublicURL + forgeidentity.CallbackPath
	data.OAuthFormError = oauthFormError
	if configured {
		data.OAuthEnabled = client.Enabled
		data.OAuthClientID = client.ClientID
		data.OAuthRevision = strconv.FormatInt(client.Revision, 10)
		data.OAuthStale = client.Enabled && client.BoundBaseURL != connection.BaseURL
	}
	data.OAuthFormOpen = oauthFormError != "" ||
		(r.URL.Query().Get("oauth") == "edit" && data.EncryptionAvailable)
	data.OAuthDisableConfirmOpen = r.URL.Query().Get("oauth") == "disable"
	return true
}

// forgeAccessCheckState derives the evidence state shown at the top of the
// saved-connection card. Evidence is current only when both the revision and
// the check generation match the connection.
func forgeAccessCheckState(connection forgeconnection.Connection) forgeAccessCheckStateView {
	check := connection.SetupCheck
	switch {
	case check == nil && connection.CheckGeneration == 0:
		return forgeAccessCheckStateView{
			State:   "never",
			Heading: "Never checked",
			Summary: "Run a check to observe the repositories visible to the attested credential. The check is read-only: no roles change and no repositories are added.",
			Tone:    "info",
		}
	case check == nil ||
		check.ConfigRevision == connection.Revision && check.CheckGeneration < connection.CheckGeneration:
		return forgeAccessCheckStateView{
			State:   "incomplete",
			Heading: "Check incomplete; run again.",
			Summary: "A check was started but no result was recorded for it. Run the check again.",
			Tone:    "warning",
		}
	case check.ConfigRevision != connection.Revision:
		return forgeAccessCheckStateView{
			State:   "stale",
			Heading: "Evidence predates the current revision",
			Summary: "The connection was edited after this result was recorded. Run a fresh check against the saved revision.",
			Tone:    "warning",
			// The stale result itself stays visible below the banner.
			ResultText: forgeAccessResultText(*check),
			CheckedAt:  check.CheckedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			Version:    check.ObservedVersion,
		}
	default:
		view := forgeAccessCheckStateView{
			State:      "current",
			Heading:    "Current check result",
			Summary:    forgeAccessResultText(*check),
			CheckedAt:  check.CheckedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			Version:    check.ObservedVersion,
			ResultText: forgeAccessResultText(*check),
		}
		switch check.ResultCode {
		case forgeconnection.CheckVisibleInventoryObserved:
			view.Tone = "success"
			view.Heading = "Visible inventory observed"
		case forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven:
			view.Tone = "warning"
			view.Heading = "Visible inventory observed; private read unproven"
		default:
			view.Tone = "danger"
			view.Heading = "Check failed"
		}
		return view
	}
}

// forgeAccessResultText is the bounded cause-neutral copy for one sanitized
// result code. It never includes provider error text or raw statuses.
func forgeAccessResultText(check forgeconnection.SetupCheck) string {
	switch check.ResultCode {
	case forgeconnection.CheckVisibleInventoryObserved:
		visible, private := int64(0), int64(0)
		if check.VisibleRepositoryCount != nil {
			visible = *check.VisibleRepositoryCount
		}
		if check.VisiblePrivateRepositoryCount != nil {
			private = *check.VisiblePrivateRepositoryCount
		}
		return "A stable snapshot recorded " + strconv.FormatInt(visible, 10) +
			" repositories visible to this attested credential (" + strconv.FormatInt(private, 10) +
			" private). Reading one visible private repository succeeded, so private-read capability was observed for this snapshot."
	case forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven:
		visible := int64(0)
		if check.VisibleRepositoryCount != nil {
			visible = *check.VisibleRepositoryCount
		}
		return "A stable snapshot recorded " + strconv.FormatInt(visible, 10) +
			" repositories visible to this attested credential. No private repository was visible, so private-read capability is unproven."
	case forgeconnection.CheckUnavailable:
		return "The installation could not be reached or did not answer in time."
	case forgeconnection.CheckInvalidResponse:
		return "The installation returned a response the check could not accept."
	case forgeconnection.CheckAuthenticationFailed:
		return "The saved service PAT was not accepted."
	case forgeconnection.CheckAuthorizationFailed:
		return "The saved service PAT was denied read access it needs."
	case forgeconnection.CheckServiceUserIsAdmin:
		return "The service account reports site-administrator rights. Use a dedicated non-administrator organization owner and replace the PAT."
	case forgeconnection.CheckServiceUserChanged:
		return "The saved PAT no longer belongs to the bound service account."
	case forgeconnection.CheckOrganizationUnavailable:
		return "The configured organization was not among the organizations visible to this credential."
	case forgeconnection.CheckOrganizationChanged:
		return "The bound organization identity was no longer visible to this credential."
	case forgeconnection.CheckPaginationIncomplete:
		return "The repository listing did not paginate consistently, so no snapshot was recorded."
	case forgeconnection.CheckInventoryLimitExceeded:
		return "The visible inventory exceeded the preview limits, so no snapshot was recorded."
	default:
		return "The check result could not be displayed."
	}
}

func (s *Server) buildForgeAccessPreview(
	data *forgeAccessPageData,
	connection forgeconnection.Connection,
	repositories forgeconnection.RepositoryBindingReadModel,
	query url.Values,
) {
	data.PreviewAvailable = len(repositories.Rows) > 0
	if !data.PreviewAvailable && !connection.Bound() {
		// Nothing was ever observed: the section shows only the
		// "No preview recorded yet" state, never a staleness label.
		return
	}
	data.PreviewStale = !repositories.Current
	data.PreviewLabel = "Repository bindings and current preview"
	if data.PreviewStale {
		data.PreviewLabel = "Repository bindings and last observed preview"
	}
	if !data.PreviewAvailable {
		data.PreviewEmpty = true
		return
	}

	previewQuery := forgeAccessPreviewQueryFromValues(query)
	filtered := make([]forgeAccessRepositoryRowView, 0, len(repositories.Rows))
	search := strings.ToLower(previewQuery.Search)
	bindID, bindOpen := forgeAccessConfirmationRepositoryID(query, "bind")
	unbindID, unbindOpen := forgeAccessConfirmationRepositoryID(query, "unbind")
	for _, repository := range repositories.Rows {
		view := forgeAccessRepositoryRow(repository)
		if repository.State.Bound() {
			data.HasBindings = true
		}
		if bindOpen && repository.RepositoryID == bindID && repository.State.CanBind() {
			confirmation := view
			data.BindConfirm = &confirmation
		}
		if unbindOpen && repository.RepositoryID == unbindID && repository.State.CanUnbind() {
			confirmation := view
			data.UnbindConfirm = &confirmation
		}
		if previewQuery.Status == "private" &&
			(repository.RemotePrivate == nil || !*repository.RemotePrivate) {
			continue
		}
		if previewQuery.Status == "public" &&
			(repository.RemotePrivate == nil || *repository.RemotePrivate) {
			continue
		}
		switch previewQuery.Binding {
		case "ready":
			if !repository.State.CanBind() {
				continue
			}
		case "bound":
			if repository.State != forgeconnection.RepositoryBindingCurrent {
				continue
			}
		case "attention":
			if !repository.State.Attention() {
				continue
			}
		case "unmatched":
			if repository.State != forgeconnection.RepositoryBindingUnmatched {
				continue
			}
		}
		// RemoteFullNames keeps conflict rows searchable by retained locators
		// that are not selected for display.
		searchText := strings.ToLower(repository.LocalFullName + " " + strings.Join(repository.RemoteFullNames, " "))
		if search != "" && !strings.Contains(searchText, search) {
			continue
		}
		filtered = append(filtered, view)
	}
	data.PreviewTotal = len(filtered)
	data.PreviewNoMatch = len(filtered) == 0
	data.PreviewSearch = previewQuery.Search
	data.PreviewStatus = previewQuery.Status
	data.BindingFilter = previewQuery.Binding

	lastPage := max((len(filtered)+forgeAccessPreviewPageSize-1)/forgeAccessPreviewPageSize, 1)
	page := min(max(previewQuery.Page, 1), lastPage)
	start := (page - 1) * forgeAccessPreviewPageSize
	end := min(start+forgeAccessPreviewPageSize, len(filtered))
	data.PreviewRows = append(data.PreviewRows, filtered[start:end]...)

	urlFor := func(override func(*forgeAccessPreviewQuery)) string {
		next := previewQuery
		next.Page = 1
		if override != nil {
			override(&next)
		}
		return forgeAccessURL(next)
	}
	data.PreviewChips = filterChips(previewQuery.Status, []filterChipOption{
		{Value: "", Label: "All"},
		{Value: "private", Label: "Private"},
		{Value: "public", Label: "Public"},
	}, func(value string) string {
		return urlFor(func(next *forgeAccessPreviewQuery) { next.Status = value })
	})
	data.BindingChips = filterChips(previewQuery.Binding, []filterChipOption{
		{Value: "", Label: "All"},
		{Value: "ready", Label: "Ready"},
		{Value: "bound", Label: "Bound"},
		{Value: "attention", Label: "Attention"},
		{Value: "unmatched", Label: "Unmatched"},
	}, func(value string) string {
		return urlFor(func(next *forgeAccessPreviewQuery) { next.Binding = value })
	})
	data.PreviewPager = paginateTable(len(filtered), page, forgeAccessPreviewPageSize, func(page int) string {
		next := previewQuery
		next.Page = page
		return forgeAccessURL(next)
	})
}

func forgeAccessRepositoryRow(repository forgeconnection.RepositoryBindingRow) forgeAccessRepositoryRowView {
	label, tone, summary := forgeAccessRepositoryBindingPresentation(repository.State)
	row := forgeAccessRepositoryRowView{
		RepositoryID:        repository.RepositoryID,
		RepositoryCreatedAt: repository.RepositoryCreatedAt,
		LocalFullName:       repository.LocalFullName,
		LocalDefaultBranch:  repository.LocalDefaultBranch,
		RemoteFullName:      repository.RemoteFullName,
		RemoteMissingLabel:  "Not visible in the retained preview",
		RemoteDefaultBranch: repository.RemoteDefaultBranch,
		VisibilityLabel:     "Unknown",
		VisibilityTone:      "neutral",
		BindingLabel:        label,
		BindingTone:         tone,
		BindingSummary:      summary,
		CanBind:             repository.State.CanBind(),
		CanUnbind:           repository.State.CanUnbind(),
	}
	if repository.LocalFullName != "" {
		row.LocalStateLabel = "Inactive"
		row.LocalStateTone = "warning"
		if repository.LocalActive {
			row.LocalStateLabel = "Active"
			row.LocalStateTone = "neutral"
		}
	}
	if repository.State == forgeconnection.RepositoryBindingIdentityConflict && row.RemoteFullName == "" {
		row.RemoteMissingLabel = "Conflicting current locators"
	}
	if repository.RemotePrivate != nil {
		row.VisibilityLabel = "Public"
		if *repository.RemotePrivate {
			row.VisibilityLabel = "Private"
			row.VisibilityTone = "frozen"
		}
	}
	if !repository.ObservedAt.IsZero() {
		row.ObservedAt = repository.ObservedAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	return row
}

func forgeAccessRepositoryBindingPresentation(state forgeconnection.RepositoryBindingState) (string, string, string) {
	switch state {
	case forgeconnection.RepositoryBindingLastObservedOnly:
		return "Last observed only", "warning", "The immutable binding remains, but no current successful preview can confirm its locator."
	case forgeconnection.RepositoryBindingPreviewNotCurrent:
		return "Preview not current", "warning", "This retained preview row cannot be used to create a binding. Run a successful current check."
	case forgeconnection.RepositoryBindingIdentityConflict:
		return "Identity conflict", "danger", "Current local or remote identities collide at this locator. Review the duplicate or replacement before changing the binding."
	case forgeconnection.RepositoryBindingLocatorDrift:
		return "Locator drift", "warning", "The bound remote identity is visible, but its current owner/name locator no longer exactly matches the local repository."
	case forgeconnection.RepositoryBindingCurrent:
		return "Bound and current", "success", "The immutable binding and current exact locator match. This does not prove authority, scopes, or enforcement readiness."
	case forgeconnection.RepositoryBindingNotVisible:
		return "Not visible in latest preview", "warning", "The immutable binding remains, but its remote identity was not visible to the latest successful credential check."
	case forgeconnection.RepositoryBindingReady:
		return "Ready to bind", "info", "Exactly one current remote identity matches exactly one existing local repository."
	case forgeconnection.RepositoryBindingUnmatched:
		return "Unmatched", "neutral", "No existing local repository has this exact canonical Forge locator. Local repositories recorded for another forge type are never matched."
	case forgeconnection.RepositoryBindingMultipleLocalMatches:
		return "Multiple local matches", "danger", "More than one compatible local repository has this canonical locator, so binding is ambiguous."
	case forgeconnection.RepositoryBindingDuplicateRemoteLocator:
		return "Duplicate remote locator", "danger", "More than one current remote identity reports this owner/name locator, so binding is ambiguous."
	default:
		return "Unavailable", "danger", "This repository binding state could not be displayed safely."
	}
}

func forgeAccessPreviewQueryFromValues(values url.Values) forgeAccessPreviewQuery {
	query := forgeAccessPreviewQuery{Page: 1}
	search := strings.TrimSpace(values.Get("q"))
	if len(search) <= forgeAccessSearchMaxBytes && utf8.ValidString(search) && !strings.ContainsFunc(search, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		query.Search = search
	}
	switch values.Get("status") {
	case "private":
		query.Status = "private"
	case "public":
		query.Status = "public"
	}
	switch values.Get("binding") {
	case "ready", "bound", "attention", "unmatched":
		query.Binding = values.Get("binding")
	}
	if page, err := strconv.Atoi(strings.TrimSpace(values.Get("page"))); err == nil && page > 1 && page <= 1_000_000 {
		query.Page = page
	}
	return query
}

func forgeAccessURL(query forgeAccessPreviewQuery) string {
	params := url.Values{}
	if query.Search != "" {
		params.Set("q", query.Search)
	}
	if query.Status != "" {
		params.Set("status", query.Status)
	}
	if query.Binding != "" {
		params.Set("binding", query.Binding)
	}
	if query.Page > 1 {
		params.Set("page", strconv.Itoa(query.Page))
	}
	if len(params) == 0 {
		return "/settings/forge-access"
	}
	return "/settings/forge-access?" + params.Encode()
}

func parseForgeAccessSaveForm(requestURL *url.URL, values url.Values) (forgeAccessFormView, int64, int64, bool, string, error) {
	fail := func(message string) (forgeAccessFormView, int64, int64, bool, string, error) {
		return forgeAccessFormView{}, 0, 0, false, "", errors.New(message)
	}
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return fail("query values are not allowed")
	}
	required := []string{csrfFormField, "display_name", "base_url", "organization_slug", "service_pat", "expected_connection_id", "expected_revision"}
	allowed := map[string]bool{"pat_attested": true}
	for _, field := range required {
		allowed[field] = true
	}
	for key, fieldValues := range values {
		if !allowed[key] || len(fieldValues) != 1 {
			return fail("unexpected or duplicate form field")
		}
	}
	for _, field := range required {
		if len(values[field]) != 1 {
			return fail("required form field is missing")
		}
	}
	if len(values["pat_attested"]) == 1 && values.Get("pat_attested") != forgeAccessPATAttestedValue {
		return fail("attestation value is invalid")
	}
	connectionID, err := canonicalExpectedRevision(values.Get("expected_connection_id"))
	if err != nil {
		return fail("expected connection id is invalid")
	}
	revision, err := canonicalExpectedRevision(values.Get("expected_revision"))
	if err != nil {
		return fail("expected revision is invalid")
	}
	// A create targets no connection (both zero); an edit targets exactly
	// one never-reused id at one revision (both positive).
	if (connectionID == 0) != (revision == 0) {
		return fail("expected connection id and revision are inconsistent")
	}
	form := forgeAccessFormView{
		DisplayName:          values.Get("display_name"),
		BaseURL:              values.Get("base_url"),
		OrganizationSlug:     values.Get("organization_slug"),
		ExpectedConnectionID: values.Get("expected_connection_id"),
		ExpectedRevision:     values.Get("expected_revision"),
	}
	attested := values.Get("pat_attested") == forgeAccessPATAttestedValue
	return form, connectionID, revision, attested, values.Get("service_pat"), nil
}

// parseForgeAccessRevisionForm accepts exactly the CSRF field and a positive
// canonical expected connection id and revision.
func parseForgeAccessRevisionForm(requestURL *url.URL, values url.Values) (int64, int64, error) {
	fields := []string{csrfFormField, "expected_connection_id", "expected_revision"}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return 0, 0, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return 0, 0, errors.New("expected connection id is invalid")
	}
	revision, err := canonicalPositiveForgeAccessValue(values.Get("expected_revision"))
	if err != nil {
		return 0, 0, errors.New("expected revision is invalid")
	}
	return connectionID, revision, nil
}

func redirectForgeAccessNotice(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, "/settings/forge-access?notice="+notice, http.StatusSeeOther)
}

func forgeAccessNoticeToasts(values url.Values) []toastView {
	if len(values) != 1 || len(values["notice"]) != 1 {
		return nil
	}
	message := ""
	tone := "warning"
	switch values.Get("notice") {
	case forgeAccessSavedNotice:
		message = "Forge connection saved. Nothing was checked yet, no roles changed, and no repositories were added."
		tone = "success"
	case forgeAccessSaveStaleNotice:
		message = "The saved connection changed before this save. Reload Forge access and review the saved revision before editing again. No submitted PAT is retained."
	case forgeAccessSaveAuthorityNotice:
		message = "Administrator authority changed before this save could be recorded."
		tone = "danger"
	case forgeAccessSaveUnavailableNotice:
		message = "Saving is unavailable until service PAT encryption is configured."
	case forgeAccessSaveUnknownNotice:
		message = "Thawguard could not confirm whether the connection was saved. Reload Forge access and inspect the saved revision before retrying."
		tone = "danger"
	case forgeAccessCheckedNotice:
		message = "Check recorded. The result below reflects only what this attested credential could observe."
		tone = "success"
	case forgeAccessCheckStaleNotice:
		message = "The saved connection changed while the check ran, so no result was recorded. Run the check again."
	case forgeAccessCheckIncompleteNotice:
		message = "The check could not be completed and no result was recorded. Run it again; replacing the PAT and reset remain available."
	case forgeAccessCheckUnavailableNotice:
		message = "Checking is unavailable until service PAT encryption is configured."
	case forgeAccessCheckAuthorityNotice:
		message = "Administrator authority changed before this check could be recorded."
		tone = "danger"
	case forgeAccessCheckUnknownNotice:
		message = "Thawguard could not confirm whether a result was recorded. Inspect the evidence below before retrying."
		tone = "danger"
	case forgeAccessResetNotice:
		message = "Forge connection reset. The connection, its preview, and its evidence were deleted; no local repositories or roles were affected."
		tone = "success"
	case forgeAccessResetStaleNotice:
		message = "The saved connection changed before the reset. Reload Forge access and confirm again."
	case forgeAccessResetBindingsNotice:
		message = "Reset is blocked while repository bindings exist. Unbind every repository first; repository-owned data will remain unchanged."
	case forgeAccessResetIdentitiesNotice:
		message = "Reset is blocked while linked Forgejo identities exist. Every identity must be unlinked or purged first."
	case forgeAccessResetAuthorityNotice:
		message = "Administrator authority changed before the reset could be recorded."
		tone = "danger"
	case forgeAccessResetUnknownNotice:
		message = "Thawguard could not confirm the reset outcome. Reload Forge access before retrying."
		tone = "danger"
	case forgeAccessBoundNotice:
		message = "Repository identity bound. No repository settings, credentials, grants, freezes, schedules, or enforcement state changed."
		tone = "success"
	case forgeAccessBindStaleNotice:
		message = "The connection, preview, binding revision, or local repository incarnation changed before binding. Reload and review the current state."
	case forgeAccessBindUnavailableNotice:
		message = "This repository is not ready to bind. A current successful preview and one exact local and remote match are required."
	case forgeAccessBindAuthorityNotice:
		message = "Administrator authority changed before the repository binding could be recorded."
		tone = "danger"
	case forgeAccessBindUnknownNotice:
		message = "Thawguard could not confirm the repository binding outcome. Reload Forge access before retrying."
		tone = "danger"
	case forgeAccessUnboundNotice:
		message = "Repository identity unbound. All repository-owned data and operational state were left unchanged."
		tone = "success"
	case forgeAccessUnbindStaleNotice:
		message = "The connection or binding revision changed before unbinding. Reload and review the current state."
	case forgeAccessUnbindUnavailableNotice:
		message = "This repository binding could not be removed from the submitted state. Reload Forge access and try again."
	case forgeAccessUnbindAuthorityNotice:
		message = "Administrator authority changed before the repository binding could be removed."
		tone = "danger"
	case forgeAccessUnbindUnknownNotice:
		message = "Thawguard could not confirm the repository unbind outcome. Reload Forge access before retrying."
		tone = "danger"
	case forgeOAuthSavedNotice:
		message = "Forgejo OAuth client saved and enabled. Every pending link attempt started under the previous configuration was cancelled."
		tone = "success"
	case forgeOAuthDisabledNotice:
		message = "Forgejo OAuth client disabled. Its credentials were destroyed and every pending link attempt was cancelled. Linked identities remain."
		tone = "success"
	case forgeOAuthStaleNotice:
		message = "The OAuth client configuration changed before this save. Reload Forge access and review the saved state before retrying. No submitted secret is retained."
	case forgeOAuthAuthorityNotice:
		message = "Administrator authority changed before the OAuth client change could be recorded."
		tone = "danger"
	case forgeOAuthUnavailableNotice:
		message = "Saving the OAuth client is unavailable until secret encryption is configured."
	case forgeOAuthUnknownNotice:
		message = "Thawguard could not confirm whether the OAuth client change was recorded. Reload Forge access and inspect the saved state before retrying."
		tone = "danger"
	case forgeShadowCompleteNotice:
		message = "Shadow snapshot completed. The evidence below covers exactly what this credential could observe; no roles or authority changed."
		tone = "success"
	case forgeShadowIncompleteNotice:
		message = "The shadow snapshot attempt finished with a failure result and published no pair evidence. See the latest attempt state."
	case forgeShadowStaleNotice:
		message = "The connection, its evidence, or the run history changed before this snapshot could start. Reload and review the current state."
	case forgeShadowRunningNotice:
		message = "A shadow snapshot is already running. Wait for it to finish or become Interrupted after 75 seconds."
	case forgeShadowInterruptedNotice:
		message = "The shadow snapshot was interrupted before a result could be recorded. The next run recovers it safely."
	case forgeShadowAuthorityNotice:
		message = "Administrator authority changed before the shadow snapshot could start."
		tone = "danger"
	case forgeShadowUnavailableNotice:
		message = "Shadow snapshots are unavailable until the Forge connection service and secret encryption are configured."
	case forgeShadowInvalidNotice:
		message = "The shadow snapshot cannot start from the submitted state. Review the prerequisites and the small-alpha limits."
	case forgeShadowUnknownNotice:
		message = "Thawguard could not confirm the shadow snapshot outcome. Reload Forge access and inspect the latest attempt before retrying."
		tone = "danger"
	default:
		return nil
	}
	return []toastView{{Message: message, Tone: tone, DismissHref: "/settings/forge-access"}}
}
