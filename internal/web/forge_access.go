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
)

// Forge access is the Administrator-only Forgejo connection preview: one
// saved installation and organization, a write-only Administrator-attested
// service PAT, a non-mutating check, and the read-only list of repositories
// visible to that credential. Nothing on this page adds repositories,
// changes roles, or proves provider-side scopes.

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

	forgeAccessResetNotice          = "forge-reset"
	forgeAccessResetStaleNotice     = "forge-reset-stale"
	forgeAccessResetAuthorityNotice = "forge-reset-authority"
	forgeAccessResetUnknownNotice   = "forge-reset-unknown"
)

// ForgeConnectionService is the narrow consumer boundary of the Forge
// connection preview slice.
type ForgeConnectionService interface {
	Current(ctx context.Context) (forgeconnection.Connection, bool, error)
	VisibleRepositories(ctx context.Context, connectionID int64) ([]forgeconnection.VisibleRepository, error)
	Create(ctx context.Context, actorUserID int64, input forgeconnection.CreateInput) error
	Edit(ctx context.Context, actorUserID int64, input forgeconnection.EditInput) error
	Reset(ctx context.Context, actorUserID int64, input forgeconnection.ResetInput) error
	Check(ctx context.Context, actorUserID int64, expectedConnectionID, expectedRevision int64) (forgeconnection.SetupCheck, error)
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
	FullName        string
	DefaultBranch   string
	VisibilityLabel string
	VisibilityTone  string
	ObservedAt      string
}

type forgeAccessPreviewQuery struct {
	Search string
	Status string
	Page   int
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
	PreviewSearch    string
	PreviewPager     *tablePager
	PreviewTotal     int

	ResetConfirmOpen bool
	LoadError        string
}

func (s *Server) handleForgeAccess(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	s.renderForgeAccess(w, r, http.StatusOK, session, forgeAccessFormView{}, "", false)
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
		s.renderForgeAccess(w, r, http.StatusBadRequest, session, form, err.Error(), true)
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
	connectionID, revision, err := parseForgeAccessRevisionForm(r.URL, r.PostForm, nil)
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
	connectionID, revision, err := parseForgeAccessRevisionForm(r.URL, r.PostForm, map[string]string{
		"confirm_reset": forgeAccessConfirmResetValue,
	})
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeConnectionService == nil {
		redirectForgeAccessNotice(w, r, forgeAccessResetUnknownNotice)
		return
	}
	if err := s.cfg.ForgeConnectionService.Reset(r.Context(), *session.UserID, forgeconnection.ResetInput{
		ExpectedConnectionID: connectionID,
		ExpectedRevision:     revision,
		ConfirmReset:         true,
	}); err != nil {
		notice := forgeAccessResetUnknownNotice
		switch {
		case errors.Is(err, forgeconnection.ErrConflict):
			notice = forgeAccessResetStaleNotice
		case errors.Is(err, forgeconnection.ErrAuthorization):
			notice = forgeAccessResetAuthorityNotice
		}
		redirectForgeAccessNotice(w, r, notice)
		return
	}
	redirectForgeAccessNotice(w, r, forgeAccessResetNotice)
}

// renderForgeAccess assembles the whole page: connection metadata, check
// evidence state, and the retained preview with its bounded search, status
// filter, and fixed 20-row pagination.
func (s *Server) renderForgeAccess(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	session sessionState,
	submittedForm forgeAccessFormView,
	formError string,
	showSubmittedForm bool,
) {
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

	repositories, err := s.cfg.ForgeConnectionService.VisibleRepositories(r.Context(), connection.ID)
	if err != nil {
		data.LoadError = "Thawguard could not load the retained repository preview."
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/forge-access", data)
		return
	}
	s.buildForgeAccessPreview(&data, connection, repositories, r.URL.Query())
	s.renderPageStatus(w, status, "layouts/forge-access", data)
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
	repositories []forgeconnection.VisibleRepository,
	query url.Values,
) {
	// Evidence is current only while its revision and generation match the
	// connection; a stale preview is the retained last observation.
	currentEvidence := connection.SetupCheck != nil &&
		connection.SetupCheck.ConfigRevision == connection.Revision &&
		connection.SetupCheck.CheckGeneration == connection.CheckGeneration &&
		connection.SetupCheck.ResultCode.Observed()

	data.PreviewAvailable = len(repositories) > 0
	if !data.PreviewAvailable {
		// Preview rows change only on a successful check, so a bound
		// connection with zero rows means the last successful check recorded
		// an empty visible inventory — even when a later edit, failure, or
		// interruption replaced the evidence row. Only a never-successfully-
		// checked connection has no recorded preview at all.
		if !connection.Bound() {
			return
		}
		data.PreviewEmpty = true
		data.PreviewStale = !currentEvidence
		data.PreviewLabel = "Repositories visible to this attested credential"
		if data.PreviewStale {
			data.PreviewLabel = "Last observed preview"
		}
		return
	}
	current := currentEvidence && repositories[0].ObservedCheckGeneration == connection.CheckGeneration
	data.PreviewStale = !current
	data.PreviewLabel = "Repositories visible to this attested credential"
	if data.PreviewStale {
		data.PreviewLabel = "Last observed preview"
	}

	previewQuery := forgeAccessPreviewQueryFromValues(query)
	filtered := make([]forgeconnection.VisibleRepository, 0, len(repositories))
	search := strings.ToLower(previewQuery.Search)
	for _, repository := range repositories {
		if previewQuery.Status == "private" && !repository.Private {
			continue
		}
		if previewQuery.Status == "public" && repository.Private {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(repository.Owner+"/"+repository.Name), search) {
			continue
		}
		filtered = append(filtered, repository)
	}
	data.PreviewTotal = len(filtered)
	data.PreviewNoMatch = len(filtered) == 0
	data.PreviewSearch = previewQuery.Search

	lastPage := max((len(filtered)+forgeAccessPreviewPageSize-1)/forgeAccessPreviewPageSize, 1)
	page := min(max(previewQuery.Page, 1), lastPage)
	start := (page - 1) * forgeAccessPreviewPageSize
	end := min(start+forgeAccessPreviewPageSize, len(filtered))
	for _, repository := range filtered[start:end] {
		row := forgeAccessRepositoryRowView{
			FullName:        repository.Owner + "/" + repository.Name,
			DefaultBranch:   repository.DefaultBranch,
			VisibilityLabel: "Public",
			VisibilityTone:  "neutral",
			ObservedAt:      repository.ObservedAt.UTC().Format("2006-01-02 15:04 UTC"),
		}
		if repository.Private {
			row.VisibilityLabel = "Private"
			row.VisibilityTone = "frozen"
		}
		data.PreviewRows = append(data.PreviewRows, row)
	}

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
	data.PreviewPager = paginateTable(len(filtered), page, forgeAccessPreviewPageSize, func(page int) string {
		next := previewQuery
		next.Page = page
		return forgeAccessURL(next)
	})
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

// parseForgeAccessRevisionForm accepts exactly the CSRF field, a positive
// canonical expected connection id and revision, and any extra exact-value
// fields.
func parseForgeAccessRevisionForm(requestURL *url.URL, values url.Values, extra map[string]string) (int64, int64, error) {
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		return 0, 0, errors.New("query values are not allowed")
	}
	if len(values) != 3+len(extra) || len(values[csrfFormField]) != 1 ||
		len(values["expected_connection_id"]) != 1 || len(values["expected_revision"]) != 1 {
		return 0, 0, errors.New("form is malformed")
	}
	for field, want := range extra {
		if len(values[field]) != 1 || values.Get(field) != want {
			return 0, 0, errors.New("form is malformed")
		}
	}
	connectionID, err := canonicalExpectedRevision(values.Get("expected_connection_id"))
	if err != nil || connectionID == 0 {
		return 0, 0, errors.New("expected connection id is invalid")
	}
	revision, err := canonicalExpectedRevision(values.Get("expected_revision"))
	if err != nil || revision == 0 {
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
	case forgeAccessResetAuthorityNotice:
		message = "Administrator authority changed before the reset could be recorded."
		tone = "danger"
	case forgeAccessResetUnknownNotice:
		message = "Thawguard could not confirm the reset outcome. Reload Forge access before retrying."
		tone = "danger"
	default:
		return nil
	}
	return []toastView{{Message: message, Tone: tone, DismissHref: "/settings/forge-access"}}
}
