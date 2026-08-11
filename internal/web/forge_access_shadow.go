package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

// Shadow access is the Administrator-only manual snapshot of explicit
// Forgejo relationships for every linked-identity x bound-repository pair.
// Everything shown here is evidence from one credential-visible snapshot:
// it never grants authority, changes enforcement, or predicts role changes.

const (
	forgeShadowConfirmValue = "shadow-only"

	forgeShadowCompleteNotice    = "forge-shadow-complete"
	forgeShadowIncompleteNotice  = "forge-shadow-incomplete"
	forgeShadowStaleNotice       = "forge-shadow-stale"
	forgeShadowRunningNotice     = "forge-shadow-running"
	forgeShadowInterruptedNotice = "forge-shadow-interrupted"
	forgeShadowAuthorityNotice   = "forge-shadow-authority"
	forgeShadowUnavailableNotice = "forge-shadow-unavailable"
	forgeShadowInvalidNotice     = "forge-shadow-invalid"
	forgeShadowUnknownNotice     = "forge-shadow-unknown"
)

// ForgeAccessShadowService is the narrow consumer boundary of the manual
// shadow-access snapshot slice.
type ForgeAccessShadowService interface {
	View(ctx context.Context) (forgeconnection.AccessShadowView, error)
	Run(ctx context.Context, actorUserID int64, input forgeconnection.RunAccessShadowInput) (forgeconnection.AccessSyncResultCode, error)
}

// forgeShadowSectionView is the summary card state shared by the Forge
// access page and the details page header.
type forgeShadowSectionView struct {
	Available bool
	LoadError bool
	Ready     bool

	SetupEvidenceCurrent bool
	IdentityCount        int
	BindingCount         int
	WithinLimits         bool

	HasAttempt        bool
	AttemptLabel      string
	AttemptTone       string
	AttemptDetail     string
	AttemptStartedAt  string
	AttemptFinishedAt string

	HasSnapshot        bool
	SnapshotLabel      string
	SnapshotTone       string
	SnapshotDetail     string
	SnapshotObservedAt string
	SnapshotAge        string
	PresentCount       int64
	AbsentCount        int64
	UnknownCount       int64
	PairCount          int64

	// Hidden run-form fences, rendered exactly as loaded.
	ConnectionID           string
	ConfigRevision         string
	CheckGeneration        string
	BindingRevision        string
	AccessIdentityRevision string
	NewestRunID            string
}

type forgeShadowPairRowView struct {
	UserLabel          string
	UserEmail          string
	UserStateLabel     string
	UserStateTone      string
	UsernameAtLink     string
	RepositoryFullName string
	StateLabel         string
	StateTone          string
	ReasonText         string
	ObservedAt         string
	// PriorConfirmedLabel and PriorConfirmedAt render beneath a newer
	// unknown when an earlier confirmation is preserved.
	PriorConfirmedLabel string
	PriorConfirmedAt    string
}

type forgeShadowPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	LoadError     string
	HasConnection bool
	Shadow        forgeShadowSectionView
	Rows          []forgeShadowPairRowView
	RowsAvailable bool
}

func (s *Server) handleForgeAccessShadow(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	data := forgeShadowPageData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Shadow access",
		ActivePage:  "forge-access",
		CurrentUser: currentUserFromSession(session),
		CSRFToken:   session.CSRFToken,
		CSRFField:   csrfFormField,
		Toasts:      forgeAccessNoticeToasts(r.URL.Query()),
	}
	if s.cfg.ForgeAccessShadowService == nil {
		data.LoadError = "Shadow access is not configured on this installation."
		s.renderPageStatus(w, http.StatusServiceUnavailable, "layouts/forge-access-shadow", data)
		return
	}
	view, err := s.cfg.ForgeAccessShadowService.View(r.Context())
	if err != nil {
		data.LoadError = "Thawguard could not load the shadow access evidence. No secret value was retrieved."
		s.renderPageStatus(w, http.StatusInternalServerError, "layouts/forge-access-shadow", data)
		return
	}
	data.HasConnection = view.HasConnection
	data.Shadow = forgeShadowSection(view)
	data.Rows = forgeShadowPairRows(view.Pairs)
	data.RowsAvailable = len(data.Rows) > 0
	s.renderPageStatus(w, http.StatusOK, "layouts/forge-access-shadow", data)
}

func (s *Server) handleForgeAccessShadowRun(w http.ResponseWriter, r *http.Request) {
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
	input, err := parseForgeShadowRunForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeAccessShadowService == nil || !s.cfg.ForgeConnectionSecretEncryptionConfigured {
		redirectForgeAccessNotice(w, r, forgeShadowUnavailableNotice)
		return
	}
	result, err := s.cfg.ForgeAccessShadowService.Run(r.Context(), *session.UserID, input)
	if err != nil {
		notice := forgeShadowUnknownNotice
		switch {
		case forgeconnection.IsValidationError(err):
			notice = forgeShadowInvalidNotice
		case errors.Is(err, forgeconnection.ErrConflict), errors.Is(err, forgeconnection.ErrNoConnection):
			notice = forgeShadowStaleNotice
		case errors.Is(err, forgeconnection.ErrAccessSyncRunning):
			notice = forgeShadowRunningNotice
		case errors.Is(err, forgeconnection.ErrAccessSyncInterrupted):
			notice = forgeShadowInterruptedNotice
		case errors.Is(err, forgeconnection.ErrAuthorization):
			notice = forgeShadowAuthorityNotice
		case errors.Is(err, forgeconnection.ErrConfiguration):
			notice = forgeShadowUnavailableNotice
		}
		redirectForgeAccessNotice(w, r, notice)
		return
	}
	if result == forgeconnection.AccessSyncComplete {
		redirectForgeAccessNotice(w, r, forgeShadowCompleteNotice)
		return
	}
	redirectForgeAccessNotice(w, r, forgeShadowIncompleteNotice)
}

// parseForgeShadowRunForm accepts exactly the CSRF field, the five revision
// fences, the newest-run CAS token, and the explicit shadow-only
// confirmation.
func parseForgeShadowRunForm(requestURL *url.URL, values url.Values) (forgeconnection.RunAccessShadowInput, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_config_revision",
		"expected_check_generation",
		"expected_binding_revision",
		"expected_access_identity_revision",
		"expected_newest_run_id",
		"confirm_shadow_only",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeconnection.RunAccessShadowInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, err
	}
	configRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_config_revision"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, err
	}
	checkGeneration, err := canonicalPositiveForgeAccessValue(values.Get("expected_check_generation"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, err
	}
	bindingRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_binding_revision"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, err
	}
	identityRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_access_identity_revision"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, err
	}
	newestRunID, err := canonicalExpectedRevision(values.Get("expected_newest_run_id"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, errors.New("expected newest run id is invalid")
	}
	if values.Get("confirm_shadow_only") != forgeShadowConfirmValue {
		return forgeconnection.RunAccessShadowInput{}, errors.New("shadow-only confirmation is invalid")
	}
	return forgeconnection.RunAccessShadowInput{
		ExpectedConnectionID:           connectionID,
		ExpectedConfigRevision:         configRevision,
		ExpectedCheckGeneration:        checkGeneration,
		ExpectedBindingRevision:        bindingRevision,
		ExpectedAccessIdentityRevision: identityRevision,
		ExpectedNewestRunID:            newestRunID,
		ConfirmShadowOnly:              true,
	}, nil
}

// forgeShadowSection derives the two display axes: the latest attempt and
// the latest completed snapshot.
func forgeShadowSection(view forgeconnection.AccessShadowView) forgeShadowSectionView {
	section := forgeShadowSectionView{
		Available:              true,
		Ready:                  view.Ready(),
		SetupEvidenceCurrent:   view.SetupEvidenceCurrent,
		IdentityCount:          view.IdentityCount,
		BindingCount:           view.BindingCount,
		WithinLimits:           view.WithinLimits,
		ConnectionID:           strconv.FormatInt(view.ConnectionID, 10),
		ConfigRevision:         strconv.FormatInt(view.ConfigRevision, 10),
		CheckGeneration:        strconv.FormatInt(view.CheckGeneration, 10),
		BindingRevision:        strconv.FormatInt(view.BindingRevision, 10),
		AccessIdentityRevision: strconv.FormatInt(view.AccessIdentityRevision, 10),
		NewestRunID:            strconv.FormatInt(view.NewestRunID, 10),
	}
	if view.LatestAttempt != nil {
		section.HasAttempt = true
		section.AttemptLabel, section.AttemptTone, section.AttemptDetail = forgeShadowAttemptPresentation(*view.LatestAttempt)
		section.AttemptStartedAt = view.LatestAttempt.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		if view.LatestAttempt.FinishedAt != nil {
			section.AttemptFinishedAt = view.LatestAttempt.FinishedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
	}
	section.SnapshotLabel, section.SnapshotTone, section.SnapshotDetail = forgeShadowSnapshotPresentation(view.LatestSnapshot)
	if view.LatestSnapshot != nil {
		section.HasSnapshot = true
		section.PresentCount = view.LatestSnapshot.PresentCount
		section.AbsentCount = view.LatestSnapshot.AbsentCount
		section.UnknownCount = view.LatestSnapshot.UnknownCount
		section.PairCount = view.LatestSnapshot.PairCount
		section.SnapshotObservedAt = view.LatestSnapshot.ObservedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		section.SnapshotAge = forgeShadowAge(view.LatestSnapshot.ObservedAt)
	}
	return section
}

func forgeShadowAttemptPresentation(attempt forgeconnection.AccessShadowAttempt) (string, string, string) {
	switch attempt.Status {
	case forgeconnection.AccessAttemptRunning:
		return "Running", "scheduled", "A snapshot attempt is running. Without a recorded result it becomes Interrupted after 75 seconds."
	case forgeconnection.AccessAttemptInterrupted:
		return "Interrupted", "warning", "The attempt recorded no result. The next run recovers it safely before starting new work."
	case forgeconnection.AccessAttemptCompleted:
		return "Completed", "success", "The attempt completed and published its credential-visible snapshot."
	case forgeconnection.AccessAttemptFailed:
		return "Failed", "danger", "The attempt finished without publishing: " + forgeShadowResultText(attempt.ResultCode)
	case forgeconnection.AccessAttemptSuperseded:
		return "Superseded", "warning", "The attempt predates the current connection scope; its result no longer describes the current configuration."
	default:
		return "Outcome unknown", "danger", "The attempt state could not be displayed safely."
	}
}

// forgeShadowResultText is the bounded cause-neutral copy for one sanitized
// result code. It never includes provider error text or raw statuses.
func forgeShadowResultText(code forgeconnection.AccessSyncResultCode) string {
	switch code {
	case forgeconnection.AccessSyncUnavailable:
		return "the installation could not be reached or did not answer in time."
	case forgeconnection.AccessSyncAuthenticationFailed:
		return "the service credential was not accepted."
	case forgeconnection.AccessSyncAuthorizationFailed:
		return "the service credential was denied read access it needs."
	case forgeconnection.AccessSyncServiceUserIsAdmin:
		return "the service account reports site-administrator rights."
	case forgeconnection.AccessSyncServiceUserChanged:
		return "the credential no longer belongs to the bound service account."
	case forgeconnection.AccessSyncOrganizationChanged:
		return "the bound organization identity could not be verified."
	case forgeconnection.AccessSyncCredentialUnavailable:
		return "the stored service credential could not be used."
	case forgeconnection.AccessSyncInvalidResponse:
		return "the installation returned a response the snapshot could not accept."
	case forgeconnection.AccessSyncPaginationIncomplete:
		return "a listing did not paginate completely within the approved limits."
	case forgeconnection.AccessSyncWorkLimitExceeded:
		return "the snapshot exceeded the approved work limits."
	case forgeconnection.AccessSyncScopeChanged:
		return "the connection scope changed while the snapshot ran."
	case forgeconnection.AccessSyncInterrupted:
		return "the attempt was interrupted before a result could be recorded."
	default:
		return "the result could not be displayed."
	}
}

func forgeShadowSnapshotPresentation(snapshot *forgeconnection.AccessShadowSnapshot) (string, string, string) {
	switch {
	case snapshot == nil:
		return "Never observed", "neutral", "No completed credential-visible snapshot exists yet."
	case !snapshot.ScopeCurrent:
		return "Scope changed", "warning", "The identity or binding scope changed after this snapshot; its evidence predates the current scope."
	case snapshot.UnknownCount == 0:
		return "Scope unchanged · complete", "success", "Every current pair carries confirmed evidence from the complete credential-visible snapshot."
	default:
		return "Scope unchanged · incomplete", "warning", "The snapshot completed but some pairs stayed unknown; earlier confirmations, where present, are preserved beneath them."
	}
}

// forgeShadowAge renders a coarse age. Ages inform the Administrator; the
// manual-only slice applies no freshness expiry.
func forgeShadowAge(observedAt time.Time) string {
	elapsed := time.Since(observedAt)
	switch {
	case elapsed < time.Minute:
		return "moments ago"
	case elapsed < time.Hour:
		return strconv.Itoa(int(elapsed.Minutes())) + " min ago"
	case elapsed < 48*time.Hour:
		return strconv.Itoa(int(elapsed.Hours())) + " h ago"
	default:
		return strconv.Itoa(int(elapsed.Hours()/24)) + " days ago"
	}
}

func forgeShadowPairRows(pairs []forgeconnection.AccessShadowPairRow) []forgeShadowPairRowView {
	rows := make([]forgeShadowPairRowView, 0, len(pairs))
	for _, pair := range pairs {
		row := forgeShadowPairRowView{
			UserLabel:          pair.UserDisplayName,
			UserEmail:          pair.UserEmail,
			UserStateLabel:     "Enabled",
			UserStateTone:      "neutral",
			UsernameAtLink:     pair.UsernameAtLink,
			RepositoryFullName: pair.RepositoryFullName,
		}
		if pair.UserDisabled {
			row.UserStateLabel = "Disabled"
			row.UserStateTone = "warning"
		}
		if !pair.Observed {
			row.StateLabel = "Never observed"
			row.StateTone = "neutral"
			row.ReasonText = "This current pair has not appeared in any completed credential-visible snapshot."
			rows = append(rows, row)
			continue
		}
		row.StateLabel, row.StateTone = forgeShadowStatePresentation(pair.LatestReason.State())
		row.ReasonText = forgeShadowReasonText(pair.LatestReason)
		row.ObservedAt = pair.LatestObservedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		if pair.PriorConfirmedReason != "" {
			label, _ := forgeShadowStatePresentation(pair.PriorConfirmedReason.State())
			row.PriorConfirmedLabel = label
			row.PriorConfirmedAt = pair.PriorConfirmedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		rows = append(rows, row)
	}
	return rows
}

func forgeShadowStatePresentation(state forgeconnection.AccessObservationState) (string, string) {
	switch state {
	case forgeconnection.AccessStateConfirmedPresent:
		return "Explicit access observed", "info"
	case forgeconnection.AccessStateConfirmedAbsent:
		return "No explicit access observed", "success"
	default:
		return "Unknown", "warning"
	}
}

// forgeShadowReasonText is the bounded fixed copy per observation reason.
func forgeShadowReasonText(reason forgeconnection.AccessObservationReason) string {
	switch reason {
	case forgeconnection.AccessReasonDirectCollaborator:
		return "An explicit direct-collaborator relationship was observed with positive effective permission."
	case forgeconnection.AccessReasonTeamAccess:
		return "An explicit team-to-repository relationship was observed with positive effective permission."
	case forgeconnection.AccessReasonNoExplicitAccessNone:
		return "No explicit relationship appeared in the complete credential-visible snapshot and the effective permission was none."
	case forgeconnection.AccessReasonIdentityUnresolved:
		return "The linked identity could not be resolved in this credential-visible snapshot."
	case forgeconnection.AccessReasonRepositoryUnavailable:
		return "The bound repository was not visible in this credential-visible snapshot."
	case forgeconnection.AccessReasonVisibilitySourceUnproven:
		return "A positive effective permission was observed without any explicit relationship, so its source is unproven."
	case forgeconnection.AccessReasonPermissionUnavailable:
		return "The effective permission for this pair could not be read."
	case forgeconnection.AccessReasonPermissionUnrecognized:
		return "The reported permission value was not recognized."
	case forgeconnection.AccessReasonEvidenceInconsistent:
		return "The observed relationships and the effective permission disagreed."
	default:
		return "This observation could not be displayed safely."
	}
}
