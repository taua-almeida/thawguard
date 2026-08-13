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

// Shadow access is the bounded manual and explicitly enabled periodic
// snapshot of explicit Forgejo relationships for every linked-identity x
// bound-repository pair. Everything shown here is credential-visible
// evidence: it never grants authority, changes enforcement, or predicts role
// changes.

const (
	forgeShadowConfirmValue          = "shadow-only"
	forgePeriodicEnableConfirmValue  = "periodic-shadow-enable"
	forgePeriodicDisableConfirmValue = "periodic-shadow-disable"

	forgeShadowCompleteNotice    = "forge-shadow-complete"
	forgeShadowIncompleteNotice  = "forge-shadow-incomplete"
	forgeShadowSupersededNotice  = "forge-shadow-superseded"
	forgeShadowStaleNotice       = "forge-shadow-stale"
	forgeShadowRunningNotice     = "forge-shadow-running"
	forgeShadowInterruptedNotice = "forge-shadow-interrupted"
	forgeShadowAuthorityNotice   = "forge-shadow-authority"
	forgeShadowUnavailableNotice = "forge-shadow-unavailable"
	forgeShadowInvalidNotice     = "forge-shadow-invalid"
	forgeShadowUnknownNotice     = "forge-shadow-unknown"

	forgePeriodicEnabledNotice        = "forge-periodic-enabled"
	forgePeriodicAlreadyEnabledNotice = "forge-periodic-already-enabled"
	forgePeriodicDisabledNotice       = "forge-periodic-disabled"
	forgePeriodicStaleNotice          = "forge-periodic-stale"
	forgePeriodicAuthorityNotice      = "forge-periodic-authority"
	forgePeriodicUnavailableNotice    = "forge-periodic-unavailable"
	forgePeriodicInvalidNotice        = "forge-periodic-invalid"
	forgePeriodicExhaustedNotice      = "forge-periodic-exhausted"
	forgePeriodicUnknownNotice        = "forge-periodic-unknown"
)

// ForgeAccessShadowService is the narrow web consumer boundary of the
// shadow-access snapshot slice.
type ForgeAccessShadowService interface {
	View(ctx context.Context) (forgeconnection.AccessShadowView, error)
	Run(ctx context.Context, actorUserID int64, input forgeconnection.RunAccessShadowInput) (forgeconnection.AccessSyncResultCode, error)
	EnablePeriodic(ctx context.Context, actorUserID int64, input forgeconnection.EnableAccessShadowPeriodicInput) (bool, error)
	DisablePeriodic(ctx context.Context, actorUserID int64, input forgeconnection.DisableAccessShadowPeriodicInput) error
}

// forgeShadowSectionView is the summary card state shared by the Forge
// access page and the details page header.
type forgeShadowSectionView struct {
	Available bool
	LoadError bool
	Ready     bool
	// EncryptionAvailable copies the shadow service's explicit readiness fact;
	// provider-changing handlers also retain their installation-config guard.
	EncryptionAvailable bool

	SetupEvidenceCurrent bool
	IdentityCount        int
	BindingCount         int
	WithinLimits         bool

	PeriodicEnableReady  bool
	PeriodicConfigLabel  string
	PeriodicConfigTone   string
	PeriodicConfigDetail string
	PeriodicBlockers     []string
	PeriodicDueLabel     string
	PeriodicDueTone      string
	PeriodicDueDetail    string
	PeriodicNextDueAt    string
	PeriodicRevision     string

	HasAttempt        bool
	AttemptLabel      string
	AttemptTone       string
	AttemptDetail     string
	AttemptTrigger    string
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
	// PriorConfirmedLabel, PriorConfirmedReasonText, and PriorConfirmedAt
	// render beneath a newer unknown when an earlier confirmation is
	// preserved.
	PriorConfirmedLabel      string
	PriorConfirmedReasonText string
	PriorConfirmedAt         string
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
	switch result {
	case forgeconnection.AccessSyncComplete:
		redirectForgeAccessNotice(w, r, forgeShadowCompleteNotice)
	case forgeconnection.AccessSyncScopeChanged:
		// Superseded is not a failure; the notice must match the attempt
		// axis and the audit trail.
		redirectForgeAccessNotice(w, r, forgeShadowSupersededNotice)
	default:
		redirectForgeAccessNotice(w, r, forgeShadowIncompleteNotice)
	}
}

func (s *Server) handleForgeAccessShadowPeriodicEnable(w http.ResponseWriter, r *http.Request) {
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
	input, err := parseForgeShadowPeriodicEnableForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeAccessShadowService == nil || !s.cfg.ForgeConnectionSecretEncryptionConfigured {
		redirectForgeAccessNotice(w, r, forgePeriodicUnavailableNotice)
		return
	}
	changed, err := s.cfg.ForgeAccessShadowService.EnablePeriodic(r.Context(), *session.UserID, input)
	if err != nil {
		redirectForgeAccessNotice(w, r, forgePeriodicNoticeForError(err))
		return
	}
	if !changed {
		redirectForgeAccessNotice(w, r, forgePeriodicAlreadyEnabledNotice)
		return
	}
	redirectForgeAccessNotice(w, r, forgePeriodicEnabledNotice)
}

func (s *Server) handleForgeAccessShadowPeriodicDisable(w http.ResponseWriter, r *http.Request) {
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
	input, err := parseForgeShadowPeriodicDisableForm(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeAccessShadowService == nil {
		redirectForgeAccessNotice(w, r, forgePeriodicUnavailableNotice)
		return
	}
	if err := s.cfg.ForgeAccessShadowService.DisablePeriodic(r.Context(), *session.UserID, input); err != nil {
		redirectForgeAccessNotice(w, r, forgePeriodicNoticeForError(err))
		return
	}
	redirectForgeAccessNotice(w, r, forgePeriodicDisabledNotice)
}

func forgePeriodicNoticeForError(err error) string {
	switch {
	case forgeconnection.IsValidationError(err):
		return forgePeriodicInvalidNotice
	case errors.Is(err, forgeconnection.ErrConflict), errors.Is(err, forgeconnection.ErrNoConnection):
		return forgePeriodicStaleNotice
	case errors.Is(err, forgeconnection.ErrAuthorization):
		return forgePeriodicAuthorityNotice
	case errors.Is(err, forgeconnection.ErrConfiguration):
		return forgePeriodicUnavailableNotice
	case errors.Is(err, forgeconnection.ErrAccessPeriodicRevisionExhausted):
		return forgePeriodicExhaustedNotice
	default:
		return forgePeriodicUnknownNotice
	}
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
	// Zero is canonical for bindings that predate the revision column.
	bindingRevision, err := canonicalExpectedRevision(values.Get("expected_binding_revision"))
	if err != nil {
		return forgeconnection.RunAccessShadowInput{}, errors.New("expected binding revision is invalid")
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

func parseForgeShadowPeriodicEnableForm(
	requestURL *url.URL,
	values url.Values,
) (forgeconnection.EnableAccessShadowPeriodicInput, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_config_revision",
		"expected_check_generation",
		"expected_binding_revision",
		"expected_access_identity_revision",
		"expected_newest_run_id",
		"expected_periodic_revision",
		"confirm_periodic_enable",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected connection id is invalid")
	}
	configRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_config_revision"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected configuration revision is invalid")
	}
	checkGeneration, err := canonicalPositiveForgeAccessValue(values.Get("expected_check_generation"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected check generation is invalid")
	}
	bindingRevision, err := canonicalExpectedRevision(values.Get("expected_binding_revision"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected binding revision is invalid")
	}
	identityRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_access_identity_revision"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected access identity revision is invalid")
	}
	newestRunID, err := canonicalExpectedRevision(values.Get("expected_newest_run_id"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected newest run id is invalid")
	}
	periodicRevision, err := canonicalExpectedRevision(values.Get("expected_periodic_revision"))
	if err != nil {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("expected periodic revision is invalid")
	}
	if values.Get("confirm_periodic_enable") != forgePeriodicEnableConfirmValue {
		return forgeconnection.EnableAccessShadowPeriodicInput{}, errors.New("periodic enable confirmation is invalid")
	}
	return forgeconnection.EnableAccessShadowPeriodicInput{
		ExpectedConnectionID:           connectionID,
		ExpectedConfigRevision:         configRevision,
		ExpectedCheckGeneration:        checkGeneration,
		ExpectedBindingRevision:        bindingRevision,
		ExpectedAccessIdentityRevision: identityRevision,
		ExpectedNewestRunID:            newestRunID,
		ExpectedPeriodicRevision:       periodicRevision,
		ConfirmPeriodicEnable:          true,
	}, nil
}

func parseForgeShadowPeriodicDisableForm(
	requestURL *url.URL,
	values url.Values,
) (forgeconnection.DisableAccessShadowPeriodicInput, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_periodic_revision",
		"confirm_periodic_disable",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeconnection.DisableAccessShadowPeriodicInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeconnection.DisableAccessShadowPeriodicInput{}, errors.New("expected connection id is invalid")
	}
	periodicRevision, err := canonicalExpectedRevision(values.Get("expected_periodic_revision"))
	if err != nil {
		return forgeconnection.DisableAccessShadowPeriodicInput{}, errors.New("expected periodic revision is invalid")
	}
	if values.Get("confirm_periodic_disable") != forgePeriodicDisableConfirmValue {
		return forgeconnection.DisableAccessShadowPeriodicInput{}, errors.New("periodic disable confirmation is invalid")
	}
	return forgeconnection.DisableAccessShadowPeriodicInput{
		ExpectedConnectionID:     connectionID,
		ExpectedPeriodicRevision: periodicRevision,
		ConfirmPeriodicDisable:   true,
	}, nil
}

// forgeShadowSection derives the independent configuration, due, latest
// attempt, and completed-evidence axes.
func forgeShadowSection(view forgeconnection.AccessShadowView) forgeShadowSectionView {
	section := forgeShadowSectionView{
		Available:              true,
		Ready:                  view.Ready(),
		EncryptionAvailable:    view.EncryptionAvailable,
		SetupEvidenceCurrent:   view.SetupEvidenceCurrent,
		IdentityCount:          view.IdentityCount,
		BindingCount:           view.BindingCount,
		WithinLimits:           view.WithinLimits,
		PeriodicEnableReady:    view.PeriodicEnableReady(),
		PeriodicRevision:       strconv.FormatInt(view.PeriodicRevision, 10),
		ConnectionID:           strconv.FormatInt(view.ConnectionID, 10),
		ConfigRevision:         strconv.FormatInt(view.ConfigRevision, 10),
		CheckGeneration:        strconv.FormatInt(view.CheckGeneration, 10),
		BindingRevision:        strconv.FormatInt(view.BindingRevision, 10),
		AccessIdentityRevision: strconv.FormatInt(view.AccessIdentityRevision, 10),
		NewestRunID:            strconv.FormatInt(view.NewestRunID, 10),
	}
	section.PeriodicConfigLabel, section.PeriodicConfigTone, section.PeriodicConfigDetail =
		forgeShadowPeriodicConfigPresentation(view)
	section.PeriodicBlockers = forgeShadowPeriodicBlockerText(view.PeriodicBlockers)
	section.PeriodicDueLabel, section.PeriodicDueTone, section.PeriodicDueDetail =
		forgeShadowPeriodicDuePresentation(view.PeriodicDueStatus)
	if view.PeriodicNextDueAt != nil {
		section.PeriodicNextDueAt = view.PeriodicNextDueAt.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	if view.LatestAttempt != nil {
		section.HasAttempt = true
		section.AttemptLabel, section.AttemptTone, section.AttemptDetail = forgeShadowAttemptPresentation(*view.LatestAttempt)
		section.AttemptTrigger = forgeShadowRunTriggerLabel(view.LatestAttempt.Trigger)
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
		section.SnapshotAge = forgeShadowAge(view.LatestSnapshot.Age)
	}
	return section
}

func forgeShadowPeriodicConfigPresentation(
	view forgeconnection.AccessShadowView,
) (string, string, string) {
	if view.PeriodicNextDueAt == nil {
		return "Disabled", "neutral", "Automatic snapshots are off. Manual snapshots remain available."
	}
	if len(view.PeriodicBlockers) > 0 {
		return "Enabled · blocked", "warning", "Local prerequisites currently block automatic snapshots. No provider call occurs; the five-minute schedule advances and refresh resumes automatically when the blockers clear."
	}
	return "Enabled", "info", "Thawguard attempts one automatic shadow snapshot per five-minute due window."
}

func forgeShadowPeriodicBlockerText(
	blockers []forgeconnection.AccessShadowPeriodicBlocker,
) []string {
	text := make([]string, 0, len(blockers))
	for _, blocker := range blockers {
		switch blocker {
		case forgeconnection.AccessPeriodicEncryptionUnavailable:
			text = append(text, "Service PAT encryption is unavailable.")
		case forgeconnection.AccessPeriodicSetupEvidenceNotCurrent:
			text = append(text, "Forge connection setup evidence is not current.")
		case forgeconnection.AccessPeriodicNoLinkedIdentities:
			text = append(text, "No Forgejo identities are linked.")
		case forgeconnection.AccessPeriodicNoBindings:
			text = append(text, "No repositories are bound.")
		case forgeconnection.AccessPeriodicScopeExceedsLimits:
			text = append(text, "The current identity × repository scope exceeds the 3A limits.")
		}
	}
	return text
}

func forgeShadowPeriodicDuePresentation(
	status forgeconnection.AccessShadowPeriodicDueStatus,
) (string, string, string) {
	switch status {
	case forgeconnection.AccessPeriodicScheduled:
		return "Scheduled", "scheduled", "The next persisted due time is in the future."
	case forgeconnection.AccessPeriodicDue:
		return "Due", "warning", "The persisted due time has arrived and is no more than 30 seconds past."
	case forgeconnection.AccessPeriodicOverdue:
		return "Overdue", "danger", "The persisted due time is more than 30 seconds past and no live periodic run explains it."
	case forgeconnection.AccessPeriodicRunning:
		return "Running", "scheduled", "A periodic snapshot is running. Disabling prevents later reservations but does not cancel this run."
	default:
		return "Not scheduled", "neutral", "Periodic refresh is disabled and no periodic run is live."
	}
}

func forgeShadowRunTriggerLabel(trigger forgeconnection.AccessShadowRunTrigger) string {
	switch trigger {
	case forgeconnection.AccessShadowRunManual:
		return "Manual"
	case forgeconnection.AccessShadowRunPeriodic:
		return "Periodic"
	default:
		return "Unknown"
	}
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
		return "Superseded", "warning", "The connection configuration, its evidence, or its identity/binding scope changed while the snapshot ran, so the attempt was superseded and published nothing."
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
		return "the connection configuration or its identity/binding scope changed while the snapshot ran."
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
		return "Scope changed", "warning", "The connection configuration or its identity/binding scope changed after this snapshot; its evidence predates the current scope."
	case snapshot.Fresh() && snapshot.UnknownCount == 0:
		return "Current · complete", "success", "Every current pair carries confirmed evidence from a completed snapshot less than ten minutes old."
	case snapshot.Fresh():
		return "Current · incomplete", "warning", "The completed snapshot is less than ten minutes old, but some pairs stayed unknown; earlier confirmations, where present, are preserved beneath them."
	case snapshot.UnknownCount == 0:
		return "Stale · complete", "warning", "Every pair was confirmed, but the completed snapshot is at least ten minutes old."
	default:
		return "Stale · incomplete", "warning", "The completed snapshot is at least ten minutes old and some pairs stayed unknown; earlier confirmations, where present, are preserved beneath them."
	}
}

// forgeShadowAge renders the nonnegative age sampled by the shadow service
// in fixed coarse units. It does not sample the web process clock.
func forgeShadowAge(age time.Duration) string {
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Minute:
		return "moments ago"
	case age < time.Hour:
		return strconv.Itoa(int(age.Minutes())) + " min ago"
	case age < 48*time.Hour:
		return strconv.Itoa(int(age.Hours())) + " h ago"
	default:
		return strconv.Itoa(int(age.Hours()/24)) + " days ago"
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
			row.PriorConfirmedReasonText = forgeShadowReasonText(pair.PriorConfirmedReason)
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
