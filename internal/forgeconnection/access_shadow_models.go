package forgeconnection

import (
	"context"
	"errors"
	"time"
)

// Shadow-access snapshots record, for every current linked-identity x
// bound-repository pair, whether an explicit Forgejo relationship was
// observed through the Administrator-attested service credential. The
// evidence is inert: nothing here reads or mutates repository_grants,
// grants authority, changes enforcement, or predicts role changes. A
// completed snapshot is complete only for the graph visible to that exact
// credential within the approved limits.

// AccessSyncResultCode is the strict sanitized result of one snapshot
// attempt. Only complete publishes pair observations.
type AccessSyncResultCode string

const (
	AccessSyncComplete              AccessSyncResultCode = "complete"
	AccessSyncUnavailable           AccessSyncResultCode = "unavailable"
	AccessSyncAuthenticationFailed  AccessSyncResultCode = "authentication_failed"
	AccessSyncAuthorizationFailed   AccessSyncResultCode = "authorization_failed"
	AccessSyncServiceUserIsAdmin    AccessSyncResultCode = "service_user_is_admin"
	AccessSyncServiceUserChanged    AccessSyncResultCode = "service_user_changed"
	AccessSyncOrganizationChanged   AccessSyncResultCode = "organization_changed"
	AccessSyncCredentialUnavailable AccessSyncResultCode = "credential_unavailable"
	AccessSyncInvalidResponse       AccessSyncResultCode = "invalid_response"
	AccessSyncPaginationIncomplete  AccessSyncResultCode = "pagination_incomplete"
	AccessSyncWorkLimitExceeded     AccessSyncResultCode = "work_limit_exceeded"
	AccessSyncScopeChanged          AccessSyncResultCode = "scope_changed"
	AccessSyncInterrupted           AccessSyncResultCode = "interrupted"
)

func (code AccessSyncResultCode) Valid() bool {
	switch code {
	case AccessSyncComplete,
		AccessSyncUnavailable,
		AccessSyncAuthenticationFailed,
		AccessSyncAuthorizationFailed,
		AccessSyncServiceUserIsAdmin,
		AccessSyncServiceUserChanged,
		AccessSyncOrganizationChanged,
		AccessSyncCredentialUnavailable,
		AccessSyncInvalidResponse,
		AccessSyncPaginationIncomplete,
		AccessSyncWorkLimitExceeded,
		AccessSyncScopeChanged,
		AccessSyncInterrupted:
		return true
	default:
		return false
	}
}

// AccessShadowRunTrigger records who reserved a snapshot independently of
// whether a manual requester's account still exists later.
type AccessShadowRunTrigger string

const (
	AccessShadowRunManual   AccessShadowRunTrigger = "manual"
	AccessShadowRunPeriodic AccessShadowRunTrigger = "periodic"
	// AccessShadowRunnerActorRole is the fixed system role persisted for
	// periodic shadow-refresh Activity.
	AccessShadowRunnerActorRole = "shadow_refresh_runner"
)

func (trigger AccessShadowRunTrigger) Valid() bool {
	return trigger == AccessShadowRunManual || trigger == AccessShadowRunPeriodic
}

// observerReturnable reports whether an observer may hand this code back.
// credential_unavailable, scope_changed, and interrupted belong to the
// service lifecycle, never to provider observation.
func (code AccessSyncResultCode) observerReturnable() bool {
	switch code {
	case AccessSyncComplete,
		AccessSyncUnavailable,
		AccessSyncAuthenticationFailed,
		AccessSyncAuthorizationFailed,
		AccessSyncServiceUserIsAdmin,
		AccessSyncServiceUserChanged,
		AccessSyncOrganizationChanged,
		AccessSyncInvalidResponse,
		AccessSyncPaginationIncomplete,
		AccessSyncWorkLimitExceeded:
		return true
	default:
		return false
	}
}

// AccessObservationReason is the fixed per-pair evidence classification.
type AccessObservationReason string

const (
	// AccessReasonDirectCollaborator: an explicit direct-collaborator edge
	// exists and effective permission is read, write, admin, or owner.
	AccessReasonDirectCollaborator AccessObservationReason = "direct_collaborator"
	// AccessReasonTeamAccess: an explicit team-to-repository edge exists for
	// the immutable user and effective permission is positive.
	AccessReasonTeamAccess AccessObservationReason = "team_access"
	// AccessReasonNoExplicitAccessNone: no explicit edge exists in the
	// complete credential-visible snapshot, the identity resolved by
	// immutable id, and effective permission is exactly none.
	AccessReasonNoExplicitAccessNone  AccessObservationReason = "no_explicit_access_none"
	AccessReasonIdentityUnresolved    AccessObservationReason = "identity_unresolved"
	AccessReasonRepositoryUnavailable AccessObservationReason = "repository_unavailable"
	// AccessReasonVisibilitySourceUnproven: effective permission was
	// positive without any explicit edge; implicit visibility is never
	// inferred, so the source stays unproven.
	AccessReasonVisibilitySourceUnproven AccessObservationReason = "visibility_source_unproven"
	AccessReasonPermissionUnavailable    AccessObservationReason = "permission_unavailable"
	AccessReasonPermissionUnrecognized   AccessObservationReason = "permission_unrecognized"
	AccessReasonEvidenceInconsistent     AccessObservationReason = "evidence_inconsistent"
)

func (reason AccessObservationReason) Valid() bool {
	switch reason {
	case AccessReasonDirectCollaborator,
		AccessReasonTeamAccess,
		AccessReasonNoExplicitAccessNone,
		AccessReasonIdentityUnresolved,
		AccessReasonRepositoryUnavailable,
		AccessReasonVisibilitySourceUnproven,
		AccessReasonPermissionUnavailable,
		AccessReasonPermissionUnrecognized,
		AccessReasonEvidenceInconsistent:
		return true
	default:
		return false
	}
}

// AccessObservationState is the derived pair state; every reason maps to
// exactly one state.
type AccessObservationState string

const (
	AccessStateConfirmedPresent AccessObservationState = "confirmed_present"
	AccessStateConfirmedAbsent  AccessObservationState = "confirmed_absent"
	AccessStateUnknown          AccessObservationState = "unknown"
)

// State derives the pair state from the fixed reason.
func (reason AccessObservationReason) State() AccessObservationState {
	switch reason {
	case AccessReasonDirectCollaborator, AccessReasonTeamAccess:
		return AccessStateConfirmedPresent
	case AccessReasonNoExplicitAccessNone:
		return AccessStateConfirmedAbsent
	default:
		return AccessStateUnknown
	}
}

// Confirmed reports whether the reason is confirmation evidence (present or
// absent) rather than unknown.
func (reason AccessObservationReason) Confirmed() bool {
	return reason.State() != AccessStateUnknown
}

// Small-alpha limits. The snapshot fails closed beyond them.
const (
	// AccessShadowIdentityLimit caps linked identities in one snapshot scope.
	AccessShadowIdentityLimit = 10
	// AccessShadowRepositoryLimit caps bound repositories in one snapshot scope.
	AccessShadowRepositoryLimit = 10
	// AccessShadowPairLimit caps the identity x repository product.
	AccessShadowPairLimit = 25
	// AccessSyncConstructiveRequestMaximum is the largest request count for
	// the bounded valid scope when every accepted listing reaches its limit.
	AccessSyncConstructiveRequestMaximum = 89
	// AccessSyncRequestLimit caps the requests of one provider operation.
	AccessSyncRequestLimit = 96
	// AccessShadowPeriodicIntervalSeconds is the fixed periodic cadence
	// recorded in configuration Activity.
	AccessShadowPeriodicIntervalSeconds = 5 * 60
	// accessShadowInterruptionAge is how old a still-running row must be
	// before it is treated as interrupted and may be terminalized.
	accessShadowInterruptionAge = 75 * time.Second
	// accessShadowOverallDeadline bounds the whole provider operation.
	accessShadowOverallDeadline = 60 * time.Second
	// accessShadowFinalizationDeadline lets a reserved run durably record the
	// observer result after its request or runner context is cancelled. It
	// stays below the outer ten-second app shutdown deadline so a timed-out
	// finalizer can return before HTTP and runner joining reaches that edge.
	accessShadowFinalizationDeadline = 9 * time.Second
	// accessShadowPeriodicCadence is fixed for this slice. Persisted due time,
	// rather than process uptime, decides when work may be reserved.
	accessShadowPeriodicCadence = time.Duration(AccessShadowPeriodicIntervalSeconds) * time.Second
	// accessShadowEvidenceFreshness is the exact completed-snapshot freshness
	// boundary: age equal to the duration is stale.
	accessShadowEvidenceFreshness = 10 * time.Minute
	// accessShadowPeriodicOverdueAge distinguishes an arrived due time from an
	// unexplained overdue schedule in the UI.
	accessShadowPeriodicOverdueAge = 30 * time.Second
)

// AccessShadowObserver performs the read-only provider snapshot for one
// reserved run, entirely outside SQLite. Implementations must never call a
// write endpoint and must never retain raw response data in the report.
type AccessShadowObserver interface {
	ObserveAccess(ctx context.Context, input AccessObserveInput) AccessObservation
}

// AccessShadowIdentity is one linked identity handed to the observer. The
// remote id and username-at-link travel only into bounded request memory
// and never into persisted results.
type AccessShadowIdentity struct {
	IdentityID     int64
	RemoteUserID   string
	UsernameAtLink string
}

// AccessShadowBinding is one bound repository handed to the observer.
type AccessShadowBinding struct {
	RepositoryID       int64
	RemoteRepositoryID string
}

// AccessObserveInput is the reserved-run snapshot an observer needs. PAT
// holds decrypted secret bytes; the observer must not retain them.
type AccessObserveInput struct {
	BaseURL                   string
	OrganizationSlug          string
	PAT                       []byte
	BoundServiceUserRemoteID  string
	BoundOrganizationRemoteID string
	Identities                []AccessShadowIdentity
	Bindings                  []AccessShadowBinding
}

// AccessObservation is the sanitized result of one provider snapshot. Pairs
// are meaningful only when ResultCode is complete, and then must classify
// every identity x binding pair exactly once. RequestCount is the
// request-local count of attempted provider RoundTrips: a budget rejection
// never counts, while an attempt that fails before reaching the provider
// (canceled context, DNS, TLS) still counts as one attempt.
type AccessObservation struct {
	ResultCode   AccessSyncResultCode
	Pairs        []AccessPairObservation
	RequestCount int64
}

// AccessPairObservation is one classified pair, named only by internal row
// ids and a fixed reason.
type AccessPairObservation struct {
	IdentityID   int64
	RepositoryID int64
	Reason       AccessObservationReason
}

// RunAccessShadowInput fences one manual snapshot to the exact state the
// summary page rendered.
type RunAccessShadowInput struct {
	ExpectedConnectionID           int64
	ExpectedConfigRevision         int64
	ExpectedCheckGeneration        int64
	ExpectedBindingRevision        int64
	ExpectedAccessIdentityRevision int64
	// ExpectedNewestRunID is the newest run id the page rendered, or 0 when
	// no run existed. The never-reused id makes this a CAS token.
	ExpectedNewestRunID int64
	// ConfirmShadowOnly must be explicitly true: the Administrator confirms
	// the snapshot records shadow evidence only and changes no authority.
	ConfirmShadowOnly bool
}

// EnableAccessShadowPeriodicInput fences one explicit enable to the exact
// connection, scope, newest-run, and periodic configuration state rendered.
type EnableAccessShadowPeriodicInput struct {
	ExpectedConnectionID           int64
	ExpectedConfigRevision         int64
	ExpectedCheckGeneration        int64
	ExpectedBindingRevision        int64
	ExpectedAccessIdentityRevision int64
	ExpectedNewestRunID            int64
	ExpectedPeriodicRevision       int64
	ConfirmPeriodicEnable          bool
}

// DisableAccessShadowPeriodicInput fences one explicit disable. Disable does
// not depend on setup evidence, encryption, identities, or bindings.
type DisableAccessShadowPeriodicInput struct {
	ExpectedConnectionID     int64
	ExpectedPeriodicRevision int64
	ConfirmPeriodicDisable   bool
}

// AccessShadowPeriodicBlocker is one local reason an enabled periodic scan
// will advance cadence without reserving a run or calling the provider.
type AccessShadowPeriodicBlocker string

const (
	AccessPeriodicEncryptionUnavailable   AccessShadowPeriodicBlocker = "encryption_unavailable"
	AccessPeriodicSetupEvidenceNotCurrent AccessShadowPeriodicBlocker = "setup_evidence_not_current"
	AccessPeriodicNoLinkedIdentities      AccessShadowPeriodicBlocker = "no_linked_identities"
	AccessPeriodicNoBindings              AccessShadowPeriodicBlocker = "no_bindings"
	AccessPeriodicScopeExceedsLimits      AccessShadowPeriodicBlocker = "scope_exceeds_limits"
)

// AccessShadowPeriodicDueStatus is the independent runner-schedule axis.
type AccessShadowPeriodicDueStatus string

const (
	AccessPeriodicNotScheduled AccessShadowPeriodicDueStatus = "not_scheduled"
	AccessPeriodicScheduled    AccessShadowPeriodicDueStatus = "scheduled"
	AccessPeriodicDue          AccessShadowPeriodicDueStatus = "due"
	AccessPeriodicOverdue      AccessShadowPeriodicDueStatus = "overdue"
	AccessPeriodicRunning      AccessShadowPeriodicDueStatus = "running"
)

// AccessAttemptStatus is the derived latest-attempt axis.
type AccessAttemptStatus string

const (
	AccessAttemptRunning        AccessAttemptStatus = "running"
	AccessAttemptInterrupted    AccessAttemptStatus = "interrupted"
	AccessAttemptCompleted      AccessAttemptStatus = "completed"
	AccessAttemptFailed         AccessAttemptStatus = "failed"
	AccessAttemptSuperseded     AccessAttemptStatus = "superseded"
	AccessAttemptOutcomeUnknown AccessAttemptStatus = "outcome_unknown"
)

// AccessShadowAttempt is the newest run in either axis-relevant form.
type AccessShadowAttempt struct {
	Status     AccessAttemptStatus
	Trigger    AccessShadowRunTrigger
	ResultCode AccessSyncResultCode // empty while running or interrupted-by-age
	StartedAt  time.Time
	FinishedAt *time.Time
}

// AccessShadowSnapshot is the newest completed snapshot anchor.
type AccessShadowSnapshot struct {
	RunID        int64
	PresentCount int64
	AbsentCount  int64
	UnknownCount int64
	PairCount    int64
	// ScopeCurrent reports whether the captured config, binding, and
	// access-identity revisions still match the connection.
	ScopeCurrent bool
	// Age is derived from the same service clock sample used by the rest of
	// the view.
	Age        time.Duration
	ObservedAt time.Time
}

// Fresh reports whether the completed snapshot is strictly less than ten
// minutes old.
func (s AccessShadowSnapshot) Fresh() bool {
	return s.Age < accessShadowEvidenceFreshness
}

// AccessShadowPairRow is one current pair for the details page. It carries
// local labels only; remote ids never enter web models.
type AccessShadowPairRow struct {
	IdentityID         int64
	UserID             int64
	RepositoryID       int64
	UserDisplayName    string
	UserEmail          string
	UserDisabled       bool
	UsernameAtLink     string
	RepositoryFullName string
	// Observed is false when no observation row exists for the current
	// pair; the UI derives never_observed.
	Observed         bool
	LatestReason     AccessObservationReason
	LatestRunID      int64
	LatestObservedAt time.Time
	// PriorConfirmedReason and PriorConfirmedAt are set only when the
	// latest reason is unknown and an earlier confirmation is preserved.
	PriorConfirmedReason AccessObservationReason
	PriorConfirmedAt     time.Time
}

// AccessShadowLinkedUser is one current local user linked to the Forge
// connection. Historical usernames are retained for display, while remote
// user identifiers stay outside the web-facing view.
type AccessShadowLinkedUser struct {
	UserID          int64
	UserDisplayName string
	UserEmail       string
	UserDisabled    bool
	UsernameAtLink  string
}

// AccessShadowBoundRepository is one current local repository binding exposed
// for read-only selection. Remote repository identifiers never enter the view.
type AccessShadowBoundRepository struct {
	RepositoryID       int64
	RepositoryFullName string
}

// AccessShadowView is everything the summary and details pages need.
type AccessShadowView struct {
	HasConnection          bool
	ConnectionID           int64
	ConfigRevision         int64
	CheckGeneration        int64
	BindingRevision        int64
	AccessIdentityRevision int64
	// SetupEvidenceCurrent reports bound identities plus a current
	// successful setup check at the exact revision and generation.
	SetupEvidenceCurrent bool
	EncryptionAvailable  bool
	IdentityCount        int
	BindingCount         int
	WithinLimits         bool
	NewestRunID          int64
	LatestAttempt        *AccessShadowAttempt
	LatestSnapshot       *AccessShadowSnapshot
	// PeriodicRevision is zero when no configuration row exists.
	PeriodicRevision  int64
	PeriodicNextDueAt *time.Time
	PeriodicDueStatus AccessShadowPeriodicDueStatus
	PeriodicBlockers  []AccessShadowPeriodicBlocker
	// BoundRepositories is populated independently of pair-detail limits so a
	// read-only repository selector remains truthful for every current binding.
	BoundRepositories []AccessShadowBoundRepository
	// LinkedUsers is populated independently of bindings and pair-detail limits
	// in local user ID order.
	LinkedUsers []AccessShadowLinkedUser
	// Pairs is populated only within limits, sorted by local user label,
	// repository label, then internal ids.
	Pairs []AccessShadowPairRow
}

// PeriodicEnableReady reports whether the currently disabled configuration
// meets the local prerequisites for an explicit enable.
func (v AccessShadowView) PeriodicEnableReady() bool {
	return v.HasConnection && v.PeriodicNextDueAt == nil && len(v.PeriodicBlockers) == 0
}

// Ready reports whether a new snapshot may be reserved from this view.
func (v AccessShadowView) Ready() bool {
	return v.HasConnection && v.EncryptionAvailable && v.SetupEvidenceCurrent && v.WithinLimits &&
		v.IdentityCount >= 1 && v.BindingCount >= 1 &&
		(v.LatestAttempt == nil || v.LatestAttempt.Status != AccessAttemptRunning)
}

var (
	ErrAccessSyncRunning               = errors.New("a shadow snapshot is already running; wait for it to finish or become interrupted")
	ErrAccessSyncInterrupted           = errors.New("the shadow snapshot was interrupted before a result could be recorded")
	ErrAccessSyncOutcomeUnknown        = errors.New("the shadow snapshot outcome could not be confirmed")
	ErrAccessPeriodicOutcomeUnknown    = errors.New("the periodic shadow refresh outcome could not be confirmed")
	ErrAccessPeriodicRevisionExhausted = errors.New("the periodic shadow refresh revision is exhausted")
	ErrAccessPeriodicReservationFailed = errors.New("the periodic shadow refresh reservation failed")
	ErrAccessPeriodicExecutionFailed   = errors.New("the periodic shadow refresh execution failed")
)
