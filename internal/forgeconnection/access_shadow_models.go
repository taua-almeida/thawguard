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
	maxAccessShadowIdentities   = 10
	maxAccessShadowRepositories = 10
	maxAccessShadowPairs        = 25
	// AccessSyncRequestLimit caps the requests of one provider operation.
	AccessSyncRequestLimit = 96
	// accessShadowInterruptionAge is how old a still-running row must be
	// before it is treated as interrupted and may be terminalized.
	accessShadowInterruptionAge = 75 * time.Second
	// accessShadowOverallDeadline bounds the whole provider operation.
	accessShadowOverallDeadline = 60 * time.Second
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
// request-local count of provider requests actually issued.
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
	ResultCode AccessSyncResultCode // empty while running or interrupted-by-age
	StartedAt  time.Time
	FinishedAt *time.Time
}

// AccessShadowSnapshot is the newest completed snapshot anchor.
type AccessShadowSnapshot struct {
	PresentCount int64
	AbsentCount  int64
	UnknownCount int64
	PairCount    int64
	// ScopeCurrent reports whether the captured config, binding, and
	// access-identity revisions still match the connection.
	ScopeCurrent bool
	ObservedAt   time.Time
}

// AccessShadowPairRow is one current pair for the details page. It carries
// local labels only; remote ids never enter web models.
type AccessShadowPairRow struct {
	IdentityID         int64
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
	LatestObservedAt time.Time
	// PriorConfirmedReason and PriorConfirmedAt are set only when the
	// latest reason is unknown and an earlier confirmation is preserved.
	PriorConfirmedReason AccessObservationReason
	PriorConfirmedAt     time.Time
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
	IdentityCount        int
	BindingCount         int
	WithinLimits         bool
	NewestRunID          int64
	LatestAttempt        *AccessShadowAttempt
	LatestSnapshot       *AccessShadowSnapshot
	// Pairs is populated only within limits, sorted by local user label,
	// repository label, then internal ids.
	Pairs []AccessShadowPairRow
}

// Ready reports whether a new snapshot may be reserved from this view.
func (v AccessShadowView) Ready() bool {
	return v.HasConnection && v.SetupEvidenceCurrent && v.WithinLimits &&
		v.IdentityCount >= 1 && v.BindingCount >= 1 &&
		(v.LatestAttempt == nil || v.LatestAttempt.Status != AccessAttemptRunning)
}

var (
	ErrAccessSyncRunning        = errors.New("a shadow snapshot is already running; wait for it to finish or become interrupted")
	ErrAccessSyncInterrupted    = errors.New("the shadow snapshot was interrupted before a result could be recorded")
	ErrAccessSyncOutcomeUnknown = errors.New("the shadow snapshot outcome could not be confirmed")
)
