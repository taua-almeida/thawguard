package forgeconnection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

// AccessShadowService owns the bounded, connection-wide shadow access
// snapshot and its explicitly enabled periodic cadence. It is deliberately
// separate from the connection Service: snapshots reuse the connection's
// stored credential and evidence fences but never change connection, binding,
// identity, or repository-owned state, and no code path here reads or mutates
// repository_grants.
type AccessShadowService struct {
	lifecycleCtx context.Context
	db           *sql.DB
	secrets      secrets.Store
	observer     AccessShadowObserver
	now          func() time.Time
}

func NewAccessShadowService(
	lifecycleCtx context.Context,
	db *sql.DB,
	secretStore secrets.Store,
	observer AccessShadowObserver,
) *AccessShadowService {
	if lifecycleCtx == nil {
		lifecycleCtx = context.Background()
	}
	return &AccessShadowService{
		lifecycleCtx: lifecycleCtx,
		db:           db,
		secrets:      secretStore,
		observer:     observer,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// accessShadowRunSnapshot carries one reserved run between the reservation
// transaction, the provider observation, and the finalization transaction.
type accessShadowRunSnapshot struct {
	runID                  int64
	runTrigger             AccessShadowRunTrigger
	connectionID           int64
	configRevision         int64
	checkGeneration        int64
	bindingRevision        int64
	accessIdentityRevision int64
	baseURL                string
	organizationSlug       string
	patCiphertext          []byte
	serviceUserRemoteID    string
	organizationRemoteID   string
	identities             []AccessShadowIdentity
	bindings               []AccessShadowBinding
	startedAt              time.Time
}

// Run executes one manual shadow snapshot end to end: reserve the run in a
// writer-first transaction, observe the provider outside SQLite under the
// overall deadline, and finalize atomically. It returns the terminal result
// code recorded for the run.
func (s *AccessShadowService) Run(ctx context.Context, actorUserID int64, input RunAccessShadowInput) (AccessSyncResultCode, error) {
	if s == nil || s.db == nil {
		return "", errors.New("forge access shadow service has no database")
	}
	if s.secrets == nil {
		return "", ErrConfiguration
	}
	if s.observer == nil {
		return "", errors.New("forge access shadow observer is not configured")
	}
	if actorUserID <= 0 {
		return "", ErrAuthorization
	}
	// A zero binding revision is canonical for a connection whose bindings
	// predate the revision column; it is accepted, never backfilled.
	if input.ExpectedConnectionID <= 0 || input.ExpectedConfigRevision <= 0 ||
		input.ExpectedCheckGeneration <= 0 || input.ExpectedBindingRevision < 0 ||
		input.ExpectedAccessIdentityRevision <= 0 || input.ExpectedNewestRunID < 0 {
		return "", ValidationError{Message: "the expected connection, revision, and run ids must identify the rendered snapshot state"}
	}
	if !input.ConfirmShadowOnly {
		return "", ValidationError{Message: "confirm the shadow-only snapshot before running it"}
	}

	// Manual provider work stops with either its request or the application
	// lifecycle. The lifecycle context is scoped here instead of serving as
	// http.Server.BaseContext, so graceful shutdown does not cancel unrelated
	// handlers before http.Server.Shutdown can drain them.
	runCtx, cancelRun := context.WithCancel(ctx)
	stopLifecycleCancellation := context.AfterFunc(s.lifecycleCtx, cancelRun)
	if s.lifecycleCtx.Err() != nil {
		cancelRun()
	}
	defer func() {
		stopLifecycleCancellation()
		cancelRun()
	}()

	snapshot, err := s.reserveRun(runCtx, actorUserID, input)
	if err != nil {
		return "", err
	}
	return s.executeRun(runCtx, snapshot)
}

// executeRun is the shared post-reservation path for manual and periodic
// snapshots. Both triggers decrypt, observe, validate, finalize, retain, and
// audit through exactly the same implementation.
func (s *AccessShadowService) executeRun(
	ctx context.Context,
	snapshot accessShadowRunSnapshot,
) (AccessSyncResultCode, error) {
	observation, requestCountKnown := s.observeAccess(ctx, snapshot)
	if ctx.Err() != nil && observation.ResultCode != AccessSyncComplete {
		// Cancellation belongs to the service lifecycle, not the provider
		// error matrix. The detached finalizer below records that durable truth
		// without guessing how many requests completed before cancellation. A
		// validated complete observation wins a cancellation race after observer
		// return because all bounded provider evidence has already been collected.
		observation = AccessObservation{ResultCode: AccessSyncInterrupted}
		requestCountKnown = false
	}
	// Reservation committed before provider work, so cancellation must stop
	// provider I/O without preventing the attempt from recording its bounded,
	// sanitized result. WithoutCancel preserves request values while this
	// independent deadline keeps finalization from outliving shutdown forever.
	finalizeCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		accessShadowFinalizationDeadline,
	)
	defer cancel()
	return s.finalizeRun(finalizeCtx, snapshot, observation, requestCountKnown)
}

func (s *AccessShadowService) reserveRun(ctx context.Context, actorUserID int64, input RunAccessShadowInput) (accessShadowRunSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return accessShadowRunSnapshot{}, fmt.Errorf("begin forge access shadow reservation: %w", err)
	}
	defer tx.Rollback()
	// The actor lock's UPDATE takes writer ownership before any read below,
	// and re-proves enabled Administrator authority inside the transaction.
	// Authorization happens only here: finalization is actor-independent
	// because this slice can never publish authority.
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return accessShadowRunSnapshot{}, err
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return accessShadowRunSnapshot{}, err
	}
	if !found {
		return accessShadowRunSnapshot{}, ErrNoConnection
	}
	if record.ID != input.ExpectedConnectionID ||
		record.Revision != input.ExpectedConfigRevision ||
		record.CheckGeneration != input.ExpectedCheckGeneration ||
		record.BindingRevision != input.ExpectedBindingRevision ||
		record.AccessIdentityRevision != input.ExpectedAccessIdentityRevision {
		return accessShadowRunSnapshot{}, ErrConflict
	}
	if !currentAccessSetupEvidence(record) {
		return accessShadowRunSnapshot{}, ErrConflict
	}
	identities, err := loadAccessShadowIdentities(ctx, tx, record.ID)
	if err != nil {
		return accessShadowRunSnapshot{}, err
	}
	bindings, err := loadAccessShadowBindings(ctx, tx, record.ID)
	if err != nil {
		return accessShadowRunSnapshot{}, err
	}
	if len(identities) == 0 || len(bindings) == 0 {
		return accessShadowRunSnapshot{}, ValidationError{
			Message: "link at least one Forgejo identity and bind at least one repository before running a shadow snapshot",
		}
	}
	if !accessShadowScopeWithinLimits(len(identities), len(bindings)) {
		return accessShadowRunSnapshot{}, ValidationError{
			Message: "the snapshot scope exceeds the small-alpha limits; reduce linked identities or bound repositories",
		}
	}

	now := s.now().UTC()
	if err := s.validateNewestRunAndRecoverOrphan(ctx, tx, record.ID, input.ExpectedNewestRunID, now); err != nil {
		return accessShadowRunSnapshot{}, err
	}

	result, err := tx.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, started_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		actorUserID,
		record.Revision,
		record.CheckGeneration,
		record.BindingRevision,
		record.AccessIdentityRevision,
		len(identities),
		len(bindings),
		string(AccessShadowRunManual),
		formatForgeConnectionTime(now),
	)
	if err != nil {
		return accessShadowRunSnapshot{}, fmt.Errorf("insert forge access shadow run: %w", err)
	}
	runID, err := result.LastInsertId()
	if err != nil || runID <= 0 {
		return accessShadowRunSnapshot{}, errors.New("determine forge access shadow run id")
	}
	actor := actorUserID
	if err := recordAccessSyncStarted(
		ctx,
		tx,
		&actor,
		AccessShadowRunManual,
		record.ID,
		runID,
		len(identities),
		len(bindings),
	); err != nil {
		return accessShadowRunSnapshot{}, err
	}
	// Commit before any PAT decryption or provider I/O.
	if err := tx.Commit(); err != nil {
		return accessShadowRunSnapshot{}, ErrAccessSyncOutcomeUnknown
	}
	return accessShadowRunSnapshot{
		runID:                  runID,
		runTrigger:             AccessShadowRunManual,
		connectionID:           record.ID,
		configRevision:         record.Revision,
		checkGeneration:        record.CheckGeneration,
		bindingRevision:        record.BindingRevision,
		accessIdentityRevision: record.AccessIdentityRevision,
		baseURL:                record.BaseURL,
		organizationSlug:       currentOrganizationSlug(record),
		patCiphertext:          record.ServicePATCiphertext,
		serviceUserRemoteID:    record.ServiceUserRemoteID,
		organizationRemoteID:   currentOrganizationRemoteID(record),
		identities:             identities,
		bindings:               bindings,
		startedAt:              now,
	}, nil
}

type newestAccessShadowReservation struct {
	id         int64
	requester  sql.NullInt64
	runTrigger AccessShadowRunTrigger
	resultCode sql.NullString
	startedAt  time.Time
}

func loadNewestAccessShadowReservation(
	ctx context.Context,
	q queryer,
	connectionID int64,
) (newestAccessShadowReservation, bool, error) {
	var record newestAccessShadowReservation
	var triggerText, startedAtText string
	err := q.QueryRowContext(ctx, `
SELECT id, requested_by_user_id, run_trigger, result_code, started_at
FROM forge_access_shadow_runs
WHERE connection_id = ?
ORDER BY id DESC
LIMIT 1`, connectionID).Scan(
		&record.id,
		&record.requester,
		&triggerText,
		&record.resultCode,
		&startedAtText,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return newestAccessShadowReservation{}, false, nil
	}
	if err != nil {
		return newestAccessShadowReservation{}, false, fmt.Errorf("read newest forge access shadow reservation: %w", err)
	}
	record.runTrigger = AccessShadowRunTrigger(triggerText)
	record.startedAt, err = parseForgeConnectionTime(startedAtText)
	if record.id <= 0 || !record.runTrigger.Valid() || err != nil {
		return newestAccessShadowReservation{}, false, errors.New("forge access shadow run data is malformed")
	}
	if record.runTrigger == AccessShadowRunPeriodic && record.requester.Valid {
		return newestAccessShadowReservation{}, false, errors.New("forge access shadow run data is malformed")
	}
	if record.resultCode.Valid && !AccessSyncResultCode(record.resultCode.String).Valid() {
		return newestAccessShadowReservation{}, false, errors.New("forge access shadow run data is malformed")
	}
	return record, true, nil
}

// validateNewestRunAndRecoverOrphan enforces the newest-run CAS and
// terminalizes an orphaned running row older than the interruption age. A
// younger running row rejects the reservation instead. The interruption's
// finished event is attributed to the run's persisted requester (NULL when
// that account was deleted), never to the Administrator whose reservation
// happened to recover the orphan.
func (s *AccessShadowService) validateNewestRunAndRecoverOrphan(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	expectedNewestRunID int64,
	now time.Time,
) error {
	newest, found, err := loadNewestAccessShadowReservation(ctx, tx, connectionID)
	if err != nil {
		return err
	}
	if !found {
		if expectedNewestRunID != 0 {
			return ErrConflict
		}
		return nil
	}
	if newest.id != expectedNewestRunID {
		return ErrConflict
	}
	if newest.resultCode.Valid {
		return nil
	}
	if now.Sub(newest.startedAt) < accessShadowInterruptionAge {
		return ErrAccessSyncRunning
	}
	finishedAt := now
	if finishedAt.Before(newest.startedAt) {
		finishedAt = newest.startedAt
	}
	return terminalizeAccessShadowOrphan(
		ctx,
		tx,
		connectionID,
		newest.id,
		newest.requester,
		newest.runTrigger,
		finishedAt,
	)
}

func terminalizeAccessShadowOrphan(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	runID int64,
	requester sql.NullInt64,
	runTrigger AccessShadowRunTrigger,
	finishedAt time.Time,
) error {
	terminalized, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_access_shadow_runs
SET result_code = ?, finished_at = ?
WHERE id = ? AND result_code IS NULL`,
		string(AccessSyncInterrupted),
		formatForgeConnectionTime(finishedAt),
		runID,
	)
	if err != nil {
		return fmt.Errorf("terminalize orphaned forge access shadow run: %w", err)
	}
	if !terminalized {
		return errors.New("terminalize orphaned forge access shadow run: run is no longer active")
	}
	if err := applyAccessShadowRetention(ctx, tx, connectionID); err != nil {
		return err
	}
	// Orphan interruption omits the request count: it was never known.
	return recordAccessSyncFinished(
		ctx,
		tx,
		nullableActor(requester),
		runTrigger,
		connectionID,
		runID,
		AccessSyncInterrupted,
		nil,
		nil,
		nil,
	)
}

// nullableActor converts a scanned nullable requester into an audit actor.
func nullableActor(requester sql.NullInt64) *int64 {
	if !requester.Valid {
		return nil
	}
	actor := requester.Int64
	return &actor
}

// observeAccess decrypts the PAT outside SQLite and runs the provider
// observation under the overall deadline on the original request context.
// The returned bool reports whether the observation's request count is
// trustworthy for audit evidence.
func (s *AccessShadowService) observeAccess(ctx context.Context, snapshot accessShadowRunSnapshot) (AccessObservation, bool) {
	envelope, err := s.secrets.Decrypt(ctx, snapshot.patCiphertext)
	if err != nil {
		// Cause-neutral: a wrong key and a corrupt ciphertext read the same.
		// No provider I/O happened, so the request count is a known zero.
		return AccessObservation{ResultCode: AccessSyncCredentialUnavailable, RequestCount: 0}, true
	}
	pat, err := unwrapServicePAT(envelope)
	if err != nil {
		return AccessObservation{ResultCode: AccessSyncCredentialUnavailable, RequestCount: 0}, true
	}
	defer clearBytes(pat)

	runCtx, cancel := context.WithTimeout(ctx, accessShadowOverallDeadline)
	defer cancel()
	observation := s.observer.ObserveAccess(runCtx, AccessObserveInput{
		BaseURL:                   snapshot.baseURL,
		OrganizationSlug:          snapshot.organizationSlug,
		PAT:                       pat,
		BoundServiceUserRemoteID:  snapshot.serviceUserRemoteID,
		BoundOrganizationRemoteID: snapshot.organizationRemoteID,
		Identities:                snapshot.identities,
		Bindings:                  snapshot.bindings,
	})
	if err := validAccessObservation(snapshot, observation); err != nil {
		// A contract-violating observer publishes nothing; the run records
		// the sanitized invalid-response result.
		return AccessObservation{ResultCode: AccessSyncInvalidResponse}, false
	}
	return observation, true
}

// validAccessObservation rejects observer output that violates the
// observation contract before anything reaches SQLite.
func validAccessObservation(snapshot accessShadowRunSnapshot, observation AccessObservation) error {
	malformed := errors.New("forge access shadow observation is malformed")
	if !observation.ResultCode.observerReturnable() {
		return malformed
	}
	if observation.RequestCount < 0 || observation.RequestCount > AccessSyncRequestLimit {
		return malformed
	}
	if observation.ResultCode != AccessSyncComplete {
		if len(observation.Pairs) != 0 {
			return malformed
		}
		return nil
	}
	expected := make(map[[2]int64]bool, len(snapshot.identities)*len(snapshot.bindings))
	for _, identity := range snapshot.identities {
		for _, binding := range snapshot.bindings {
			expected[[2]int64{identity.IdentityID, binding.RepositoryID}] = false
		}
	}
	if len(observation.Pairs) != len(expected) {
		return malformed
	}
	for _, pair := range observation.Pairs {
		key := [2]int64{pair.IdentityID, pair.RepositoryID}
		seen, known := expected[key]
		if !known || seen || !pair.Reason.Valid() {
			return malformed
		}
		expected[key] = true
	}
	return nil
}

func (s *AccessShadowService) finalizeRun(
	ctx context.Context,
	snapshot accessShadowRunSnapshot,
	observation AccessObservation,
	requestCountKnown bool,
) (AccessSyncResultCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin forge access shadow finalization: %w", err)
	}
	defer tx.Rollback()
	// Take writer ownership on the exact run row before any read.
	if _, err := tx.ExecContext(ctx, `
UPDATE forge_access_shadow_runs SET id = id WHERE id = ?`, snapshot.runID); err != nil {
		return "", fmt.Errorf("lock forge access shadow run: %w", err)
	}
	var runConnectionID int64
	var requester sql.NullInt64
	var resultCode sql.NullString
	var runTriggerText string
	err = tx.QueryRowContext(ctx, `
SELECT connection_id, requested_by_user_id, run_trigger, result_code
FROM forge_access_shadow_runs
WHERE id = ?`, snapshot.runID).Scan(&runConnectionID, &requester, &runTriggerText, &resultCode)
	if errors.Is(err, sql.ErrNoRows) {
		// The row was terminalized by a later reservation and retained away;
		// a late observer return can never publish.
		return "", ErrAccessSyncInterrupted
	}
	if err != nil {
		return "", fmt.Errorf("read forge access shadow run for finalization: %w", err)
	}
	runTrigger := AccessShadowRunTrigger(runTriggerText)
	if resultCode.Valid || runConnectionID != snapshot.connectionID ||
		!runTrigger.Valid() || runTrigger != snapshot.runTrigger {
		return "", ErrAccessSyncInterrupted
	}

	scopeCurrent, err := accessShadowScopeUnchanged(ctx, tx, snapshot)
	if err != nil {
		return "", err
	}
	result := observation.ResultCode
	if !scopeCurrent {
		// A stale revision or changed identity/binding set can never publish.
		result = AccessSyncScopeChanged
	}

	now, err := s.finalizationTime(ctx, tx, snapshot.connectionID, snapshot.startedAt, result == AccessSyncComplete)
	if err != nil {
		return "", err
	}
	var presentCount, unknownCount *int64
	if result == AccessSyncComplete {
		present, unknown := int64(0), int64(0)
		for _, pair := range observation.Pairs {
			switch pair.Reason.State() {
			case AccessStateConfirmedPresent:
				present++
			case AccessStateUnknown:
				unknown++
			}
			if err := upsertAccessShadowObservation(ctx, tx, snapshot.connectionID, snapshot.runID, pair, now); err != nil {
				return "", err
			}
		}
		presentCount, unknownCount = &present, &unknown
	}

	finalized, err := finalizeAccessShadowRunRow(ctx, tx, snapshot.runID, result, presentCount, unknownCount, now)
	if err != nil {
		return "", err
	}
	if !finalized {
		return "", ErrAccessSyncInterrupted
	}
	if result == AccessSyncComplete && snapshot.runTrigger == AccessShadowRunManual {
		if err := advanceAccessShadowPeriodicAfterManualComplete(ctx, tx, snapshot); err != nil {
			return "", err
		}
	}
	if err := applyAccessShadowRetention(ctx, tx, snapshot.connectionID); err != nil {
		return "", err
	}
	var requestCount *int64
	if requestCountKnown {
		count := observation.RequestCount
		requestCount = &count
	}
	// The finished event is attributed to the run's persisted requester, so
	// finalization stays actor-independent even after a logout, demotion, or
	// account deletion mid-run.
	if err := recordAccessSyncFinished(
		ctx,
		tx,
		nullableActor(requester),
		runTrigger,
		snapshot.connectionID,
		snapshot.runID,
		result,
		presentCount,
		unknownCount,
		requestCount,
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", ErrAccessSyncOutcomeUnknown
	}
	return result, nil
}

// finalizationTime clamps the finish instant so it can never precede the
// run's start or, when observations will be written, any already persisted
// observation time.
func (s *AccessShadowService) finalizationTime(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	startedAt time.Time,
	willPublish bool,
) (time.Time, error) {
	now := s.now().UTC()
	if now.Before(startedAt) {
		now = startedAt
	}
	if !willPublish {
		return now, nil
	}
	var newest sql.NullString
	if err := tx.QueryRowContext(ctx, `
SELECT MAX(latest_observed_at) FROM forge_access_shadow_observations WHERE connection_id = ?`,
		connectionID).Scan(&newest); err != nil {
		return time.Time{}, fmt.Errorf("read newest forge access shadow observation time: %w", err)
	}
	if newest.Valid {
		previous, err := parseForgeConnectionTime(newest.String)
		if err != nil {
			return time.Time{}, errors.New("forge access shadow observation data is malformed")
		}
		if now.Before(previous) {
			now = previous
		}
	}
	return now, nil
}

// accessShadowScopeUnchanged rechecks every captured fence: the connection
// revisions and the exact identity and binding id sets.
func accessShadowScopeUnchanged(ctx context.Context, tx *sql.Tx, snapshot accessShadowRunSnapshot) (bool, error) {
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return false, err
	}
	if !found || record.ID != snapshot.connectionID ||
		record.Revision != snapshot.configRevision ||
		record.CheckGeneration != snapshot.checkGeneration ||
		record.BindingRevision != snapshot.bindingRevision ||
		record.AccessIdentityRevision != snapshot.accessIdentityRevision {
		return false, nil
	}
	identities, err := loadAccessShadowIdentities(ctx, tx, snapshot.connectionID)
	if err != nil {
		return false, err
	}
	if len(identities) != len(snapshot.identities) {
		return false, nil
	}
	for i, identity := range identities {
		if identity.IdentityID != snapshot.identities[i].IdentityID {
			return false, nil
		}
	}
	bindings, err := loadAccessShadowBindings(ctx, tx, snapshot.connectionID)
	if err != nil {
		return false, err
	}
	if len(bindings) != len(snapshot.bindings) {
		return false, nil
	}
	for i, binding := range bindings {
		if binding.RepositoryID != snapshot.bindings[i].RepositoryID {
			return false, nil
		}
	}
	return true, nil
}

func upsertAccessShadowObservation(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	runID int64,
	pair AccessPairObservation,
	observedAt time.Time,
) error {
	var confirmedReason, confirmedRunID, confirmedAt any
	if pair.Reason.Confirmed() {
		confirmedReason = string(pair.Reason)
		confirmedRunID = runID
		confirmedAt = formatForgeConnectionTime(observedAt)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(connection_id, identity_id, repository_id) DO UPDATE SET
  latest_reason = excluded.latest_reason,
  latest_run_id = excluded.latest_run_id,
  latest_observed_at = excluded.latest_observed_at,
  last_confirmed_reason = COALESCE(excluded.last_confirmed_reason, last_confirmed_reason),
  last_confirmed_run_id = COALESCE(excluded.last_confirmed_run_id, last_confirmed_run_id),
  last_confirmed_at = COALESCE(excluded.last_confirmed_at, last_confirmed_at)`,
		connectionID,
		pair.IdentityID,
		pair.RepositoryID,
		string(pair.Reason),
		runID,
		formatForgeConnectionTime(observedAt),
		confirmedReason,
		confirmedRunID,
		confirmedAt,
	); err != nil {
		return fmt.Errorf("upsert forge access shadow observation: %w", err)
	}
	return nil
}

func finalizeAccessShadowRunRow(
	ctx context.Context,
	tx *sql.Tx,
	runID int64,
	result AccessSyncResultCode,
	presentCount *int64,
	unknownCount *int64,
	finishedAt time.Time,
) (bool, error) {
	var present, unknown any
	if presentCount != nil {
		present = *presentCount
	}
	if unknownCount != nil {
		unknown = *unknownCount
	}
	finalized, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_access_shadow_runs
SET result_code = ?, present_count = ?, unknown_count = ?, finished_at = ?
WHERE id = ? AND result_code IS NULL`,
		string(result),
		present,
		unknown,
		formatForgeConnectionTime(finishedAt),
		runID,
	)
	if err != nil {
		return false, fmt.Errorf("finalize forge access shadow run: %w", err)
	}
	return finalized, nil
}

// applyAccessShadowRetention keeps exactly the union of the newest terminal
// attempt and the newest completed snapshot anchor; a running row is never
// touched. COALESCE is load-bearing: a NULL subquery would poison NOT IN
// and delete nothing.
func applyAccessShadowRetention(ctx context.Context, tx *sql.Tx, connectionID int64) error {
	if _, err := tx.ExecContext(ctx, `
DELETE FROM forge_access_shadow_runs
WHERE connection_id = ?
  AND result_code IS NOT NULL
  AND id NOT IN (
    COALESCE((SELECT id FROM forge_access_shadow_runs
      WHERE connection_id = ? AND result_code IS NOT NULL
      ORDER BY id DESC LIMIT 1), 0),
    COALESCE((SELECT id FROM forge_access_shadow_runs
      WHERE connection_id = ? AND result_code = 'complete'
      ORDER BY id DESC LIMIT 1), 0)
  )`, connectionID, connectionID, connectionID); err != nil {
		return fmt.Errorf("apply forge access shadow retention: %w", err)
	}
	return nil
}

func currentOrganizationSlug(record connectionRecord) string {
	if record.Organization == nil {
		return record.OrganizationSlug
	}
	return record.Organization.Slug
}

// currentAccessSetupEvidence requires bound immutable identities plus a
// current successful setup check at the connection's exact revision and
// generation.
func currentAccessSetupEvidence(record connectionRecord) bool {
	return record.bound() &&
		record.SetupCheck != nil &&
		record.SetupCheck.ConfigRevision == record.Revision &&
		record.SetupCheck.CheckGeneration == record.CheckGeneration &&
		record.SetupCheck.ResultCode.Observed()
}

func loadAccessShadowIdentities(ctx context.Context, q queryer, connectionID int64) ([]AccessShadowIdentity, error) {
	rows, err := q.QueryContext(ctx, `
SELECT id, remote_user_id, username_at_link
FROM forgejo_identities
WHERE connection_id = ?
ORDER BY id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read forge access shadow identities: %w", err)
	}
	defer rows.Close()
	identities := make([]AccessShadowIdentity, 0, AccessShadowIdentityLimit)
	for rows.Next() {
		var identity AccessShadowIdentity
		if err := rows.Scan(&identity.IdentityID, &identity.RemoteUserID, &identity.UsernameAtLink); err != nil {
			return nil, fmt.Errorf("scan forge access shadow identity: %w", err)
		}
		if identity.IdentityID <= 0 || !validRemoteID(identity.RemoteUserID) ||
			!validRemoteName(identity.UsernameAtLink) {
			return nil, errors.New("forge access shadow identity data is malformed")
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read forge access shadow identity rows: %w", err)
	}
	return identities, nil
}

func loadAccessShadowBindings(ctx context.Context, q queryer, connectionID int64) ([]AccessShadowBinding, error) {
	records, err := loadRepositoryBindingRows(ctx, q, connectionID)
	if err != nil {
		return nil, err
	}
	bindings := make([]AccessShadowBinding, 0, len(records))
	for _, record := range records {
		bindings = append(bindings, AccessShadowBinding{
			RepositoryID:       record.repositoryID,
			RemoteRepositoryID: record.remoteID,
		})
	}
	return bindings, nil
}

func recordAccessSyncStarted(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID *int64,
	runTrigger AccessShadowRunTrigger,
	connectionID int64,
	runID int64,
	identityCount int,
	repositoryCount int,
) error {
	if !runTrigger.Valid() ||
		(runTrigger == AccessShadowRunManual && (actorUserID == nil || *actorUserID <= 0)) ||
		(runTrigger == AccessShadowRunPeriodic && actorUserID != nil) {
		return errors.New("forge access shadow start audit attribution is malformed")
	}
	actorKind, actorRole := "", ""
	if runTrigger == AccessShadowRunPeriodic {
		actorKind = domain.ActorKindSystem
		actorRole = AccessShadowRunnerActorRole
	}
	details, err := json.Marshal(struct {
		RunID           int64                  `json:"run_id"`
		IdentityCount   int                    `json:"identity_count"`
		RepositoryCount int                    `json:"repository_count"`
		RunTrigger      AccessShadowRunTrigger `json:"run_trigger"`
		ActorKind       string                 `json:"actor_kind,omitempty"`
		ActorRole       string                 `json:"actor_role,omitempty"`
	}{
		RunID:           runID,
		IdentityCount:   identityCount,
		RepositoryCount: repositoryCount,
		RunTrigger:      runTrigger,
		ActorKind:       actorKind,
		ActorRole:       actorRole,
	})
	if err != nil {
		return errors.New("encode forge access shadow start audit evidence")
	}
	return recordForgeConnectionEventForActor(
		ctx,
		tx,
		actorUserID,
		audit.ActionForgeAccessSyncStarted,
		connectionID,
		string(details),
	)
}

func recordAccessSyncFinished(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID *int64,
	runTrigger AccessShadowRunTrigger,
	connectionID int64,
	runID int64,
	result AccessSyncResultCode,
	presentCount *int64,
	unknownCount *int64,
	requestCount *int64,
) error {
	if !runTrigger.Valid() || runTrigger == AccessShadowRunPeriodic && actorUserID != nil {
		return errors.New("forge access shadow finish audit attribution is malformed")
	}
	actorKind, actorRole := "", ""
	if runTrigger == AccessShadowRunPeriodic {
		actorKind = domain.ActorKindSystem
		actorRole = AccessShadowRunnerActorRole
	}
	details, err := json.Marshal(struct {
		RunID        int64                  `json:"run_id"`
		ResultCode   AccessSyncResultCode   `json:"result_code"`
		RunTrigger   AccessShadowRunTrigger `json:"run_trigger"`
		PresentCount *int64                 `json:"present_count,omitempty"`
		UnknownCount *int64                 `json:"unknown_count,omitempty"`
		RequestCount *int64                 `json:"request_count,omitempty"`
		ActorKind    string                 `json:"actor_kind,omitempty"`
		ActorRole    string                 `json:"actor_role,omitempty"`
	}{
		RunID:        runID,
		ResultCode:   result,
		RunTrigger:   runTrigger,
		PresentCount: presentCount,
		UnknownCount: unknownCount,
		RequestCount: requestCount,
		ActorKind:    actorKind,
		ActorRole:    actorRole,
	})
	if err != nil {
		return errors.New("encode forge access shadow finish audit evidence")
	}
	return recordForgeConnectionEventForActor(
		ctx,
		tx,
		actorUserID,
		audit.ActionForgeAccessSyncFinished,
		connectionID,
		string(details),
	)
}
