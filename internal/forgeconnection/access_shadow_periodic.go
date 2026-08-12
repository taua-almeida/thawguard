package forgeconnection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

type accessShadowPeriodicConfigRecord struct {
	revision  int64
	nextDueAt *time.Time
}

// EnablePeriodic schedules the first periodic snapshot five minutes after an
// Administrator explicitly enables it. The transaction performs no PAT
// decryption and no provider I/O. The bool is true only when a configuration
// mutation durably committed; an exact already-enabled state returns false.
func (s *AccessShadowService) EnablePeriodic(
	ctx context.Context,
	actorUserID int64,
	input EnableAccessShadowPeriodicInput,
) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("forge access shadow service has no database")
	}
	if actorUserID <= 0 {
		return false, ErrAuthorization
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedConfigRevision <= 0 ||
		input.ExpectedCheckGeneration <= 0 || input.ExpectedBindingRevision < 0 ||
		input.ExpectedAccessIdentityRevision <= 0 || input.ExpectedNewestRunID < 0 ||
		input.ExpectedPeriodicRevision < 0 {
		return false, ValidationError{Message: "the expected connection, scope, run, and periodic revisions must identify the rendered state"}
	}
	if !input.ConfirmPeriodicEnable {
		return false, ValidationError{Message: "confirm periodic shadow refresh before enabling it"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin periodic shadow refresh enable: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return false, err
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrConflict
	}
	periodic, hasPeriodic, err := loadAccessShadowPeriodicConfig(ctx, tx, record.ID)
	if err != nil {
		return false, err
	}
	newest, hasNewest, err := loadNewestAccessShadowReservation(ctx, tx, record.ID)
	if err != nil {
		return false, err
	}
	newestRunID := int64(0)
	if hasNewest {
		newestRunID = newest.id
	}
	periodicRevision := int64(0)
	if hasPeriodic {
		periodicRevision = periodic.revision
	}
	if record.ID != input.ExpectedConnectionID ||
		record.Revision != input.ExpectedConfigRevision ||
		record.CheckGeneration != input.ExpectedCheckGeneration ||
		record.BindingRevision != input.ExpectedBindingRevision ||
		record.AccessIdentityRevision != input.ExpectedAccessIdentityRevision ||
		newestRunID != input.ExpectedNewestRunID ||
		periodicRevision != input.ExpectedPeriodicRevision {
		return false, ErrConflict
	}
	// A current enabled state is an exact no-op after every submitted fence
	// has been checked. It writes neither a revision nor Activity.
	if hasPeriodic && periodic.nextDueAt != nil {
		return false, nil
	}
	identities, err := loadAccessShadowIdentities(ctx, tx, record.ID)
	if err != nil {
		return false, err
	}
	bindings, err := loadAccessShadowBindings(ctx, tx, record.ID)
	if err != nil {
		return false, err
	}
	blockers := accessShadowPeriodicBlockers(
		s.secrets != nil,
		currentAccessSetupEvidence(record),
		len(identities),
		len(bindings),
	)
	if len(blockers) > 0 {
		return false, accessShadowPeriodicEnableError(blockers)
	}
	if hasPeriodic && periodic.revision == math.MaxInt64 {
		return false, ErrAccessPeriodicRevisionExhausted
	}

	nextRevision := int64(1)
	if hasPeriodic {
		nextRevision = periodic.revision + 1
	}
	nextDueAt := s.now().UTC().Add(accessShadowPeriodicCadence)
	if hasPeriodic {
		updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_access_shadow_periodic_config
SET revision = ?, next_due_at = ?
WHERE connection_id = ? AND revision = ? AND next_due_at IS NULL`,
			nextRevision,
			formatForgeConnectionTime(nextDueAt),
			record.ID,
			periodic.revision,
		)
		if err != nil {
			return false, fmt.Errorf("enable periodic shadow refresh: %w", err)
		}
		if !updated {
			return false, ErrConflict
		}
	} else if _, err := tx.ExecContext(ctx, `
INSERT INTO forge_access_shadow_periodic_config(connection_id, revision, next_due_at)
VALUES (?, 1, ?)`, record.ID, formatForgeConnectionTime(nextDueAt)); err != nil {
		return false, fmt.Errorf("create periodic shadow refresh configuration: %w", err)
	}
	if err := recordAccessPeriodicConfiguration(
		ctx,
		tx,
		actorUserID,
		audit.ActionForgeAccessPeriodicEnabled,
		record.ID,
		nextRevision,
	); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, ErrAccessPeriodicOutcomeUnknown
	}
	return true, nil
}

// DisablePeriodic prevents new periodic reservations without touching a live
// run or any completed evidence. It remains available when every observation
// prerequisite is broken.
func (s *AccessShadowService) DisablePeriodic(
	ctx context.Context,
	actorUserID int64,
	input DisableAccessShadowPeriodicInput,
) error {
	if s == nil || s.db == nil {
		return errors.New("forge access shadow service has no database")
	}
	if actorUserID <= 0 {
		return ErrAuthorization
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedPeriodicRevision < 0 {
		return ValidationError{Message: "the expected connection and periodic revision must identify the rendered state"}
	}
	if !input.ConfirmPeriodicDisable {
		return ValidationError{Message: "confirm periodic shadow refresh before disabling it"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin periodic shadow refresh disable: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	connectionID, found, err := loadForgejoConnectionID(ctx, tx)
	if err != nil {
		return err
	}
	if !found || connectionID != input.ExpectedConnectionID {
		return ErrConflict
	}
	periodic, hasPeriodic, err := loadAccessShadowPeriodicConfig(ctx, tx, connectionID)
	if err != nil {
		return err
	}
	periodicRevision := int64(0)
	if hasPeriodic {
		periodicRevision = periodic.revision
	}
	if periodicRevision != input.ExpectedPeriodicRevision {
		return ErrConflict
	}
	// Absence and a NULL due time are both disabled. An exact disabled state
	// is a no-op and records no Activity.
	if !hasPeriodic || periodic.nextDueAt == nil {
		return nil
	}
	if periodic.revision == math.MaxInt64 {
		return ErrAccessPeriodicRevisionExhausted
	}
	nextRevision := periodic.revision + 1
	updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_access_shadow_periodic_config
SET revision = ?, next_due_at = NULL
WHERE connection_id = ? AND revision = ? AND next_due_at IS NOT NULL`,
		nextRevision,
		connectionID,
		periodic.revision,
	)
	if err != nil {
		return fmt.Errorf("disable periodic shadow refresh: %w", err)
	}
	if !updated {
		return ErrConflict
	}
	if err := recordAccessPeriodicConfiguration(
		ctx,
		tx,
		actorUserID,
		audit.ActionForgeAccessPeriodicDisabled,
		connectionID,
		nextRevision,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrAccessPeriodicOutcomeUnknown
	}
	return nil
}

// RunPeriodicDue performs at most one due reservation and then invokes the
// exact shared 3A execution path. Expected no-work scans return nil.
func (s *AccessShadowService) RunPeriodicDue(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("forge access shadow service has no database")
	}
	snapshot, reserved, err := s.reservePeriodicDue(ctx)
	if err != nil {
		return errors.Join(ErrAccessPeriodicReservationFailed, err)
	}
	if !reserved {
		return nil
	}
	_, err = s.executeRun(ctx, snapshot)
	if errors.Is(err, ErrAccessSyncInterrupted) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrAccessPeriodicExecutionFailed, err)
	}
	return nil
}

func (s *AccessShadowService) reservePeriodicDue(
	ctx context.Context,
) (accessShadowRunSnapshot, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return accessShadowRunSnapshot{}, false, fmt.Errorf("begin periodic shadow refresh reservation: %w", err)
	}
	defer tx.Rollback()
	// This code-owned no-op acquires SQLite writer ownership without
	// impersonating a user. Manual and periodic reservations therefore have
	// equal first-writer priority. The impossible positive-id predicate keeps
	// this lock acquisition from rewriting or revalidating any configuration
	// row, including one that the due-error path must repair below.
	if _, err := tx.ExecContext(ctx, `
UPDATE forge_access_shadow_periodic_config
SET revision = revision
WHERE connection_id = 0`); err != nil {
		return accessShadowRunSnapshot{}, false, fmt.Errorf("lock periodic shadow refresh configuration: %w", err)
	}
	now := s.now().UTC()
	connectionID, found, err := loadForgejoConnectionID(ctx, tx)
	if err != nil {
		return accessShadowRunSnapshot{}, false, err
	}
	if !found {
		return accessShadowRunSnapshot{}, false, nil
	}
	nextDueAt, found, err := loadAccessShadowPeriodicDueForScan(ctx, tx, connectionID)
	if err != nil {
		return accessShadowRunSnapshot{}, false, advancePeriodicAfterDueError(
			ctx,
			tx,
			connectionID,
			now,
			err,
		)
	}
	if !found || nextDueAt == nil {
		return accessShadowRunSnapshot{}, false, nil
	}
	if nextDueAt.After(now) {
		return accessShadowRunSnapshot{}, false, nil
	}
	if _, found, err := loadAccessShadowPeriodicConfig(ctx, tx, connectionID); err != nil {
		return accessShadowRunSnapshot{}, false, advancePeriodicAfterDueError(
			ctx,
			tx,
			connectionID,
			now,
			err,
		)
	} else if !found {
		return accessShadowRunSnapshot{}, false, errors.New("periodic shadow refresh configuration disappeared during reservation")
	}
	// All work after the due check lives inside a savepoint. If an
	// unexpected reservation error occurs, rolling back only this savepoint
	// lets the same writer transaction advance the ordinary cadence without
	// retaining a partial orphan recovery, run, or start event.
	if _, err := tx.ExecContext(ctx, `SAVEPOINT forge_access_shadow_periodic_work`); err != nil {
		return accessShadowRunSnapshot{}, false, advancePeriodicAfterDueError(
			ctx,
			tx,
			connectionID,
			now,
			fmt.Errorf("start periodic shadow refresh reservation savepoint: %w", err),
		)
	}
	failReservation := func(cause error) (accessShadowRunSnapshot, bool, error) {
		return accessShadowRunSnapshot{}, false, advancePeriodicAfterReservationError(
			ctx,
			tx,
			connectionID,
			now,
			cause,
		)
	}

	record, hasReadyRecord, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return failReservation(err)
	}
	if !hasReadyRecord || record.ID != connectionID {
		return s.advanceBlockedPeriodicScan(ctx, tx, connectionID, now)
	}
	identities, err := loadAccessShadowIdentities(ctx, tx, connectionID)
	if err != nil {
		return failReservation(err)
	}
	bindings, err := loadAccessShadowBindings(ctx, tx, connectionID)
	if err != nil {
		return failReservation(err)
	}
	if len(accessShadowPeriodicBlockers(
		s.secrets != nil,
		currentAccessSetupEvidence(record),
		len(identities),
		len(bindings),
	)) > 0 {
		return s.advanceBlockedPeriodicScan(ctx, tx, connectionID, now)
	}
	if s.observer == nil {
		return failReservation(errors.New("forge access shadow observer is not configured"))
	}

	newest, hasNewest, err := loadNewestAccessShadowReservation(ctx, tx, connectionID)
	if err != nil {
		return failReservation(err)
	}
	if hasNewest && !newest.resultCode.Valid {
		if now.Sub(newest.startedAt) < accessShadowInterruptionAge {
			return s.advanceBlockedPeriodicScan(ctx, tx, connectionID, now)
		}
		finishedAt := now
		if finishedAt.Before(newest.startedAt) {
			finishedAt = newest.startedAt
		}
		if err := terminalizeAccessShadowOrphan(
			ctx,
			tx,
			connectionID,
			newest.id,
			newest.requester,
			newest.runTrigger,
			finishedAt,
		); err != nil {
			return failReservation(err)
		}
	}

	// started_at describes the reservation that is about to commit, not the
	// beginning of the due scan. Sampling here keeps the fixed 75-second orphan
	// margin available to the 60-second provider deadline and bounded
	// finalization even when local readiness reads were slow.
	startedAt := s.now().UTC()
	if startedAt.Before(now) {
		startedAt = now
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, started_at
)
VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)`,
		connectionID,
		record.Revision,
		record.CheckGeneration,
		record.BindingRevision,
		record.AccessIdentityRevision,
		len(identities),
		len(bindings),
		string(AccessShadowRunPeriodic),
		formatForgeConnectionTime(startedAt),
	)
	if err != nil {
		return failReservation(fmt.Errorf("insert periodic forge access shadow run: %w", err))
	}
	runID, err := result.LastInsertId()
	if err != nil || runID <= 0 {
		return failReservation(errors.New("determine periodic forge access shadow run id"))
	}
	if err := setAccessShadowNextDue(ctx, tx, connectionID, startedAt.Add(accessShadowPeriodicCadence)); err != nil {
		return failReservation(err)
	}
	if err := recordAccessSyncStarted(
		ctx,
		tx,
		nil,
		AccessShadowRunPeriodic,
		connectionID,
		runID,
		len(identities),
		len(bindings),
	); err != nil {
		return failReservation(err)
	}
	if err := tx.Commit(); err != nil {
		return accessShadowRunSnapshot{}, false, ErrAccessPeriodicOutcomeUnknown
	}
	return accessShadowRunSnapshot{
		runID:                  runID,
		runTrigger:             AccessShadowRunPeriodic,
		connectionID:           connectionID,
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
		startedAt:              startedAt,
	}, true, nil
}

func advancePeriodicAfterReservationError(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	now time.Time,
	cause error,
) error {
	if ctx.Err() != nil {
		return cause
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT forge_access_shadow_periodic_work`); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback periodic shadow refresh reservation work: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT forge_access_shadow_periodic_work`); err != nil {
		return errors.Join(cause, fmt.Errorf("release periodic shadow refresh reservation savepoint: %w", err))
	}
	if err := setAccessShadowNextDue(ctx, tx, connectionID, now.Add(accessShadowPeriodicCadence)); err != nil {
		return errors.Join(cause, err)
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(cause, ErrAccessPeriodicOutcomeUnknown)
	}
	return cause
}

func (s *AccessShadowService) advanceBlockedPeriodicScan(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	now time.Time,
) (accessShadowRunSnapshot, bool, error) {
	if err := setAccessShadowNextDue(ctx, tx, connectionID, now.Add(accessShadowPeriodicCadence)); err != nil {
		return accessShadowRunSnapshot{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return accessShadowRunSnapshot{}, false, ErrAccessPeriodicOutcomeUnknown
	}
	return accessShadowRunSnapshot{}, false, nil
}

func setAccessShadowNextDue(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	nextDueAt time.Time,
) error {
	updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_access_shadow_periodic_config
SET next_due_at = ?
WHERE connection_id = ? AND next_due_at IS NOT NULL`,
		formatForgeConnectionTime(nextDueAt),
		connectionID,
	)
	if err != nil {
		return fmt.Errorf("advance periodic shadow refresh due time: %w", err)
	}
	if !updated {
		return errors.New("periodic shadow refresh was disabled during its reservation")
	}
	return nil
}

func advanceAccessShadowPeriodicAfterManualComplete(
	ctx context.Context,
	tx *sql.Tx,
	snapshot accessShadowRunSnapshot,
) error {
	nextDueAt := formatForgeConnectionTime(snapshot.startedAt.Add(accessShadowPeriodicCadence))
	if _, err := tx.ExecContext(ctx, `
UPDATE forge_access_shadow_periodic_config
SET next_due_at = CASE WHEN next_due_at < ? THEN ? ELSE next_due_at END
WHERE connection_id = ? AND next_due_at IS NOT NULL`,
		nextDueAt,
		nextDueAt,
		snapshot.connectionID,
	); err != nil {
		return fmt.Errorf("postpone periodic shadow refresh after manual completion: %w", err)
	}
	return nil
}

func loadAccessShadowPeriodicDueForScan(
	ctx context.Context,
	q queryer,
	connectionID int64,
) (*time.Time, bool, error) {
	var nextDueAt sql.NullString
	err := q.QueryRowContext(ctx, `
SELECT next_due_at
FROM forge_access_shadow_periodic_config
WHERE connection_id = ?`, connectionID).Scan(&nextDueAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read periodic shadow refresh due time: %w", err)
	}
	if !nextDueAt.Valid {
		return nil, true, nil
	}
	parsed, err := parseForgeConnectionTime(nextDueAt.String)
	if err != nil {
		return nil, true, errors.New("periodic shadow refresh configuration is malformed")
	}
	return &parsed, true, nil
}

func advancePeriodicAfterDueError(
	ctx context.Context,
	tx *sql.Tx,
	connectionID int64,
	now time.Time,
	cause error,
) error {
	if ctx.Err() != nil {
		return cause
	}
	if err := setAccessShadowNextDue(ctx, tx, connectionID, now.Add(accessShadowPeriodicCadence)); err != nil {
		return errors.Join(cause, err)
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(cause, ErrAccessPeriodicOutcomeUnknown)
	}
	return cause
}

func loadAccessShadowPeriodicConfig(
	ctx context.Context,
	q queryer,
	connectionID int64,
) (accessShadowPeriodicConfigRecord, bool, error) {
	var record accessShadowPeriodicConfigRecord
	var nextDueAt sql.NullString
	err := q.QueryRowContext(ctx, `
SELECT revision, next_due_at
FROM forge_access_shadow_periodic_config
WHERE connection_id = ?`, connectionID).Scan(&record.revision, &nextDueAt)
	if errors.Is(err, sql.ErrNoRows) {
		return accessShadowPeriodicConfigRecord{}, false, nil
	}
	if err != nil {
		return accessShadowPeriodicConfigRecord{}, false, fmt.Errorf("read periodic shadow refresh configuration: %w", err)
	}
	if record.revision <= 0 {
		return accessShadowPeriodicConfigRecord{}, false, errors.New("periodic shadow refresh configuration is malformed")
	}
	if nextDueAt.Valid {
		parsed, err := parseForgeConnectionTime(nextDueAt.String)
		if err != nil {
			return accessShadowPeriodicConfigRecord{}, false, errors.New("periodic shadow refresh configuration is malformed")
		}
		record.nextDueAt = &parsed
	}
	return record, true, nil
}

func loadForgejoConnectionID(ctx context.Context, q queryer) (int64, bool, error) {
	var connectionID int64
	err := q.QueryRowContext(ctx, `
SELECT id FROM forge_connections WHERE provider = ?`, ProviderForgejo).Scan(&connectionID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read Forgejo connection id: %w", err)
	}
	if connectionID <= 0 {
		return 0, false, errors.New("forge connection data is malformed")
	}
	return connectionID, true, nil
}

func accessShadowScopeWithinLimits(identityCount, bindingCount int) bool {
	return identityCount <= maxAccessShadowIdentities &&
		bindingCount <= maxAccessShadowRepositories &&
		identityCount*bindingCount <= maxAccessShadowPairs
}

func accessShadowPeriodicBlockers(
	encryptionAvailable bool,
	setupEvidenceCurrent bool,
	identityCount int,
	bindingCount int,
) []AccessShadowPeriodicBlocker {
	blockers := make([]AccessShadowPeriodicBlocker, 0, 5)
	if !encryptionAvailable {
		blockers = append(blockers, AccessPeriodicEncryptionUnavailable)
	}
	if !setupEvidenceCurrent {
		blockers = append(blockers, AccessPeriodicSetupEvidenceNotCurrent)
	}
	if identityCount == 0 {
		blockers = append(blockers, AccessPeriodicNoLinkedIdentities)
	}
	if bindingCount == 0 {
		blockers = append(blockers, AccessPeriodicNoBindings)
	}
	if !accessShadowScopeWithinLimits(identityCount, bindingCount) {
		blockers = append(blockers, AccessPeriodicScopeExceedsLimits)
	}
	return blockers
}

func accessShadowPeriodicEnableError(blockers []AccessShadowPeriodicBlocker) error {
	reasons := make([]string, 0, len(blockers))
	encryptionUnavailable := false
	for _, blocker := range blockers {
		switch blocker {
		case AccessPeriodicEncryptionUnavailable:
			encryptionUnavailable = true
			reasons = append(reasons, "service PAT encryption is unavailable")
		case AccessPeriodicSetupEvidenceNotCurrent:
			reasons = append(reasons, "setup evidence is not current")
		case AccessPeriodicNoLinkedIdentities:
			reasons = append(reasons, "no Forgejo identities are linked")
		case AccessPeriodicNoBindings:
			reasons = append(reasons, "no repositories are bound")
		case AccessPeriodicScopeExceedsLimits:
			reasons = append(reasons, "the scope exceeds the 3A limits")
		}
	}
	message := "periodic shadow refresh is blocked: " + strings.Join(reasons, "; ")
	if encryptionUnavailable {
		return fmt.Errorf("%w: %s", ErrConfiguration, message)
	}
	return ValidationError{Message: message}
}

func recordAccessPeriodicConfiguration(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	action string,
	connectionID int64,
	revision int64,
) error {
	details, err := json.Marshal(struct {
		Revision int64 `json:"revision"`
	}{Revision: revision})
	if err != nil {
		return errors.New("encode periodic shadow refresh audit evidence")
	}
	return recordForgeConnectionEvent(ctx, tx, actorUserID, action, connectionID, string(details))
}
