package forgeconnection

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// accessShadowRunRecord is the internal load model of one run row.
type accessShadowRunRecord struct {
	id                     int64
	runTrigger             AccessShadowRunTrigger
	configRevision         int64
	checkGeneration        int64
	bindingRevision        int64
	accessIdentityRevision int64
	identityCount          int64
	repositoryCount        int64
	resultCode             AccessSyncResultCode // empty while running
	presentCount           *int64
	unknownCount           *int64
	startedAt              time.Time
	finishedAt             *time.Time
}

type accessShadowIdentityLabel struct {
	identityID     int64
	userID         int64
	usernameAtLink string
	displayName    string
	email          string
	disabled       bool
}

type accessShadowObservationRecord struct {
	identityID          int64
	repositoryID        int64
	latestReason        AccessObservationReason
	latestRunID         int64
	latestObservedAt    time.Time
	lastConfirmedReason AccessObservationReason // empty when no confirmation is preserved
	lastConfirmedRunID  int64
	lastConfirmedAt     time.Time
}

// View assembles everything the shadow-access summary and details pages
// need at one database snapshot. It exposes local labels and derived states
// only; remote ids never leave the service.
func (s *AccessShadowService) View(ctx context.Context) (AccessShadowView, error) {
	if s == nil || s.db == nil {
		return AccessShadowView{}, errors.New("forge access shadow service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessShadowView{}, fmt.Errorf("begin forge access shadow view read: %w", err)
	}
	defer tx.Rollback()

	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return AccessShadowView{}, err
	}
	if !found {
		return AccessShadowView{}, nil
	}
	now := s.now().UTC()
	view := AccessShadowView{
		HasConnection:          true,
		ConnectionID:           record.ID,
		ConfigRevision:         record.Revision,
		CheckGeneration:        record.CheckGeneration,
		BindingRevision:        record.BindingRevision,
		AccessIdentityRevision: record.AccessIdentityRevision,
		SetupEvidenceCurrent:   currentAccessSetupEvidence(record),
		EncryptionAvailable:    s.secrets != nil,
	}
	identities, err := loadAccessShadowIdentityLabels(ctx, tx, record.ID)
	if err != nil {
		return AccessShadowView{}, err
	}
	bindings, err := loadAccessShadowBoundRepositories(ctx, tx, record.ID)
	if err != nil {
		return AccessShadowView{}, err
	}
	view.IdentityCount = len(identities)
	view.BindingCount = len(bindings)
	view.WithinLimits = accessShadowScopeWithinLimits(len(identities), len(bindings))
	view.BoundRepositories = bindings
	view.PeriodicBlockers = accessShadowPeriodicBlockers(
		view.EncryptionAvailable,
		view.SetupEvidenceCurrent,
		view.IdentityCount,
		view.BindingCount,
	)
	periodic, hasPeriodic, err := loadAccessShadowPeriodicConfig(ctx, tx, record.ID)
	if err != nil {
		return AccessShadowView{}, err
	}
	if hasPeriodic {
		view.PeriodicRevision = periodic.revision
		if periodic.nextDueAt != nil {
			nextDueAt := *periodic.nextDueAt
			view.PeriodicNextDueAt = &nextDueAt
		}
	}

	newestRun, hasNewestRun, err := loadNewestAccessShadowRun(ctx, tx, record.ID, false)
	if err != nil {
		return AccessShadowView{}, err
	}
	if hasNewestRun {
		view.NewestRunID = newestRun.id
		attempt := deriveAccessShadowAttempt(newestRun, now)
		view.LatestAttempt = &attempt
	}
	view.PeriodicDueStatus = deriveAccessShadowPeriodicDueStatus(
		now,
		view.PeriodicNextDueAt,
		view.LatestAttempt,
	)
	newestComplete, hasComplete, err := loadNewestAccessShadowRun(ctx, tx, record.ID, true)
	if err != nil {
		return AccessShadowView{}, err
	}
	if hasComplete {
		snapshot, err := deriveAccessShadowSnapshot(
			record,
			newestComplete,
			len(identities),
			len(bindings),
			now,
		)
		if err != nil {
			return AccessShadowView{}, err
		}
		view.LatestSnapshot = &snapshot
	}

	if view.WithinLimits && len(identities) > 0 && len(bindings) > 0 {
		observations, err := loadAccessShadowObservations(ctx, tx, record.ID)
		if err != nil {
			return AccessShadowView{}, err
		}
		view.Pairs, err = buildAccessShadowPairRows(identities, bindings, observations)
		if err != nil {
			return AccessShadowView{}, err
		}
	}
	return view, nil
}

// deriveAccessShadowAttempt maps the newest run onto the latest-attempt
// axis from its durable state alone. A running row older than the
// interruption age reads as interrupted, and Superseded is exactly the
// durable scope_changed result: later scope drift never relabels a
// historical attempt — scope currency belongs to the completed-snapshot
// axis only.
func deriveAccessShadowAttempt(run accessShadowRunRecord, now time.Time) AccessShadowAttempt {
	attempt := AccessShadowAttempt{
		ResultCode: run.resultCode,
		Trigger:    run.runTrigger,
		StartedAt:  run.startedAt,
		FinishedAt: run.finishedAt,
	}
	switch {
	case run.resultCode == "":
		if now.Sub(run.startedAt) < accessShadowInterruptionAge {
			attempt.Status = AccessAttemptRunning
		} else {
			attempt.Status = AccessAttemptInterrupted
		}
	case run.resultCode == AccessSyncInterrupted:
		attempt.Status = AccessAttemptInterrupted
	case run.resultCode == AccessSyncScopeChanged:
		attempt.Status = AccessAttemptSuperseded
	case run.resultCode == AccessSyncComplete:
		attempt.Status = AccessAttemptCompleted
	case run.resultCode.Valid():
		attempt.Status = AccessAttemptFailed
	default:
		attempt.Status = AccessAttemptOutcomeUnknown
	}
	return attempt
}

func deriveAccessShadowSnapshot(
	record connectionRecord,
	run accessShadowRunRecord,
	identityCount int,
	bindingCount int,
	now time.Time,
) (AccessShadowSnapshot, error) {
	if run.resultCode != AccessSyncComplete || run.presentCount == nil || run.unknownCount == nil || run.finishedAt == nil {
		return AccessShadowSnapshot{}, errors.New("forge access shadow snapshot data is malformed")
	}
	pairCount := run.identityCount * run.repositoryCount
	age := now.Sub(*run.finishedAt)
	if age < 0 {
		age = 0
	}
	return AccessShadowSnapshot{
		RunID:        run.id,
		PresentCount: *run.presentCount,
		UnknownCount: *run.unknownCount,
		AbsentCount:  pairCount - *run.presentCount - *run.unknownCount,
		PairCount:    pairCount,
		ScopeCurrent: accessShadowRunScopeCurrent(record, run, identityCount, bindingCount),
		Age:          age,
		ObservedAt:   *run.finishedAt,
	}, nil
}

func deriveAccessShadowPeriodicDueStatus(
	now time.Time,
	nextDueAt *time.Time,
	latestAttempt *AccessShadowAttempt,
) AccessShadowPeriodicDueStatus {
	if latestAttempt != nil && latestAttempt.Trigger == AccessShadowRunPeriodic &&
		latestAttempt.Status == AccessAttemptRunning {
		return AccessPeriodicRunning
	}
	if nextDueAt == nil {
		return AccessPeriodicNotScheduled
	}
	if nextDueAt.After(now) {
		return AccessPeriodicScheduled
	}
	if now.Sub(*nextDueAt) > accessShadowPeriodicOverdueAge {
		return AccessPeriodicOverdue
	}
	return AccessPeriodicDue
}

// accessShadowRunScopeCurrent compares the run's captured pair-scope fences
// with the current connection. The setup-check generation is deliberately
// absent: a later routine connection check refreshes evidence without
// changing the identity x binding scope. The current identity and binding
// counts are compared as well as the revisions: at the maximum
// access-identity revision, unlink and purge are a permitted same-revision
// reduction, and the shrunken counts are what still expose the change.
func accessShadowRunScopeCurrent(
	record connectionRecord,
	run accessShadowRunRecord,
	identityCount int,
	bindingCount int,
) bool {
	return record.Revision == run.configRevision &&
		record.BindingRevision == run.bindingRevision &&
		record.AccessIdentityRevision == run.accessIdentityRevision &&
		int64(identityCount) == run.identityCount &&
		int64(bindingCount) == run.repositoryCount
}

func loadNewestAccessShadowRun(
	ctx context.Context,
	q queryer,
	connectionID int64,
	completeOnly bool,
) (accessShadowRunRecord, bool, error) {
	query := `
SELECT id, run_trigger, config_revision, check_generation, binding_revision, access_identity_revision,
  identity_count, repository_count, result_code, present_count, unknown_count,
  started_at, finished_at
FROM forge_access_shadow_runs
WHERE connection_id = ?`
	if completeOnly {
		query += ` AND result_code = 'complete'`
	}
	query += `
ORDER BY id DESC
LIMIT 1`
	var run accessShadowRunRecord
	var resultCode sql.NullString
	var presentCount, unknownCount sql.NullInt64
	var startedAtText string
	var finishedAtText sql.NullString
	err := q.QueryRowContext(ctx, query, connectionID).Scan(
		&run.id,
		&run.runTrigger,
		&run.configRevision,
		&run.checkGeneration,
		&run.bindingRevision,
		&run.accessIdentityRevision,
		&run.identityCount,
		&run.repositoryCount,
		&resultCode,
		&presentCount,
		&unknownCount,
		&startedAtText,
		&finishedAtText,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return accessShadowRunRecord{}, false, nil
	}
	if err != nil {
		return accessShadowRunRecord{}, false, fmt.Errorf("read forge access shadow run: %w", err)
	}
	malformed := errors.New("forge access shadow run data is malformed")
	if run.id <= 0 || !run.runTrigger.Valid() || run.configRevision <= 0 || run.checkGeneration <= 0 ||
		run.bindingRevision < 0 || run.accessIdentityRevision <= 0 ||
		run.identityCount < 1 || run.identityCount > AccessShadowIdentityLimit ||
		run.repositoryCount < 1 || run.repositoryCount > AccessShadowRepositoryLimit {
		return accessShadowRunRecord{}, false, malformed
	}
	run.startedAt, err = parseForgeConnectionTime(startedAtText)
	if err != nil {
		return accessShadowRunRecord{}, false, malformed
	}
	if resultCode.Valid {
		code := AccessSyncResultCode(resultCode.String)
		if !code.Valid() || !finishedAtText.Valid {
			return accessShadowRunRecord{}, false, malformed
		}
		run.resultCode = code
		finishedAt, err := parseForgeConnectionTime(finishedAtText.String)
		if err != nil {
			return accessShadowRunRecord{}, false, malformed
		}
		run.finishedAt = &finishedAt
	} else if finishedAtText.Valid {
		return accessShadowRunRecord{}, false, malformed
	}
	if presentCount.Valid != (run.resultCode == AccessSyncComplete) ||
		unknownCount.Valid != (run.resultCode == AccessSyncComplete) {
		return accessShadowRunRecord{}, false, malformed
	}
	if presentCount.Valid {
		present, unknown := presentCount.Int64, unknownCount.Int64
		if present < 0 || unknown < 0 || present+unknown > run.identityCount*run.repositoryCount {
			return accessShadowRunRecord{}, false, malformed
		}
		run.presentCount, run.unknownCount = &present, &unknown
	}
	return run, true, nil
}

func loadAccessShadowIdentityLabels(ctx context.Context, q queryer, connectionID int64) ([]accessShadowIdentityLabel, error) {
	rows, err := q.QueryContext(ctx, `
SELECT i.id, i.user_id, i.username_at_link, u.display_name, u.email, u.disabled_at IS NOT NULL
FROM forgejo_identities i
JOIN users u ON u.id = i.user_id
WHERE i.connection_id = ?
ORDER BY i.id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read forge access shadow identity labels: %w", err)
	}
	defer rows.Close()
	labels := make([]accessShadowIdentityLabel, 0, AccessShadowIdentityLimit)
	for rows.Next() {
		var label accessShadowIdentityLabel
		var disabled int64
		if err := rows.Scan(
			&label.identityID,
			&label.userID,
			&label.usernameAtLink,
			&label.displayName,
			&label.email,
			&disabled,
		); err != nil {
			return nil, fmt.Errorf("scan forge access shadow identity label: %w", err)
		}
		if label.identityID <= 0 || label.userID <= 0 || !validRemoteName(label.usernameAtLink) ||
			disabled < 0 || disabled > 1 {
			return nil, errors.New("forge access shadow identity data is malformed")
		}
		label.disabled = disabled == 1
		labels = append(labels, label)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read forge access shadow identity label rows: %w", err)
	}
	return labels, nil
}

func loadAccessShadowBoundRepositories(ctx context.Context, q queryer, connectionID int64) ([]AccessShadowBoundRepository, error) {
	rows, err := q.QueryContext(ctx, `
SELECT b.repository_id, r.owner, r.name
FROM forge_repository_bindings b
JOIN repositories r ON r.id = b.repository_id
WHERE b.connection_id = ?
ORDER BY r.owner || '/' || r.name, b.repository_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read forge access shadow binding labels: %w", err)
	}
	defer rows.Close()
	repositories := make([]AccessShadowBoundRepository, 0, AccessShadowRepositoryLimit)
	for rows.Next() {
		var repository AccessShadowBoundRepository
		var owner, name string
		if err := rows.Scan(&repository.RepositoryID, &owner, &name); err != nil {
			return nil, fmt.Errorf("scan forge access shadow binding label: %w", err)
		}
		if repository.RepositoryID <= 0 || owner == "" || name == "" {
			return nil, errors.New("forge access shadow binding data is malformed")
		}
		repository.RepositoryFullName = owner + "/" + name
		repositories = append(repositories, repository)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read forge access shadow binding label rows: %w", err)
	}
	return repositories, nil
}

func loadAccessShadowObservations(ctx context.Context, q queryer, connectionID int64) (map[[2]int64]accessShadowObservationRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
FROM forge_access_shadow_observations
WHERE connection_id = ?`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read forge access shadow observations: %w", err)
	}
	defer rows.Close()
	observations := make(map[[2]int64]accessShadowObservationRecord, AccessShadowPairLimit)
	for rows.Next() {
		var record accessShadowObservationRecord
		var latestReason, latestObservedAt string
		var confirmedReason, confirmedAt sql.NullString
		var confirmedRunID sql.NullInt64
		if err := rows.Scan(
			&record.identityID,
			&record.repositoryID,
			&latestReason,
			&record.latestRunID,
			&latestObservedAt,
			&confirmedReason,
			&confirmedRunID,
			&confirmedAt,
		); err != nil {
			return nil, fmt.Errorf("scan forge access shadow observation: %w", err)
		}
		malformed := errors.New("forge access shadow observation data is malformed")
		record.latestReason = AccessObservationReason(latestReason)
		if record.identityID <= 0 || record.repositoryID <= 0 ||
			!record.latestReason.Valid() || record.latestRunID <= 0 {
			return nil, malformed
		}
		record.latestObservedAt, err = parseForgeConnectionTime(latestObservedAt)
		if err != nil {
			return nil, malformed
		}
		if confirmedReason.Valid != confirmedRunID.Valid || confirmedReason.Valid != confirmedAt.Valid {
			return nil, malformed
		}
		if record.latestReason.Confirmed() && !confirmedReason.Valid {
			return nil, malformed
		}
		if confirmedReason.Valid {
			record.lastConfirmedReason = AccessObservationReason(confirmedReason.String)
			if !record.lastConfirmedReason.Confirmed() || confirmedRunID.Int64 <= 0 {
				return nil, malformed
			}
			record.lastConfirmedRunID = confirmedRunID.Int64
			record.lastConfirmedAt, err = parseForgeConnectionTime(confirmedAt.String)
			if err != nil {
				return nil, malformed
			}
			// A confirmed latest reason is its own confirmation; an unknown
			// latest reason may only preserve a strictly earlier run's
			// confirmation, never render one run as both.
			if record.latestReason.Confirmed() {
				if record.lastConfirmedReason != record.latestReason ||
					record.lastConfirmedRunID != record.latestRunID ||
					!record.lastConfirmedAt.Equal(record.latestObservedAt) {
					return nil, malformed
				}
			} else if record.lastConfirmedRunID >= record.latestRunID {
				return nil, malformed
			}
		}
		key := [2]int64{record.identityID, record.repositoryID}
		if _, duplicate := observations[key]; duplicate {
			return nil, malformed
		}
		observations[key] = record
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read forge access shadow observation rows: %w", err)
	}
	return observations, nil
}

// buildAccessShadowPairRows crosses the current identities and bindings,
// attaches the latest observation where one exists, and sorts by local user
// label, repository label, then internal ids.
func buildAccessShadowPairRows(
	identities []accessShadowIdentityLabel,
	bindings []AccessShadowBoundRepository,
	observations map[[2]int64]accessShadowObservationRecord,
) ([]AccessShadowPairRow, error) {
	rows := make([]AccessShadowPairRow, 0, len(identities)*len(bindings))
	seen := make(map[[2]int64]bool, len(identities)*len(bindings))
	for _, identity := range identities {
		for _, binding := range bindings {
			key := [2]int64{identity.userID, binding.RepositoryID}
			if seen[key] {
				return nil, errors.New("forge access shadow pair data contains duplicate user and repository")
			}
			seen[key] = true
			row := AccessShadowPairRow{
				IdentityID:         identity.identityID,
				UserID:             identity.userID,
				RepositoryID:       binding.RepositoryID,
				UserDisplayName:    identity.displayName,
				UserEmail:          identity.email,
				UserDisabled:       identity.disabled,
				UsernameAtLink:     identity.usernameAtLink,
				RepositoryFullName: binding.RepositoryFullName,
			}
			if observation, found := observations[[2]int64{identity.identityID, binding.RepositoryID}]; found {
				row.Observed = true
				row.LatestReason = observation.latestReason
				row.LatestRunID = observation.latestRunID
				row.LatestObservedAt = observation.latestObservedAt
				if !observation.latestReason.Confirmed() && observation.lastConfirmedReason != "" {
					row.PriorConfirmedReason = observation.lastConfirmedReason
					row.PriorConfirmedAt = observation.lastConfirmedAt
				}
			}
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].UserDisplayName != rows[j].UserDisplayName {
			return rows[i].UserDisplayName < rows[j].UserDisplayName
		}
		if rows[i].RepositoryFullName != rows[j].RepositoryFullName {
			return rows[i].RepositoryFullName < rows[j].RepositoryFullName
		}
		if rows[i].IdentityID != rows[j].IdentityID {
			return rows[i].IdentityID < rows[j].IdentityID
		}
		return rows[i].RepositoryID < rows[j].RepositoryID
	})
	return rows, nil
}
