package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

const (
	ReconcileRepositoryEnforcement Type = "reconcile_repository_enforcement"
	reconciliationPayload               = "{}"
	sqliteTimestampFormat               = "2006-01-02T15:04:05.000000000Z"
	ReconciliationLease                 = 2 * time.Minute
)

type Type string

const (
	RecomputePRStatus       Type = "recompute_pr_status"
	RecomputeBranchStatuses Type = "recompute_branch_statuses"
	ActivateScheduledFreeze Type = "activate_scheduled_freeze"
	ExecutePlannedUnfreeze  Type = "execute_planned_unfreeze"
	ExpireThawException     Type = "expire_thaw_exception"
	RetryStatusPost         Type = "retry_status_post"
	RunSetupCheck           Type = "run_setup_check"
	ReconcileOpenPRs        Type = "reconcile_open_prs"
)

var ErrReconciliationInProgress = errors.New("enforcement recovery is already in progress")

type Job struct {
	ID           int64
	RepositoryID int64
	Generation   int64
	RunAt        time.Time
	LockedAt     *time.Time
	Attempts     int
	LastError    string
}

func (j Job) LeaseActive(now time.Time) bool {
	return j.LockedAt != nil && j.LockedAt.After(now.UTC().Add(-ReconciliationLease))
}

type database interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type Store struct {
	db  database
	now func() time.Time
}

func NewStore(db *sql.DB) *Store {
	if db == nil {
		return newStore(nil)
	}
	return newStore(db)
}

func NewStoreTx(tx *sql.Tx) *Store {
	if tx == nil {
		return newStore(nil)
	}
	return newStore(tx)
}

func newStore(db database) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// EnqueueReconciliation records new repository-wide work. An existing row is
// refreshed to run now and advances generation without disturbing its lease.
func (s *Store) EnqueueReconciliation(ctx context.Context, repositoryID int64) (Job, error) {
	return s.upsertReconciliation(ctx, repositoryID, true, "")
}

func (s *Store) EnqueueReconciliationFailure(ctx context.Context, repositoryID int64, category string) (Job, error) {
	return s.upsertReconciliation(ctx, repositoryID, true, category)
}

func (s *Store) EnsureReconciliationFailure(ctx context.Context, repositoryID int64, category string) (Job, error) {
	return s.upsertReconciliation(ctx, repositoryID, false, category)
}

func (s *Store) upsertReconciliation(ctx context.Context, repositoryID int64, advance bool, category string) (Job, error) {
	if s == nil || s.db == nil {
		return Job{}, errors.New("job store has no database")
	}
	if repositoryID <= 0 {
		return Job{}, errors.New("reconciliation repository is required")
	}
	if category != "" && !domain.ValidEnforcementFailureReason(category) {
		return Job{}, errors.New("reconciliation failure category is invalid")
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	generationUpdate := "generation"
	if advance {
		generationUpdate = "generation + 1"
	}
	query := `
INSERT INTO jobs(type, payload_json, repository_id, generation, run_at, locked_at, attempts, last_error, created_at)
VALUES (?, ?, ?, 1, ?, NULL, 0, ?, ?)
ON CONFLICT(repository_id) WHERE type = 'reconcile_repository_enforcement' AND repository_id IS NOT NULL
DO UPDATE SET generation = ` + generationUpdate + `, run_at = excluded.run_at,
  last_error = COALESCE(excluded.last_error, jobs.last_error)`
	if _, err := s.db.ExecContext(ctx, query, ReconcileRepositoryEnforcement, reconciliationPayload, repositoryID, now, nullableString(category), now); err != nil {
		return Job{}, fmt.Errorf("enqueue repository reconciliation: %w", err)
	}
	return s.GetReconciliation(ctx, repositoryID)
}

func (s *Store) GetReconciliation(ctx context.Context, repositoryID int64) (Job, error) {
	if s == nil || s.db == nil {
		return Job{}, errors.New("job store has no database")
	}
	row := s.db.QueryRowContext(ctx, reconciliationSelect+`
WHERE type = ? AND repository_id = ?`, ReconcileRepositoryEnforcement, repositoryID)
	return scanJob(row)
}

func (s *Store) ListReconciliations(ctx context.Context) ([]Job, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("job store has no database")
	}
	rows, err := s.db.QueryContext(ctx, reconciliationSelect+`
WHERE type = ? AND repository_id IS NOT NULL
ORDER BY repository_id ASC`, ReconcileRepositoryEnforcement)
	if err != nil {
		return nil, fmt.Errorf("list repository reconciliations: %w", err)
	}
	defer rows.Close()
	result := make([]Job, 0)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list repository reconciliations rows: %w", err)
	}
	return result, nil
}

func (s *Store) ClaimDue(ctx context.Context, limit int) ([]Job, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("job store has no database")
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	now := s.now().UTC()
	rows, err := s.db.QueryContext(ctx, reconciliationSelect+`
WHERE type = ? AND repository_id IS NOT NULL AND run_at <= ?
  AND (locked_at IS NULL OR locked_at < ?)
ORDER BY run_at ASC, id ASC
LIMIT ?`, ReconcileRepositoryEnforcement, formatTime(now), formatTime(now.Add(-ReconciliationLease)), limit)
	if err != nil {
		return nil, fmt.Errorf("list due repository reconciliations: %w", err)
	}
	candidates := make([]Job, 0)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, job)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close due repository reconciliations: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list due repository reconciliations rows: %w", err)
	}
	claimed := make([]Job, 0, len(candidates))
	for _, candidate := range candidates {
		job, ok, err := s.claim(ctx, candidate, now)
		if err != nil {
			return claimed, err
		}
		if ok {
			claimed = append(claimed, job)
		}
	}
	return claimed, nil
}

func (s *Store) ClaimRepository(ctx context.Context, repositoryID int64) (Job, bool, error) {
	job, err := s.GetReconciliation(ctx, repositoryID)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, err
	}
	now := s.now().UTC()
	if job.RunAt.After(now) || job.LeaseActive(now) {
		return Job{}, false, nil
	}
	return s.claim(ctx, job, now)
}

func (s *Store) claim(ctx context.Context, candidate Job, now time.Time) (Job, bool, error) {
	lockedAt := formatTime(now)
	result, err := s.db.ExecContext(ctx, `
UPDATE jobs
SET locked_at = ?, attempts = attempts + 1
WHERE id = ? AND type = ? AND generation = ? AND run_at <= ?
  AND (locked_at IS NULL OR locked_at < ?)`, lockedAt, candidate.ID, ReconcileRepositoryEnforcement, candidate.Generation, lockedAt, formatTime(now.Add(-ReconciliationLease)))
	if err != nil {
		return Job{}, false, fmt.Errorf("claim repository reconciliation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Job{}, false, fmt.Errorf("claim repository reconciliation rows: %w", err)
	}
	if affected == 0 {
		return Job{}, false, nil
	}
	candidate.Attempts++
	candidate.LockedAt = timePointer(now)
	return candidate, true, nil
}

// ClaimCurrent reports whether claim still owns the exact live generation and
// lease. Callers check this before external side effects so an expired or
// superseded worker cannot publish stale repository policy.
func (s *Store) ClaimCurrent(ctx context.Context, claim Job) (bool, error) {
	if err := validateClaim(claim); err != nil {
		return false, err
	}
	var current bool
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM jobs
  WHERE id = ? AND type = ? AND generation = ? AND locked_at = ? AND locked_at > ?
)`, claim.ID, ReconcileRepositoryEnforcement, claim.Generation, formatTime(*claim.LockedAt), formatTime(s.now().UTC().Add(-ReconciliationLease))).Scan(&current)
	if err != nil {
		return false, fmt.Errorf("check repository reconciliation claim: %w", err)
	}
	return current, nil
}

// CompleteClaim deletes only the exact generation and lease token observed by
// the worker. If enqueue advanced generation during the claim, the newer work
// is retained and the old lease is released without changing its due time.
func (s *Store) CompleteClaim(ctx context.Context, claim Job) (bool, error) {
	if err := validateClaim(claim); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `
DELETE FROM jobs
WHERE id = ? AND type = ? AND generation = ? AND locked_at = ?`, claim.ID, ReconcileRepositoryEnforcement, claim.Generation, formatTime(*claim.LockedAt))
	if err != nil {
		return false, fmt.Errorf("complete repository reconciliation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("complete repository reconciliation rows: %w", err)
	}
	if affected == 0 {
		if err := s.releaseSupersededClaim(ctx, claim); err != nil {
			return false, err
		}
	}
	return affected > 0, nil
}

func (s *Store) RescheduleClaim(ctx context.Context, claim Job, category string) (bool, error) {
	if err := validateClaim(claim); err != nil {
		return false, err
	}
	if !domain.ValidEnforcementFailureReason(category) {
		return false, errors.New("reconciliation failure category is invalid")
	}
	nextRun := s.now().UTC().Add(RetryDelay(claim.Attempts))
	result, err := s.db.ExecContext(ctx, `
UPDATE jobs
SET locked_at = NULL, run_at = ?, last_error = ?
WHERE id = ? AND type = ? AND generation = ? AND locked_at = ?`, formatTime(nextRun), category, claim.ID, ReconcileRepositoryEnforcement, claim.Generation, formatTime(*claim.LockedAt))
	if err != nil {
		return false, fmt.Errorf("reschedule repository reconciliation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("reschedule repository reconciliation rows: %w", err)
	}
	if affected == 0 {
		if err := s.releaseSupersededClaim(ctx, claim); err != nil {
			return false, err
		}
	}
	return affected > 0, nil
}

func (s *Store) releaseSupersededClaim(ctx context.Context, claim Job) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE jobs
SET locked_at = NULL
WHERE id = ? AND type = ? AND generation <> ? AND locked_at = ?`, claim.ID, ReconcileRepositoryEnforcement, claim.Generation, formatTime(*claim.LockedAt))
	if err != nil {
		return fmt.Errorf("release superseded repository reconciliation claim: %w", err)
	}
	return nil
}

func (s *Store) MakeDueNow(ctx context.Context, repositoryID int64) (Job, error) {
	if s == nil || s.db == nil {
		return Job{}, errors.New("job store has no database")
	}
	if repositoryID <= 0 {
		return Job{}, errors.New("reconciliation repository is required")
	}
	now := s.now().UTC()
	result, err := s.db.ExecContext(ctx, `
UPDATE jobs
SET generation = generation + 1, run_at = ?
WHERE type = ? AND repository_id = ?
  AND (locked_at IS NULL OR locked_at < ?)`, formatTime(now), ReconcileRepositoryEnforcement, repositoryID, formatTime(now.Add(-ReconciliationLease)))
	if err != nil {
		return Job{}, fmt.Errorf("make repository reconciliation due: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Job{}, fmt.Errorf("make repository reconciliation due rows: %w", err)
	}
	if affected > 0 {
		return s.GetReconciliation(ctx, repositoryID)
	}
	if _, err := s.GetReconciliation(ctx, repositoryID); err == nil {
		return Job{}, ErrReconciliationInProgress
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Job{}, err
	}
	return s.EnqueueReconciliation(ctx, repositoryID)
}

func (s *Store) RemoveReconciliation(ctx context.Context, repositoryID int64) error {
	if s == nil || s.db == nil {
		return errors.New("job store has no database")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM jobs WHERE type = ? AND repository_id = ?`, ReconcileRepositoryEnforcement, repositoryID); err != nil {
		return fmt.Errorf("remove repository reconciliation: %w", err)
	}
	return nil
}

func RetryDelay(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 15 * time.Second
	case 2:
		return 30 * time.Second
	case 3:
		return time.Minute
	case 4:
		return 2 * time.Minute
	case 5:
		return 4 * time.Minute
	case 6:
		return 8 * time.Minute
	default:
		return 15 * time.Minute
	}
}

const reconciliationSelect = `
SELECT id, repository_id, generation, run_at, locked_at, attempts, last_error
FROM jobs`

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (Job, error) {
	var job Job
	var repositoryID sql.NullInt64
	var lockedAt, lastError sql.NullString
	var runAt string
	if err := row.Scan(&job.ID, &repositoryID, &job.Generation, &runAt, &lockedAt, &job.Attempts, &lastError); err != nil {
		return Job{}, err
	}
	if repositoryID.Valid {
		job.RepositoryID = repositoryID.Int64
	}
	parsedRunAt, err := parseTime(runAt)
	if err != nil {
		return Job{}, fmt.Errorf("parse job run_at: %w", err)
	}
	job.RunAt = parsedRunAt
	if lockedAt.Valid {
		parsed, err := parseTime(lockedAt.String)
		if err != nil {
			return Job{}, fmt.Errorf("parse job locked_at: %w", err)
		}
		job.LockedAt = &parsed
	}
	if lastError.Valid {
		job.LastError = lastError.String
	}
	return job, nil
}

func validateClaim(claim Job) error {
	if claim.ID <= 0 || claim.RepositoryID <= 0 || claim.Generation <= 0 || claim.LockedAt == nil || claim.LockedAt.IsZero() || claim.Attempts <= 0 {
		return errors.New("reconciliation claim is invalid")
	}
	return nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(sqliteTimestampFormat)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(sqliteTimestampFormat, strings.TrimSpace(value))
	if err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
}

func timePointer(value time.Time) *time.Time { return &value }

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
