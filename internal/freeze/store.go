package freeze

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

const sqliteTimestampFormat = "2006-01-02T15:04:05.000000000Z"
const scheduledFreezeReasonMaxLength = 500

type database interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type Store struct {
	db  database
	now func() time.Time
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

type CreateParams struct {
	RepositoryID    int64
	Branch          string
	Reason          string
	PlannedEndsAt   *time.Time
	CreatedByUserID *int64
	CreatedByKind   string
}

type ScheduleParams struct {
	RepositoryID    int64
	Branch          string
	Reason          string
	StartsAt        time.Time
	PlannedEndsAt   *time.Time
	CreatedByUserID *int64
	CreatedByKind   string
}

type EditScheduleParams struct {
	ID            int64
	Reason        string
	StartsAt      time.Time
	PlannedEndsAt *time.Time
}

type CloseParams struct {
	ID     int64
	Status domain.BranchFreezeStatus
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

func (s *Store) CreateActive(ctx context.Context, params CreateParams) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}

	params = normalizeCreateParams(params)
	now := s.now().UTC()
	if err := validateCreateParams(params, now); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.requireEnforcementActiveRepository(ctx, params.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.rejectDuplicateActive(ctx, params.RepositoryID, params.Branch); err != nil {
		return domain.BranchFreeze{}, err
	}

	nowText := now.Format(sqliteTimestampFormat)
	var plannedEndsAt any
	if params.PlannedEndsAt != nil {
		plannedEndsAt = params.PlannedEndsAt.UTC().Format(sqliteTimestampFormat)
	}
	var createdBy any
	if params.CreatedByUserID != nil {
		createdBy = *params.CreatedByUserID
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO branch_freezes(repository_id, branch, status, reason, starts_at, ends_at, scheduled, planned_ends_at, created_by, created_by_kind, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, params.RepositoryID, params.Branch, domain.BranchFreezeStatusActive, params.Reason, nowText, nil, 0, plannedEndsAt, createdBy, params.CreatedByKind, nowText, nowText)
	if err != nil {
		return domain.BranchFreeze{}, createActiveFreezeError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("created branch freeze id: %w", err)
	}
	return s.Get(ctx, id)
}

func createActiveFreezeError(err error) error {
	if isDuplicateActiveFreezeError(err) {
		return ValidationError{Message: "branch is already frozen"}
	}
	return fmt.Errorf("create branch freeze: %w", err)
}

func isDuplicateActiveFreezeError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "idx_branch_freezes_one_active") ||
		strings.Contains(message, "UNIQUE constraint failed: branch_freezes.repository_id, branch_freezes.branch")
}

func (s *Store) CreateScheduled(ctx context.Context, params ScheduleParams) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}

	params = normalizeScheduleParams(params)
	if err := validateScheduleParams(params, s.now().UTC()); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.requireEnforcementActiveRepository(ctx, params.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	now := s.now().UTC()
	nowText := now.Format(sqliteTimestampFormat)
	startsAtText := params.StartsAt.UTC().Format(sqliteTimestampFormat)
	var plannedEndsAt any
	if params.PlannedEndsAt != nil {
		plannedEndsAt = params.PlannedEndsAt.UTC().Format(sqliteTimestampFormat)
	}
	var createdBy any
	if params.CreatedByUserID != nil {
		createdBy = *params.CreatedByUserID
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO branch_freezes(repository_id, branch, status, reason, starts_at, ends_at, scheduled, planned_ends_at, created_by, created_by_kind, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, params.RepositoryID, params.Branch, domain.BranchFreezeStatusScheduled, params.Reason, startsAtText, nil, 1, plannedEndsAt, createdBy, params.CreatedByKind, nowText, nowText)
	if err != nil {
		return domain.BranchFreeze{}, createScheduledFreezeError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("created scheduled freeze id: %w", err)
	}
	return s.Get(ctx, id)
}

func createScheduledFreezeError(err error) error {
	return fmt.Errorf("create scheduled freeze: %w", err)
}

func (s *Store) Get(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
WHERE id = ?`, id)
	return scanBranchFreeze(row)
}

func (s *Store) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
WHERE status = ?
ORDER BY created_at DESC, id DESC`, domain.BranchFreezeStatusActive)
	if err != nil {
		return nil, fmt.Errorf("list active branch freezes: %w", err)
	}
	defer rows.Close()

	freezes := make([]domain.BranchFreeze, 0)
	for rows.Next() {
		freeze, err := scanBranchFreeze(rows)
		if err != nil {
			return nil, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active branch freezes rows: %w", err)
	}
	return freezes, nil
}

func (s *Store) ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
WHERE scheduled = 1
ORDER BY
  CASE status WHEN 'scheduled' THEN 0 WHEN 'active' THEN 1 WHEN 'ended' THEN 2 WHEN 'cancelled' THEN 3 ELSE 4 END,
  starts_at ASC,
  id ASC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scheduled branch freezes: %w", err)
	}
	defer rows.Close()

	freezes := make([]domain.BranchFreeze, 0)
	for rows.Next() {
		freeze, err := scanBranchFreeze(rows)
		if err != nil {
			return nil, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list scheduled branch freezes rows: %w", err)
	}
	return freezes, nil
}

func (s *Store) ListScheduledPage(ctx context.Context, status domain.BranchFreezeStatus, offset, limit int) ([]domain.BranchFreeze, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("freeze store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where := "WHERE scheduled = 1"
	countArgs := []any{}
	if status != "" {
		where += " AND status = ?"
		countArgs = append(countArgs, status)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM branch_freezes "+where, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scheduled branch freezes: %w", err)
	}

	args := append(append([]any{}, countArgs...), limit, offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
`+where+`
ORDER BY
  CASE status WHEN 'scheduled' THEN 0 WHEN 'active' THEN 1 WHEN 'ended' THEN 2 WHEN 'cancelled' THEN 3 ELSE 4 END,
  starts_at ASC,
  id ASC
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scheduled branch freezes page: %w", err)
	}
	defer rows.Close()

	freezes := make([]domain.BranchFreeze, 0)
	for rows.Next() {
		freeze, err := scanBranchFreeze(rows)
		if err != nil {
			return nil, 0, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list scheduled branch freezes page rows: %w", err)
	}
	return freezes, total, nil
}

func (s *Store) ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze store has no database")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
WHERE scheduled = 1 AND status = ? AND starts_at <= ?
ORDER BY starts_at ASC, id ASC
LIMIT ?`, domain.BranchFreezeStatusScheduled, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due scheduled branch freezes: %w", err)
	}
	defer rows.Close()

	freezes := make([]domain.BranchFreeze, 0)
	for rows.Next() {
		freeze, err := scanBranchFreeze(rows)
		if err != nil {
			return nil, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list due scheduled branch freezes rows: %w", err)
	}
	return freezes, nil
}

func (s *Store) ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze store has no database")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
WHERE status = ? AND planned_ends_at IS NOT NULL AND planned_ends_at <= ?
ORDER BY planned_ends_at ASC, id ASC
LIMIT ?`, domain.BranchFreezeStatusActive, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due planned unfreezes: %w", err)
	}
	defer rows.Close()

	freezes := make([]domain.BranchFreeze, 0)
	for rows.Next() {
		freeze, err := scanBranchFreeze(rows)
		if err != nil {
			return nil, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list due planned unfreezes rows: %w", err)
	}
	return freezes, nil
}

func (s *Store) ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze store has no database")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, scheduled, needs_recompute, reason, starts_at, ends_at, planned_ends_at, created_by, created_by_kind, created_at, updated_at
FROM branch_freezes
WHERE needs_recompute = 1
ORDER BY updated_at ASC, id ASC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list freezes needing recompute: %w", err)
	}
	defer rows.Close()

	freezes := make([]domain.BranchFreeze, 0)
	for rows.Next() {
		freeze, err := scanBranchFreeze(rows)
		if err != nil {
			return nil, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list freezes needing recompute rows: %w", err)
	}
	return freezes, nil
}

func (s *Store) MarkRecomputed(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	if id <= 0 {
		return domain.BranchFreeze{}, ValidationError{Message: "freeze is required"}
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET needs_recompute = 0, updated_at = ?
WHERE id = ? AND needs_recompute = 1`, now, id)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("mark freeze recomputed: %w", err)
	}
	if err := requireAffectedFreeze(result, "freeze does not need recompute"); err != nil {
		return domain.BranchFreeze{}, err
	}
	return s.Get(ctx, id)
}

func (s *Store) MarkRepositoryRecomputed(ctx context.Context, repositoryID int64) error {
	if s == nil || s.db == nil {
		return errors.New("freeze store has no database")
	}
	if repositoryID <= 0 {
		return ValidationError{Message: "repository is required"}
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	if _, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET needs_recompute = 0, updated_at = ?
WHERE repository_id = ? AND needs_recompute = 1`, now, repositoryID); err != nil {
		return fmt.Errorf("mark repository freezes recomputed: %w", err)
	}
	return nil
}

func (s *Store) End(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	return s.closeActive(ctx, CloseParams{ID: id, Status: domain.BranchFreezeStatusEnded})
}

func (s *Store) Cancel(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	return s.closeActive(ctx, CloseParams{ID: id, Status: domain.BranchFreezeStatusCancelled})
}

func (s *Store) CancelScheduled(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	if id <= 0 {
		return domain.BranchFreeze{}, ValidationError{Message: "freeze is required"}
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET status = ?, ends_at = ?, updated_at = ?
WHERE id = ? AND scheduled = 1 AND status = ?`, domain.BranchFreezeStatusCancelled, now, now, id, domain.BranchFreezeStatusScheduled)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("cancel scheduled freeze: %w", err)
	}
	if err := requireAffectedFreeze(result, "scheduled freeze is not pending"); err != nil {
		return domain.BranchFreeze{}, err
	}
	return s.Get(ctx, id)
}

func (s *Store) EditScheduled(ctx context.Context, params EditScheduleParams) (domain.BranchFreeze, error) {
	return s.editScheduled(ctx, params, nil)
}

func (s *Store) editScheduled(ctx context.Context, params EditScheduleParams, expectedUpdatedAt *time.Time) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	params = normalizeEditScheduleParams(params)
	now := s.now().UTC()
	if expectedUpdatedAt != nil && !now.After(expectedUpdatedAt.UTC()) {
		now = expectedUpdatedAt.UTC().Add(time.Nanosecond)
	}
	if err := validateEditScheduleParams(params, now); err != nil {
		return domain.BranchFreeze{}, err
	}
	var plannedEndsAt any
	if params.PlannedEndsAt != nil {
		plannedEndsAt = params.PlannedEndsAt.Format(sqliteTimestampFormat)
	}
	var expectedUpdatedAtText any
	if expectedUpdatedAt != nil {
		expectedUpdatedAtText = expectedUpdatedAt.UTC().Format(sqliteTimestampFormat)
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET reason = ?, starts_at = ?, planned_ends_at = ?, updated_at = ?
WHERE id = ? AND scheduled = 1 AND status = ? AND starts_at > ?
  AND (? IS NULL OR updated_at = ?)`,
		params.Reason,
		params.StartsAt.Format(sqliteTimestampFormat),
		plannedEndsAt,
		now.Format(sqliteTimestampFormat),
		params.ID,
		domain.BranchFreezeStatusScheduled,
		now.Format(sqliteTimestampFormat),
		expectedUpdatedAtText,
		expectedUpdatedAtText,
	)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("edit scheduled freeze: %w", err)
	}
	if err := requireAffectedFreeze(result, "scheduled freeze is no longer pending"); err != nil {
		return domain.BranchFreeze{}, err
	}
	return s.Get(ctx, params.ID)
}

func (s *Store) ActivateScheduled(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	if id <= 0 {
		return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is required"}
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET status = ?, needs_recompute = 1, updated_at = ?
WHERE id = ? AND scheduled = 1 AND status = ? AND starts_at <= ?
  AND EXISTS (
    SELECT 1 FROM repositories
    WHERE repositories.id = branch_freezes.repository_id
      AND repositories.active = 1
      AND repositories.enforcement_state = ?
  )`, domain.BranchFreezeStatusActive, now, id, domain.BranchFreezeStatusScheduled, now, domain.EnforcementActive)
	if err != nil {
		return domain.BranchFreeze{}, createActiveFreezeError(err)
	}
	if err := requireAffectedFreeze(result, "scheduled freeze is not due"); err != nil {
		if activeErr := s.requireFreezeRepositoryEnforcement(ctx, id); activeErr != nil {
			return domain.BranchFreeze{}, activeErr
		}
		return domain.BranchFreeze{}, err
	}
	return s.Get(ctx, id)
}

func (s *Store) StartScheduledNow(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	if id <= 0 {
		return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is required"}
	}
	now := s.now().UTC()
	nowText := now.Format(sqliteTimestampFormat)
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET status = ?, starts_at = ?, needs_recompute = 1, updated_at = ?
WHERE id = ? AND scheduled = 1 AND status = ? AND starts_at > ?
  AND (planned_ends_at IS NULL OR planned_ends_at > ?)
  AND EXISTS (
    SELECT 1 FROM repositories
    WHERE repositories.id = branch_freezes.repository_id
      AND repositories.active = 1
      AND repositories.enforcement_state = ?
  )`,
		domain.BranchFreezeStatusActive,
		nowText,
		nowText,
		id,
		domain.BranchFreezeStatusScheduled,
		nowText,
		nowText,
		domain.EnforcementActive,
	)
	if err != nil {
		return domain.BranchFreeze{}, createActiveFreezeError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("start scheduled freeze now rows affected: %w", err)
	}
	if affected == 0 {
		if activeErr := s.requireFreezeRepositoryEnforcement(ctx, id); activeErr != nil {
			return domain.BranchFreeze{}, activeErr
		}
		target, err := s.Get(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is no longer pending"}
		}
		if err != nil {
			return domain.BranchFreeze{}, err
		}
		if !target.Scheduled || target.Status != domain.BranchFreezeStatusScheduled {
			return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is no longer pending"}
		}
		if target.StartsAt == nil || !target.StartsAt.After(now) {
			return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze has reached its start time"}
		}
		if target.PlannedEndsAt != nil && !target.PlannedEndsAt.After(now) {
			return domain.BranchFreeze{}, ValidationError{Message: "planned unfreeze is no longer in the future; edit the schedule before starting it now"}
		}
		return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is no longer pending"}
	}
	return s.Get(ctx, id)
}

func (s *Store) ExecutePlannedUnfreeze(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	if id <= 0 {
		return domain.BranchFreeze{}, ValidationError{Message: "freeze is required"}
	}
	now := s.now().UTC().Format(sqliteTimestampFormat)
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET status = ?, ends_at = ?, needs_recompute = 1, updated_at = ?
WHERE id = ? AND status = ? AND planned_ends_at IS NOT NULL AND planned_ends_at <= ?`, domain.BranchFreezeStatusEnded, now, now, id, domain.BranchFreezeStatusActive, now)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("execute planned unfreeze: %w", err)
	}
	if err := requireAffectedFreeze(result, "freeze is not due for planned unfreeze"); err != nil {
		return domain.BranchFreeze{}, err
	}
	return s.Get(ctx, id)
}

func requireAffectedFreeze(result sql.Result, message string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("freeze rows affected: %w", err)
	}
	if affected == 0 {
		return ValidationError{Message: message}
	}
	return nil
}

func (s *Store) closeActive(ctx context.Context, params CloseParams) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	if err := validateCloseParams(params); err != nil {
		return domain.BranchFreeze{}, err
	}

	now := s.now().UTC().Format(sqliteTimestampFormat)
	result, err := s.db.ExecContext(ctx, `
UPDATE branch_freezes
SET status = ?, ends_at = ?, needs_recompute = 1, updated_at = ?
WHERE id = ? AND status = ?`, params.Status, now, now, params.ID, domain.BranchFreezeStatusActive)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("close branch freeze: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("close branch freeze rows affected: %w", err)
	}
	if affected == 0 {
		existing, getErr := s.Get(ctx, params.ID)
		if errors.Is(getErr, sql.ErrNoRows) {
			return domain.BranchFreeze{}, ValidationError{Message: "active freeze not found"}
		}
		if getErr != nil {
			return domain.BranchFreeze{}, getErr
		}
		if existing.Status != domain.BranchFreezeStatusActive {
			return domain.BranchFreeze{}, ValidationError{Message: "freeze is not active"}
		}
		return domain.BranchFreeze{}, ValidationError{Message: "freeze is not active"}
	}
	return s.Get(ctx, params.ID)
}

func (s *Store) requireEnforcementActiveRepository(ctx context.Context, repositoryID int64) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE id = ? AND active = 1 AND enforcement_state = ?`, repositoryID, domain.EnforcementActive).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: domain.EnforcementNotActiveMessage}
	}
	if err != nil {
		return fmt.Errorf("check freeze repository enforcement: %w", err)
	}
	return nil
}

func (s *Store) requireFreezeRepositoryEnforcement(ctx context.Context, freezeID int64) error {
	var repositoryID int64
	err := s.db.QueryRowContext(ctx, `SELECT repository_id FROM branch_freezes WHERE id = ?`, freezeID).Scan(&repositoryID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load freeze repository for enforcement check: %w", err)
	}
	return s.requireEnforcementActiveRepository(ctx, repositoryID)
}

func (s *Store) HasActiveForRepository(ctx context.Context, repositoryID int64) (bool, error) {
	return s.hasStatusForRepository(ctx, repositoryID, domain.BranchFreezeStatusActive)
}

func (s *Store) HasScheduledForRepository(ctx context.Context, repositoryID int64) (bool, error) {
	return s.hasStatusForRepository(ctx, repositoryID, domain.BranchFreezeStatusScheduled)
}

func (s *Store) hasStatusForRepository(ctx context.Context, repositoryID int64, status domain.BranchFreezeStatus) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("freeze store has no database")
	}
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM branch_freezes WHERE repository_id = ? AND status = ?)`, repositoryID, status).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check repository freeze blockers: %w", err)
	}
	return exists == 1, nil
}

func (s *Store) rejectDuplicateActive(ctx context.Context, repositoryID int64, branch string) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `
SELECT id FROM branch_freezes
WHERE repository_id = ? AND branch = ? AND status = ?
LIMIT 1`, repositoryID, branch, domain.BranchFreezeStatusActive).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check duplicate active freeze: %w", err)
	}
	return ValidationError{Message: "branch is already frozen"}
}

func normalizeCreateParams(params CreateParams) CreateParams {
	params.Branch = strings.TrimSpace(params.Branch)
	params.Reason = strings.TrimSpace(params.Reason)
	if params.PlannedEndsAt != nil {
		plannedEndsAt := params.PlannedEndsAt.UTC()
		params.PlannedEndsAt = &plannedEndsAt
	}
	return params
}

func validateCreateParams(params CreateParams, now time.Time) error {
	var missing []string
	if params.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if params.Branch == "" {
		missing = append(missing, "branch")
	}
	if params.Reason == "" {
		missing = append(missing, "reason")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required freeze fields: %s", strings.Join(missing, ", "))}
	}
	if params.PlannedEndsAt != nil && !params.PlannedEndsAt.After(now) {
		return ValidationError{Message: "planned unfreeze time must be in the future"}
	}
	return nil
}

func normalizeScheduleParams(params ScheduleParams) ScheduleParams {
	params.Branch = strings.TrimSpace(params.Branch)
	params.Reason = strings.TrimSpace(params.Reason)
	params.StartsAt = params.StartsAt.UTC()
	if params.PlannedEndsAt != nil {
		plannedEndsAt := params.PlannedEndsAt.UTC()
		params.PlannedEndsAt = &plannedEndsAt
	}
	return params
}

func normalizeEditScheduleParams(params EditScheduleParams) EditScheduleParams {
	params.Reason = strings.TrimSpace(params.Reason)
	params.StartsAt = params.StartsAt.UTC()
	if params.PlannedEndsAt != nil {
		plannedEndsAt := params.PlannedEndsAt.UTC()
		params.PlannedEndsAt = &plannedEndsAt
	}
	return params
}

func validateScheduleParams(params ScheduleParams, now time.Time) error {
	var missing []string
	if params.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if params.Branch == "" {
		missing = append(missing, "branch")
	}
	if params.Reason == "" {
		missing = append(missing, "reason")
	}
	if params.StartsAt.IsZero() {
		missing = append(missing, "start time")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required scheduled freeze fields: %s", strings.Join(missing, ", "))}
	}
	if err := validateScheduledFreezeReason(params.Reason); err != nil {
		return err
	}
	if !params.StartsAt.After(now) {
		return ValidationError{Message: "scheduled freeze start time must be in the future"}
	}
	if params.PlannedEndsAt != nil && !params.PlannedEndsAt.After(params.StartsAt) {
		return ValidationError{Message: "planned unfreeze time must be after the scheduled start"}
	}
	return nil
}

func validateEditScheduleParams(params EditScheduleParams, now time.Time) error {
	if params.ID <= 0 {
		return ValidationError{Message: "scheduled freeze is required"}
	}
	if params.Reason == "" {
		return ValidationError{Message: "scheduled freeze reason is required"}
	}
	if params.StartsAt.IsZero() {
		return ValidationError{Message: "scheduled freeze start time is required"}
	}
	if err := validateScheduledFreezeReason(params.Reason); err != nil {
		return err
	}
	if !params.StartsAt.After(now) {
		return ValidationError{Message: "scheduled freeze start time must be in the future"}
	}
	if params.PlannedEndsAt != nil && !params.PlannedEndsAt.After(params.StartsAt) {
		return ValidationError{Message: "planned unfreeze time must be after the scheduled start"}
	}
	return nil
}

func validateScheduledFreezeReason(reason string) error {
	if len(reason) > scheduledFreezeReasonMaxLength {
		return ValidationError{Message: "scheduled freeze reason must be 500 characters or fewer"}
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return ValidationError{Message: "scheduled freeze reason contains unsupported control characters"}
		}
	}
	return nil
}

func validateCloseParams(params CloseParams) error {
	if params.ID <= 0 {
		return ValidationError{Message: "active freeze is required"}
	}
	if params.Status != domain.BranchFreezeStatusEnded && params.Status != domain.BranchFreezeStatusCancelled {
		return ValidationError{Message: "freeze close status is invalid"}
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanBranchFreeze(row scanner) (domain.BranchFreeze, error) {
	var freeze domain.BranchFreeze
	var startsAt, endsAt, plannedEndsAt sql.NullString
	var scheduled, needsRecompute int
	var createdBy sql.NullInt64
	var createdAt, updatedAt string
	if err := row.Scan(&freeze.ID, &freeze.RepositoryID, &freeze.Branch, &freeze.Status, &scheduled, &needsRecompute, &freeze.Reason, &startsAt, &endsAt, &plannedEndsAt, &createdBy, &freeze.CreatedByKind, &createdAt, &updatedAt); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("scan branch freeze: %w", err)
	}
	freeze.Active = freeze.Status == domain.BranchFreezeStatusActive
	freeze.Scheduled = scheduled == 1
	freeze.NeedsRecompute = needsRecompute == 1
	if createdBy.Valid {
		freeze.CreatedByUserID = &createdBy.Int64
	}

	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("parse branch freeze created_at: %w", err)
	}
	parsedUpdatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("parse branch freeze updated_at: %w", err)
	}
	freeze.CreatedAt = parsedCreatedAt
	freeze.UpdatedAt = parsedUpdatedAt

	if startsAt.Valid {
		parsedStartsAt, err := time.Parse(time.RFC3339Nano, startsAt.String)
		if err != nil {
			return domain.BranchFreeze{}, fmt.Errorf("parse branch freeze starts_at: %w", err)
		}
		freeze.StartsAt = &parsedStartsAt
	}
	if endsAt.Valid {
		parsedEndsAt, err := time.Parse(time.RFC3339Nano, endsAt.String)
		if err != nil {
			return domain.BranchFreeze{}, fmt.Errorf("parse branch freeze ends_at: %w", err)
		}
		freeze.EndsAt = &parsedEndsAt
	}
	if plannedEndsAt.Valid {
		parsedPlannedEndsAt, err := time.Parse(time.RFC3339Nano, plannedEndsAt.String)
		if err != nil {
			return domain.BranchFreeze{}, fmt.Errorf("parse branch freeze planned_ends_at: %w", err)
		}
		freeze.PlannedEndsAt = &parsedPlannedEndsAt
	}
	return freeze, nil
}
