// Package schedule persists recurring freeze schedules. In this slice a
// schedule is only its shell — name, branch, timezone, kind — and is always
// created paused; nothing in this package starts or lifts freezes.
package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/taua-almeida/thawguard/internal/domain"
)

const sqliteTimestampFormat = "2006-01-02T15:04:05.000000000Z"

// nameMaxLength bounds the operator-facing schedule name. The name is
// rendered inside the 255-rune forge status description, so a short bound
// keeps it readable there without clipping.
const nameMaxLength = 100

// reasonMaxLength matches the freeze reason bound so a schedule reason can
// flow into a materialized freeze row without re-validation.
const reasonMaxLength = 500

// ErrNotFound reports a schedule id with no row; web handlers map it to 404.
var ErrNotFound = errors.New("schedule not found")

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validation ValidationError
	return errors.As(err, &validation)
}

// CreateParams carries the schedule shell. Schedules are always created
// paused; there is no Active parameter on purpose.
type CreateParams struct {
	RepositoryID    int64
	Branch          string
	Name            string
	Kind            domain.ScheduleKind
	Timezone        string
	Reason          string
	CreatedByUserID *int64
	CreatedByKind   string
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

func (s *Store) Create(ctx context.Context, params CreateParams) (domain.Schedule, error) {
	if s == nil || s.db == nil {
		return domain.Schedule{}, errors.New("schedule store has no database")
	}

	params = normalizeCreateParams(params)
	if err := validateCreateParams(params); err != nil {
		return domain.Schedule{}, err
	}
	if err := s.requireEnforcementActiveRepository(ctx, params.RepositoryID); err != nil {
		return domain.Schedule{}, err
	}
	if err := s.requireManagedBranch(ctx, params.RepositoryID, params.Branch); err != nil {
		return domain.Schedule{}, err
	}

	nowText := s.now().UTC().Format(sqliteTimestampFormat)
	var createdBy any
	if params.CreatedByUserID != nil {
		createdBy = *params.CreatedByUserID
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO schedules(repository_id, branch, name, kind, timezone, reason, active, created_by, created_by_kind, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		params.RepositoryID, params.Branch, params.Name, string(params.Kind), params.Timezone, params.Reason, createdBy, params.CreatedByKind, nowText, nowText)
	if err != nil {
		if isDuplicateScheduleNameError(err) {
			return domain.Schedule{}, ValidationError{Message: "a schedule with this name already exists for this branch"}
		}
		return domain.Schedule{}, fmt.Errorf("create schedule: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("created schedule id: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *Store) Get(ctx context.Context, id int64) (domain.Schedule, error) {
	if s == nil || s.db == nil {
		return domain.Schedule{}, errors.New("schedule store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, branch, name, kind, timezone, reason, active, created_by, created_by_kind, created_at, updated_at
FROM schedules WHERE id = ?`, id)
	schedule, err := scanSchedule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Schedule{}, ErrNotFound
	}
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("load schedule: %w", err)
	}
	return schedule, nil
}

// List returns every schedule ordered for the overview card grid: repository,
// then branch, then name. Slice counts stay small enough that pagination is
// not worth its states yet.
func (s *Store) List(ctx context.Context) ([]domain.Schedule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, name, kind, timezone, reason, active, created_by, created_by_kind, created_at, updated_at
FROM schedules ORDER BY repository_id, branch, name`)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()
	schedules := make([]domain.Schedule, 0)
	for rows.Next() {
		schedule, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}
		schedules = append(schedules, schedule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schedules: %w", err)
	}
	return schedules, nil
}

// Delete hard-deletes a schedule and returns the deleted row so the caller
// can audit what was removed. Hard delete is safe because a live freeze row
// keeps its own schedule_name snapshot once materialization exists.
func (s *Store) Delete(ctx context.Context, id int64) (domain.Schedule, error) {
	if s == nil || s.db == nil {
		return domain.Schedule{}, errors.New("schedule store has no database")
	}
	schedule, err := s.Get(ctx, id)
	if err != nil {
		return domain.Schedule{}, err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("delete schedule: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("deleted schedule rows: %w", err)
	}
	if affected == 0 {
		return domain.Schedule{}, ErrNotFound
	}
	return schedule, nil
}

// Timezones returns the IANA zone names offered by the timezone select, UTC
// first. The returned slice is a copy the caller may reorder.
func Timezones() []string {
	zones := make([]string, len(timezoneNames))
	copy(zones, timezoneNames)
	return zones
}

// ValidTimezone reports whether name resolves as an explicit IANA zone.
// "Local" is rejected: it silently means "wherever this server happens to
// run", which is exactly the ambiguity a persisted zone exists to remove.
func ValidTimezone(name string) bool {
	if name == "" || name == "Local" {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

func isDuplicateScheduleNameError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: schedules.repository_id, schedules.branch, schedules.name")
}

func (s *Store) requireEnforcementActiveRepository(ctx context.Context, repositoryID int64) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE id = ? AND active = 1 AND enforcement_state = ?`, repositoryID, domain.EnforcementActive).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: domain.EnforcementNotActiveMessage}
	}
	if err != nil {
		return fmt.Errorf("check schedule repository enforcement: %w", err)
	}
	return nil
}

func (s *Store) requireManagedBranch(ctx context.Context, repositoryID int64, branch string) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repository_branches WHERE repository_id = ? AND name = ?`, repositoryID, branch).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: domain.BranchNotManagedMessage}
	}
	if err != nil {
		return fmt.Errorf("check schedule managed branch: %w", err)
	}
	return nil
}

func normalizeCreateParams(params CreateParams) CreateParams {
	params.Branch = strings.TrimSpace(params.Branch)
	params.Name = strings.TrimSpace(params.Name)
	params.Timezone = strings.TrimSpace(params.Timezone)
	params.Reason = strings.TrimSpace(params.Reason)
	return params
}

func validateCreateParams(params CreateParams) error {
	missing := make([]string, 0, 4)
	if params.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if params.Branch == "" {
		missing = append(missing, "branch")
	}
	if params.Name == "" {
		missing = append(missing, "name")
	}
	if params.Timezone == "" {
		missing = append(missing, "timezone")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return ValidationError{Message: fmt.Sprintf("missing required fields: %s", strings.Join(missing, ", "))}
	}
	if !params.Kind.Valid() {
		return ValidationError{Message: "schedule kind must be weekly or dated"}
	}
	if utf8.RuneCountInString(params.Name) > nameMaxLength {
		return ValidationError{Message: "schedule name must be 100 characters or fewer"}
	}
	if containsControlCharacters(params.Name) {
		return ValidationError{Message: "schedule name contains unsupported control characters"}
	}
	if !ValidTimezone(params.Timezone) {
		return ValidationError{Message: "timezone must be a valid IANA timezone name"}
	}
	if len(params.Reason) > reasonMaxLength {
		return ValidationError{Message: "freeze reason must be 500 characters or fewer"}
	}
	if containsControlCharacters(params.Reason) {
		return ValidationError{Message: "freeze reason contains unsupported control characters"}
	}
	return nil
}

func containsControlCharacters(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSchedule(row scanner) (domain.Schedule, error) {
	var schedule domain.Schedule
	var kind string
	var active int64
	var createdBy sql.NullInt64
	var createdAt, updatedAt string
	if err := row.Scan(&schedule.ID, &schedule.RepositoryID, &schedule.Branch, &schedule.Name, &kind, &schedule.Timezone, &schedule.Reason, &active, &createdBy, &schedule.CreatedByKind, &createdAt, &updatedAt); err != nil {
		return domain.Schedule{}, err
	}
	schedule.Kind = domain.ScheduleKind(kind)
	schedule.Active = active != 0
	if createdBy.Valid {
		id := createdBy.Int64
		schedule.CreatedByUserID = &id
	}
	var err error
	if schedule.CreatedAt, err = time.Parse(sqliteTimestampFormat, createdAt); err != nil {
		return domain.Schedule{}, fmt.Errorf("parse schedule created_at: %w", err)
	}
	if schedule.UpdatedAt, err = time.Parse(sqliteTimestampFormat, updatedAt); err != nil {
		return domain.Schedule{}, fmt.Errorf("parse schedule updated_at: %w", err)
	}
	return schedule, nil
}
