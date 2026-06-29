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
	CreatedByUserID *int64
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
	if err := validateCreateParams(params); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.requireRepository(ctx, params.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.rejectDuplicateActive(ctx, params.RepositoryID, params.Branch); err != nil {
		return domain.BranchFreeze{}, err
	}

	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	var createdBy any
	if params.CreatedByUserID != nil {
		createdBy = *params.CreatedByUserID
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO branch_freezes(repository_id, branch, status, reason, starts_at, ends_at, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, params.RepositoryID, params.Branch, domain.BranchFreezeStatusActive, params.Reason, nowText, nil, createdBy, nowText, nowText)
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

func (s *Store) Get(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, branch, status, reason, starts_at, ends_at, created_at, updated_at
FROM branch_freezes
WHERE id = ?`, id)
	return scanBranchFreeze(row)
}

func (s *Store) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, status, reason, starts_at, ends_at, created_at, updated_at
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

func (s *Store) requireRepository(ctx context.Context, repositoryID int64) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE id = ? AND active = 1`, repositoryID).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: "repository not found"}
	}
	if err != nil {
		return fmt.Errorf("check freeze repository: %w", err)
	}
	return nil
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
	return params
}

func validateCreateParams(params CreateParams) error {
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
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanBranchFreeze(row scanner) (domain.BranchFreeze, error) {
	var freeze domain.BranchFreeze
	var startsAt, endsAt sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&freeze.ID, &freeze.RepositoryID, &freeze.Branch, &freeze.Status, &freeze.Reason, &startsAt, &endsAt, &createdAt, &updatedAt); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("scan branch freeze: %w", err)
	}
	freeze.Active = freeze.Status == domain.BranchFreezeStatusActive

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
	return freeze, nil
}
