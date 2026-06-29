package setupcheck

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const setupCheckTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

type Store struct {
	db  *sql.DB
	now func() time.Time
}

type Check struct {
	ID           int64
	RepositoryID int64
	Branch       string
	Result       Result
	CheckedAt    time.Time
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) Record(ctx context.Context, repositoryID int64, branch string, results []Result) error {
	if s == nil || s.db == nil {
		return errors.New("setup check store has no database")
	}
	if err := validateRecordParams(repositoryID, results); err != nil {
		return err
	}
	if len(results) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin setup checks record: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := s.recordNoTx(ctx, tx, repositoryID, branch, results); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit setup checks record: %w", err)
	}
	committed = true
	return nil
}

func (s *Store) recordNoTx(ctx context.Context, tx *sql.Tx, repositoryID int64, branch string, results []Result) error {
	checkedAt := s.now().UTC().Format(setupCheckTimeFormat)
	var branchValue any
	branch = strings.TrimSpace(branch)
	if branch != "" {
		branchValue = branch
	}

	for _, result := range results {
		var remediation any
		if result.Remediation != "" {
			remediation = result.Remediation
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO setup_checks(repository_id, branch, name, status, description, remediation, checked_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, repositoryID, branchValue, result.Name, result.Status, result.Description, remediation, checkedAt)
		if err != nil {
			return fmt.Errorf("record setup check %q: %w", result.Name, err)
		}
	}
	return nil
}

func (s *Store) ListByRepository(ctx context.Context, repositoryID int64) ([]Check, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("setup check store has no database")
	}
	if repositoryID <= 0 {
		return nil, errors.New("setup check repository id is required")
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, branch, name, status, description, remediation, checked_at
FROM setup_checks
WHERE repository_id = ?
ORDER BY checked_at DESC, id DESC`, repositoryID)
	if err != nil {
		return nil, fmt.Errorf("list setup checks: %w", err)
	}
	defer rows.Close()

	checks := make([]Check, 0)
	for rows.Next() {
		check, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list setup checks rows: %w", err)
	}
	return checks, nil
}

func validateRecordParams(repositoryID int64, results []Result) error {
	if repositoryID <= 0 {
		return errors.New("setup check repository id is required")
	}
	for _, result := range results {
		if strings.TrimSpace(result.Name) == "" {
			return errors.New("setup check name is required")
		}
		if !validStatus(result.Status) {
			return fmt.Errorf("setup check %q has invalid status %q", result.Name, result.Status)
		}
		if strings.TrimSpace(result.Description) == "" {
			return fmt.Errorf("setup check %q description is required", result.Name)
		}
	}
	return nil
}

func validStatus(status Status) bool {
	switch status {
	case StatusOK, StatusWarning, StatusFailed:
		return true
	default:
		return false
	}
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCheck(row scanner) (Check, error) {
	var check Check
	var branch sql.NullString
	var remediation sql.NullString
	var checkedAt string
	if err := row.Scan(&check.ID, &check.RepositoryID, &branch, &check.Result.Name, &check.Result.Status, &check.Result.Description, &remediation, &checkedAt); err != nil {
		return Check{}, fmt.Errorf("scan setup check: %w", err)
	}
	if branch.Valid {
		check.Branch = branch.String
	}
	if remediation.Valid {
		check.Result.Remediation = remediation.String
	}
	parsedCheckedAt, err := time.Parse(setupCheckTimeFormat, checkedAt)
	if err != nil {
		return Check{}, fmt.Errorf("parse setup check checked_at: %w", err)
	}
	check.CheckedAt = parsedCheckedAt
	return check, nil
}
