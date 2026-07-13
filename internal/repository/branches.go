package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

// ListBranches returns the managed branches for one repository in
// deterministic name order.
func (s *Store) ListBranches(ctx context.Context, repositoryID int64) ([]domain.RepositoryBranch, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return nil, ValidationError{Message: "repository id is required"}
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, name, protected, setup_status, last_checked_at
FROM repository_branches
WHERE repository_id = ?
ORDER BY name`, repositoryID)
	if err != nil {
		return nil, fmt.Errorf("list repository branches: %w", err)
	}
	defer rows.Close()

	branches := make([]domain.RepositoryBranch, 0)
	for rows.Next() {
		branch, err := scanRepositoryBranch(rows)
		if err != nil {
			return nil, err
		}
		branches = append(branches, branch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list repository branches rows: %w", err)
	}
	return branches, nil
}

// BranchManaged reports whether one exact branch name is managed for the
// repository. Names are compared exactly and case-sensitively.
func (s *Store) BranchManaged(ctx context.Context, repositoryID int64, name string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("repository store has no database")
	}
	name = strings.TrimSpace(name)
	if repositoryID <= 0 || name == "" {
		return false, nil
	}
	var managed bool
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM repository_branches WHERE repository_id = ? AND name = ?)`, repositoryID, name).Scan(&managed); err != nil {
		return false, fmt.Errorf("check managed branch: %w", err)
	}
	return managed, nil
}

// AddBranch inserts one exact managed branch with unverified setup state.
// It is an invariant-free primitive: enforcement-scope locking and audit
// events live in repositorysetup.Service.AddBranch, which callers must use.
func (s *Store) AddBranch(ctx context.Context, repositoryID int64, name string) (domain.RepositoryBranch, error) {
	if s == nil || s.db == nil {
		return domain.RepositoryBranch{}, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return domain.RepositoryBranch{}, ValidationError{Message: "repository id is required"}
	}
	name = strings.TrimSpace(name)
	if err := validateBranchName(name); err != nil {
		return domain.RepositoryBranch{}, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO repository_branches(repository_id, name)
VALUES (?, ?)`, repositoryID, name)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: repository_branches") {
			return domain.RepositoryBranch{}, ValidationError{Message: "branch is already managed"}
		}
		return domain.RepositoryBranch{}, fmt.Errorf("add managed branch: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return domain.RepositoryBranch{}, fmt.Errorf("added managed branch id: %w", err)
	}
	return s.getBranch(ctx, id)
}

// RemoveBranch deletes one exact managed branch row. It is an invariant-free
// primitive: default-branch, blocking-freeze, and enforcement-scope guards
// live in repositorysetup.Service.RemoveBranch, which callers must use.
func (s *Store) RemoveBranch(ctx context.Context, repositoryID int64, name string) error {
	if s == nil || s.db == nil {
		return errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return ValidationError{Message: "repository id is required"}
	}
	name = strings.TrimSpace(name)
	result, err := s.db.ExecContext(ctx, `
DELETE FROM repository_branches
WHERE repository_id = ? AND name = ?`, repositoryID, name)
	if err != nil {
		return fmt.Errorf("remove managed branch: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove managed branch rows: %w", err)
	}
	if affected == 0 {
		return ValidationError{Message: "managed branch not found"}
	}
	return nil
}

func (s *Store) UpdateBranchReadiness(ctx context.Context, repositoryID int64, name string, protected bool, setupStatus string, checkedAt time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("repository store has no database")
	}
	if repositoryID <= 0 || strings.TrimSpace(name) == "" || checkedAt.IsZero() {
		return ValidationError{Message: "valid repository branch readiness fields are required"}
	}
	if setupStatus != "ok" && setupStatus != "unknown" {
		return ValidationError{Message: "repository branch setup status is invalid"}
	}
	protectedValue := 0
	if protected {
		protectedValue = 1
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE repository_branches
SET protected = ?, setup_status = ?, last_checked_at = ?
WHERE repository_id = ? AND name = ?`, protectedValue, setupStatus, checkedAt.UTC().Format(time.RFC3339Nano), repositoryID, strings.TrimSpace(name))
	if err != nil {
		return fmt.Errorf("update repository branch readiness: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update repository branch readiness rows: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// BranchHasBlockingFreeze reports whether the branch has an active freeze or a
// pending scheduled freeze. Ended and cancelled history never blocks removal.
func (s *Store) BranchHasBlockingFreeze(ctx context.Context, repositoryID int64, name string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("repository store has no database")
	}
	var blocked bool
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM branch_freezes WHERE repository_id = ? AND branch = ? AND status IN (?, ?))`, repositoryID, name, domain.BranchFreezeStatusActive, domain.BranchFreezeStatusScheduled).Scan(&blocked); err != nil {
		return false, fmt.Errorf("check managed branch freezes: %w", err)
	}
	return blocked, nil
}

func (s *Store) getBranch(ctx context.Context, id int64) (domain.RepositoryBranch, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, name, protected, setup_status, last_checked_at
FROM repository_branches
WHERE id = ?`, id)
	return scanRepositoryBranch(row)
}

func validateBranchName(name string) error {
	if name == "" {
		return ValidationError{Message: "branch name is required"}
	}
	if len(name) > 255 {
		return ValidationError{Message: "branch name is too long"}
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return ValidationError{Message: "branch name contains invalid characters"}
		}
	}
	return nil
}

func scanRepositoryBranch(row scanner) (domain.RepositoryBranch, error) {
	var branch domain.RepositoryBranch
	var protected int
	var lastCheckedAt sql.NullString
	if err := row.Scan(&branch.ID, &branch.RepositoryID, &branch.Name, &protected, &branch.SetupStatus, &lastCheckedAt); err != nil {
		return domain.RepositoryBranch{}, fmt.Errorf("scan repository branch: %w", err)
	}
	branch.Protected = protected != 0
	if lastCheckedAt.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, lastCheckedAt.String)
		if err != nil {
			return domain.RepositoryBranch{}, fmt.Errorf("parse repository branch last_checked_at: %w", err)
		}
		branch.LastCheckedAt = &parsed
	}
	return branch, nil
}
