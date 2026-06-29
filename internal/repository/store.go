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
	Forge         string
	BaseURL       string
	Owner         string
	Name          string
	DefaultBranch string
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

func (s *Store) Create(ctx context.Context, params CreateParams) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository store has no database")
	}

	params = normalizeCreateParams(params)
	if err := validateCreateParams(params); err != nil {
		return domain.Repository{}, err
	}

	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
INSERT INTO repositories(forge, base_url, owner, name, default_branch, active, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, 1, ?, ?)`, params.Forge, params.BaseURL, params.Owner, params.Name, params.DefaultBranch, nowText, nowText)
	if err != nil {
		return domain.Repository{}, createRepositoryError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return domain.Repository{}, fmt.Errorf("created repository id: %w", err)
	}
	return s.Get(ctx, id)
}

func createRepositoryError(err error) error {
	if isDuplicateRepositoryError(err) {
		return ValidationError{Message: "repository already exists"}
	}
	return fmt.Errorf("create repository: %w", err)
}

func isDuplicateRepositoryError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "UNIQUE constraint failed: repositories.forge, repositories.base_url, repositories.owner, repositories.name") ||
		strings.Contains(message, "constraint failed: UNIQUE constraint failed: repositories")
}

func (s *Store) Get(ctx context.Context, id int64) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, forge, base_url, owner, name, default_branch, active, created_at, updated_at
FROM repositories
WHERE id = ?`, id)
	return scanRepository(row)
}

func (s *Store) List(ctx context.Context) ([]domain.Repository, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("repository store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, forge, base_url, owner, name, default_branch, active, created_at, updated_at
FROM repositories
ORDER BY owner, name`)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()

	repositories := make([]domain.Repository, 0)
	for rows.Next() {
		repo, err := scanRepository(rows)
		if err != nil {
			return nil, err
		}
		repositories = append(repositories, repo)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list repositories rows: %w", err)
	}
	return repositories, nil
}

func normalizeCreateParams(params CreateParams) CreateParams {
	params.Forge = strings.ToLower(strings.TrimSpace(params.Forge))
	params.BaseURL = strings.TrimRight(strings.TrimSpace(params.BaseURL), "/")
	params.Owner = strings.TrimSpace(params.Owner)
	params.Name = strings.TrimSpace(params.Name)
	params.DefaultBranch = strings.TrimSpace(params.DefaultBranch)

	if params.Forge == "" {
		params.Forge = "forgejo"
	}
	if params.BaseURL == "" {
		params.BaseURL = "https://codeberg.org"
	}
	if params.DefaultBranch == "" {
		params.DefaultBranch = "main"
	}
	return params
}

func validateCreateParams(params CreateParams) error {
	var missing []string
	if params.Owner == "" {
		missing = append(missing, "owner")
	}
	if params.Name == "" {
		missing = append(missing, "name")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required repository fields: %s", strings.Join(missing, ", "))}
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRepository(row scanner) (domain.Repository, error) {
	var repo domain.Repository
	var active int
	var createdAt, updatedAt string
	if err := row.Scan(&repo.ID, &repo.Forge, &repo.BaseURL, &repo.Owner, &repo.Name, &repo.DefaultBranch, &active, &createdAt, &updatedAt); err != nil {
		return domain.Repository{}, fmt.Errorf("scan repository: %w", err)
	}
	repo.Active = active != 0

	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("parse repository created_at: %w", err)
	}
	parsedUpdatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("parse repository updated_at: %w", err)
	}
	repo.CreatedAt = parsedCreatedAt
	repo.UpdatedAt = parsedUpdatedAt
	return repo, nil
}
