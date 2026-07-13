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

type RemoteParams struct {
	Forge   string
	BaseURL string
	Owner   string
	Name    string
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
	// A repository always has at least its default branch managed. Callers
	// create repositories inside the setup transaction, so a failure here
	// rolls back the repository row as well.
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO repository_branches(repository_id, name)
VALUES (?, ?)`, id, params.DefaultBranch); err != nil {
		return domain.Repository{}, fmt.Errorf("create default managed branch: %w", err)
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
SELECT id, forge, base_url, owner, name, default_branch, active, enforcement_state,
  EXISTS(SELECT 1 FROM repository_webhook_secrets WHERE repository_id = repositories.id),
  EXISTS(SELECT 1 FROM repository_status_tokens WHERE repository_id = repositories.id),
  status_post_verified_at, created_at, updated_at
FROM repositories
WHERE id = ?`, id)
	return scanRepository(row)
}

func (s *Store) List(ctx context.Context) ([]domain.Repository, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("repository store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, forge, base_url, owner, name, default_branch, active, enforcement_state,
  EXISTS(SELECT 1 FROM repository_webhook_secrets WHERE repository_id = repositories.id),
  EXISTS(SELECT 1 FROM repository_status_tokens WHERE repository_id = repositories.id),
  status_post_verified_at, created_at, updated_at
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

func (s *Store) FindActiveByRemote(ctx context.Context, params RemoteParams) (domain.Repository, bool, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, false, errors.New("repository store has no database")
	}
	params = normalizeRemoteParams(params)
	if params.Forge == "" || params.BaseURL == "" || params.Owner == "" || params.Name == "" {
		return domain.Repository{}, false, ValidationError{Message: "missing required repository remote fields"}
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, forge, base_url, owner, name, default_branch, active, enforcement_state,
  EXISTS(SELECT 1 FROM repository_webhook_secrets WHERE repository_id = repositories.id),
  EXISTS(SELECT 1 FROM repository_status_tokens WHERE repository_id = repositories.id),
  status_post_verified_at, created_at, updated_at
FROM repositories
	WHERE forge = ? AND base_url = ? AND owner = ? AND name = ? AND active = 1`, params.Forge, params.BaseURL, params.Owner, params.Name)
	repo, err := scanRepository(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, false, nil
		}
		return domain.Repository{}, false, err
	}
	return repo, true, nil
}

func (s *Store) SetEnforcementState(ctx context.Context, repositoryID int64, state domain.EnforcementState) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return domain.Repository{}, ValidationError{Message: "repository id is required"}
	}
	if !state.Valid() {
		return domain.Repository{}, ValidationError{Message: "repository enforcement state is invalid"}
	}
	updatedAt := s.now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE repositories
SET enforcement_state = ?, updated_at = ?
WHERE id = ?`, string(state), updatedAt, repositoryID)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("set repository enforcement state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Repository{}, fmt.Errorf("set repository enforcement state rows: %w", err)
	}
	if affected == 0 {
		return domain.Repository{}, sql.ErrNoRows
	}
	return s.Get(ctx, repositoryID)
}

// SetStatusPostVerifiedAt stores the latest successful controlled status-post
// verification time; a nil verifiedAt clears the evidence.
func (s *Store) SetStatusPostVerifiedAt(ctx context.Context, repositoryID int64, verifiedAt *time.Time) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return domain.Repository{}, ValidationError{Message: "repository id is required"}
	}
	var verifiedAtValue any
	if verifiedAt != nil {
		if verifiedAt.IsZero() {
			return domain.Repository{}, ValidationError{Message: "status post verification time is required"}
		}
		verifiedAtValue = verifiedAt.UTC().Format(time.RFC3339Nano)
	}
	updatedAt := s.now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE repositories
SET status_post_verified_at = ?, updated_at = ?
WHERE id = ?`, verifiedAtValue, updatedAt, repositoryID)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("set repository status post verification: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Repository{}, fmt.Errorf("set repository status post verification rows: %w", err)
	}
	if affected == 0 {
		return domain.Repository{}, sql.ErrNoRows
	}
	return s.Get(ctx, repositoryID)
}

func (s *Store) SetWebhookSecretCiphertext(ctx context.Context, repositoryID int64, ciphertext []byte) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return domain.Repository{}, ValidationError{Message: "repository id is required"}
	}
	if len(ciphertext) == 0 {
		return domain.Repository{}, ValidationError{Message: "webhook secret ciphertext is required"}
	}
	if len(ciphertext) > 4096 {
		return domain.Repository{}, ValidationError{Message: "webhook secret ciphertext is too large"}
	}
	updatedAt := s.now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE repositories
SET updated_at = ?
WHERE id = ?`, updatedAt, repositoryID)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("touch repository webhook secret updated_at: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Repository{}, fmt.Errorf("touch repository webhook secret updated_at rows: %w", err)
	}
	if affected == 0 {
		return domain.Repository{}, sql.ErrNoRows
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO repository_webhook_secrets(repository_id, ciphertext, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(repository_id) DO UPDATE SET
  ciphertext = excluded.ciphertext,
  updated_at = excluded.updated_at`, repositoryID, ciphertext, updatedAt)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("set repository webhook secret ciphertext: %w", err)
	}
	return s.Get(ctx, repositoryID)
}

func (s *Store) WebhookSecretCiphertext(ctx context.Context, repositoryID int64) ([]byte, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return nil, false, ValidationError{Message: "repository id is required"}
	}
	row := s.db.QueryRowContext(ctx, `
SELECT repository_webhook_secrets.ciphertext
FROM repository_webhook_secrets
JOIN repositories ON repositories.id = repository_webhook_secrets.repository_id
WHERE repository_webhook_secrets.repository_id = ? AND repositories.active = 1`, repositoryID)
	var ciphertext []byte
	if err := row.Scan(&ciphertext); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("scan repository webhook secret ciphertext: %w", err)
	}
	if len(ciphertext) == 0 {
		return nil, false, nil
	}
	copyCiphertext := make([]byte, len(ciphertext))
	copy(copyCiphertext, ciphertext)
	return copyCiphertext, true, nil
}

func (s *Store) SetStatusTokenCiphertext(ctx context.Context, repositoryID int64, ciphertext []byte) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return domain.Repository{}, ValidationError{Message: "repository id is required"}
	}
	if len(ciphertext) == 0 {
		return domain.Repository{}, ValidationError{Message: "status token ciphertext is required"}
	}
	if len(ciphertext) > 4096 {
		return domain.Repository{}, ValidationError{Message: "status token ciphertext is too large"}
	}
	updatedAt := s.now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE repositories
SET updated_at = ?
WHERE id = ?`, updatedAt, repositoryID)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("touch repository status token updated_at: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Repository{}, fmt.Errorf("touch repository status token updated_at rows: %w", err)
	}
	if affected == 0 {
		return domain.Repository{}, sql.ErrNoRows
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO repository_status_tokens(repository_id, ciphertext, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(repository_id) DO UPDATE SET
  ciphertext = excluded.ciphertext,
  updated_at = excluded.updated_at`, repositoryID, ciphertext, updatedAt)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("set repository status token ciphertext: %w", err)
	}
	return s.Get(ctx, repositoryID)
}

func (s *Store) StatusTokenCiphertext(ctx context.Context, repositoryID int64) ([]byte, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, errors.New("repository store has no database")
	}
	if repositoryID <= 0 {
		return nil, false, ValidationError{Message: "repository id is required"}
	}
	row := s.db.QueryRowContext(ctx, `
SELECT repository_status_tokens.ciphertext
FROM repository_status_tokens
JOIN repositories ON repositories.id = repository_status_tokens.repository_id
WHERE repository_status_tokens.repository_id = ? AND repositories.active = 1`, repositoryID)
	var ciphertext []byte
	if err := row.Scan(&ciphertext); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("scan repository status token ciphertext: %w", err)
	}
	if len(ciphertext) == 0 {
		return nil, false, nil
	}
	copyCiphertext := make([]byte, len(ciphertext))
	copy(copyCiphertext, ciphertext)
	return copyCiphertext, true, nil
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

func normalizeRemoteParams(params RemoteParams) RemoteParams {
	params.Forge = strings.ToLower(strings.TrimSpace(params.Forge))
	params.BaseURL = strings.TrimRight(strings.TrimSpace(params.BaseURL), "/")
	params.Owner = strings.TrimSpace(params.Owner)
	params.Name = strings.TrimSpace(params.Name)
	if params.Forge == "" {
		params.Forge = "forgejo"
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
	return validateBranchName(params.DefaultBranch)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRepository(row scanner) (domain.Repository, error) {
	var repo domain.Repository
	var active, hasWebhookSecret, hasStatusToken int
	var enforcementState string
	var statusPostVerifiedAt sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&repo.ID, &repo.Forge, &repo.BaseURL, &repo.Owner, &repo.Name, &repo.DefaultBranch, &active, &enforcementState, &hasWebhookSecret, &hasStatusToken, &statusPostVerifiedAt, &createdAt, &updatedAt); err != nil {
		return domain.Repository{}, fmt.Errorf("scan repository: %w", err)
	}
	repo.Active = active != 0
	repo.EnforcementState = domain.EnforcementState(enforcementState)
	repo.HasWebhookSecret = hasWebhookSecret != 0
	repo.HasStatusToken = hasStatusToken != 0
	if statusPostVerifiedAt.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, statusPostVerifiedAt.String)
		if err != nil {
			return domain.Repository{}, fmt.Errorf("parse repository status_post_verified_at: %w", err)
		}
		repo.StatusPostVerifiedAt = &parsed
	}

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
