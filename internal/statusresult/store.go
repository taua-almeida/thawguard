package statusresult

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

type Result struct {
	ID               int64
	RepositoryID     int64
	PullRequestIndex int
	TargetBranch     string
	HeadSHA          string
	Context          string
	State            domain.CommitStatusState
	Description      string
	TargetURL        string
	PostedAt         *time.Time
	Error            string
	CreatedAt        time.Time
}

type CreateParams struct {
	RepositoryID     int64
	PullRequestIndex int
	TargetBranch     string
	HeadSHA          string
	Context          string
	State            domain.CommitStatusState
	Description      string
	TargetURL        string
	PostedAt         *time.Time
	Error            string
}

func NewStore(db *sql.DB) *Store {
	if db == nil {
		return newStore(nil)
	}
	return newStore(db)
}

func newStore(db database) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) Create(ctx context.Context, params CreateParams) (Result, error) {
	if s == nil || s.db == nil {
		return Result{}, errors.New("status result store has no database")
	}
	params = normalizeCreateParams(params)
	if err := validateCreateParams(params); err != nil {
		return Result{}, err
	}
	if err := s.requireRepository(ctx, params.RepositoryID); err != nil {
		return Result{}, err
	}

	var pullRequestIndex any
	if params.PullRequestIndex > 0 {
		pullRequestIndex = params.PullRequestIndex
	}
	var targetURL any
	if params.TargetURL != "" {
		targetURL = params.TargetURL
	}
	var postedAt any
	if params.PostedAt != nil {
		postedAt = params.PostedAt.UTC().Format(time.RFC3339Nano)
	}
	var resultError any
	if params.Error != "" {
		resultError = params.Error
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	insert, err := s.db.ExecContext(ctx, `
INSERT INTO status_results(repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, posted_at, error, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, params.RepositoryID, pullRequestIndex, params.TargetBranch, params.HeadSHA, params.Context, params.State, params.Description, targetURL, postedAt, resultError, now)
	if err != nil {
		return Result{}, fmt.Errorf("create status result: %w", err)
	}
	id, err := insert.LastInsertId()
	if err != nil {
		return Result{}, fmt.Errorf("created status result id: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *Store) Get(ctx context.Context, id int64) (Result, error) {
	if s == nil || s.db == nil {
		return Result{}, errors.New("status result store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, posted_at, error, created_at
FROM status_results
WHERE id = ?`, id)
	return scanResult(row)
}

func (s *Store) ListRecent(ctx context.Context, limit int) ([]Result, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("status result store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, posted_at, error, created_at
FROM status_results
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list status results: %w", err)
	}
	defer rows.Close()

	results := make([]Result, 0)
	for rows.Next() {
		result, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list status results rows: %w", err)
	}
	return results, nil
}

func (s *Store) requireRepository(ctx context.Context, repositoryID int64) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE id = ? AND active = 1`, repositoryID).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: "repository not found"}
	}
	if err != nil {
		return fmt.Errorf("check status result repository: %w", err)
	}
	return nil
}

func normalizeCreateParams(params CreateParams) CreateParams {
	params.HeadSHA = strings.TrimSpace(params.HeadSHA)
	params.HeadSHA = strings.ToLower(params.HeadSHA)
	params.TargetBranch = strings.TrimSpace(params.TargetBranch)
	params.Context = strings.TrimSpace(params.Context)
	params.Description = strings.TrimSpace(params.Description)
	params.TargetURL = strings.TrimSpace(params.TargetURL)
	params.Error = strings.TrimSpace(params.Error)
	return params
}

func validateCreateParams(params CreateParams) error {
	var missing []string
	if params.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if params.PullRequestIndex <= 0 {
		missing = append(missing, "pull request")
	}
	if params.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if params.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if params.Context == "" {
		missing = append(missing, "context")
	}
	if params.Description == "" {
		missing = append(missing, "description")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required status result fields: %s", strings.Join(missing, ", "))}
	}
	if !validState(params.State) {
		return ValidationError{Message: "status result state is invalid"}
	}
	if params.PullRequestIndex > 1_000_000 {
		return ValidationError{Message: "pull request number is too large"}
	}
	if len(params.TargetBranch) > 255 || containsControl(params.TargetBranch) {
		return ValidationError{Message: "target branch is invalid"}
	}
	if len(params.HeadSHA) < 6 || len(params.HeadSHA) > 64 || containsControl(params.HeadSHA) || !isHex(params.HeadSHA) {
		return ValidationError{Message: "head SHA is invalid"}
	}
	return nil
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isHex(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func validState(state domain.CommitStatusState) bool {
	switch state {
	case domain.CommitStatusSuccess, domain.CommitStatusFailure, domain.CommitStatusPending, domain.CommitStatusError:
		return true
	default:
		return false
	}
}

type scanner interface {
	Scan(dest ...any) error
}

func scanResult(row scanner) (Result, error) {
	var result Result
	var pullRequestIndex sql.NullInt64
	var targetURL sql.NullString
	var postedAt sql.NullString
	var resultError sql.NullString
	var createdAt string
	if err := row.Scan(&result.ID, &result.RepositoryID, &pullRequestIndex, &result.TargetBranch, &result.HeadSHA, &result.Context, &result.State, &result.Description, &targetURL, &postedAt, &resultError, &createdAt); err != nil {
		return Result{}, fmt.Errorf("scan status result: %w", err)
	}
	if pullRequestIndex.Valid {
		result.PullRequestIndex = int(pullRequestIndex.Int64)
	}
	if targetURL.Valid {
		result.TargetURL = targetURL.String
	}
	if postedAt.Valid {
		parsedPostedAt, err := time.Parse(time.RFC3339Nano, postedAt.String)
		if err != nil {
			return Result{}, fmt.Errorf("parse status result posted_at: %w", err)
		}
		result.PostedAt = &parsedPostedAt
	}
	if resultError.Valid {
		result.Error = resultError.String
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Result{}, fmt.Errorf("parse status result created_at: %w", err)
	}
	result.CreatedAt = parsedCreatedAt
	return result, nil
}
