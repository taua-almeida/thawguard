package pullrequest

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

func NewStore(db *sql.DB) *Store {
	if db == nil {
		return newStore(nil)
	}
	return newStore(db)
}

func newStore(db database) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) Upsert(ctx context.Context, pr domain.PullRequest) (domain.PullRequest, error) {
	if s == nil || s.db == nil {
		return domain.PullRequest{}, errors.New("pull request store has no database")
	}
	pr = normalizePullRequest(pr)
	if err := validatePullRequest(pr); err != nil {
		return domain.PullRequest{}, err
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO pull_request_cache(repository_id, pull_request_index, state, target_branch, head_sha, title, url, updated_from_forge_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(repository_id, pull_request_index) DO UPDATE SET
  state = excluded.state,
  target_branch = excluded.target_branch,
  head_sha = excluded.head_sha,
  title = excluded.title,
  url = excluded.url,
  updated_from_forge_at = excluded.updated_from_forge_at`, pr.RepositoryID, pr.Index, pr.State, pr.TargetBranch, pr.HeadSHA, pr.Title, pr.URL, now)
	if err != nil {
		return domain.PullRequest{}, fmt.Errorf("upsert pull request cache: %w", err)
	}
	return s.Get(ctx, pr.RepositoryID, pr.Index)
}

func (s *Store) Get(ctx context.Context, repositoryID int64, index int) (domain.PullRequest, error) {
	if s == nil || s.db == nil {
		return domain.PullRequest{}, errors.New("pull request store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, pull_request_index, state, target_branch, head_sha, title, url
FROM pull_request_cache
WHERE repository_id = ? AND pull_request_index = ?`, repositoryID, index)
	return scanPullRequest(row)
}

func (s *Store) ListOpenByHead(ctx context.Context, repositoryID int64, headSHA string) ([]domain.PullRequest, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("pull request store has no database")
	}
	headSHA = strings.ToLower(strings.TrimSpace(headSHA))
	if repositoryID <= 0 || headSHA == "" {
		return nil, ValidationError{Message: "missing required pull request head lookup fields"}
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, pull_request_index, state, target_branch, head_sha, title, url
FROM pull_request_cache
WHERE repository_id = ? AND head_sha = ? AND state = 'open'
ORDER BY pull_request_index`, repositoryID, headSHA)
	if err != nil {
		return nil, fmt.Errorf("list open pull requests by head: %w", err)
	}
	defer rows.Close()

	prs := make([]domain.PullRequest, 0)
	for rows.Next() {
		pr, err := scanPullRequest(rows)
		if err != nil {
			return nil, err
		}
		prs = append(prs, pr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list open pull requests by head rows: %w", err)
	}
	return prs, nil
}

func (s *Store) ListOpenByTargetBranch(ctx context.Context, repositoryID int64, targetBranch string) ([]domain.PullRequest, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("pull request store has no database")
	}
	targetBranch = strings.TrimSpace(targetBranch)
	if repositoryID <= 0 || targetBranch == "" {
		return nil, ValidationError{Message: "missing required pull request branch lookup fields"}
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, pull_request_index, state, target_branch, head_sha, title, url
FROM pull_request_cache
WHERE repository_id = ? AND target_branch = ? AND state = 'open'
ORDER BY pull_request_index`, repositoryID, targetBranch)
	if err != nil {
		return nil, fmt.Errorf("list open pull requests by target branch: %w", err)
	}
	defer rows.Close()

	prs := make([]domain.PullRequest, 0)
	for rows.Next() {
		pr, err := scanPullRequest(rows)
		if err != nil {
			return nil, err
		}
		prs = append(prs, pr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list open pull requests by target branch rows: %w", err)
	}
	return prs, nil
}

func (s *Store) MarkAbsentOpenByTargetBranchClosed(ctx context.Context, repositoryID int64, targetBranch string, openIndexes []int) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("pull request store has no database")
	}
	targetBranch = strings.TrimSpace(targetBranch)
	if repositoryID <= 0 || targetBranch == "" {
		return 0, ValidationError{Message: "missing required pull request branch reconciliation fields"}
	}
	args := []any{s.now().UTC().Format(time.RFC3339Nano), repositoryID, targetBranch}
	query := `
UPDATE pull_request_cache
SET state = 'closed', updated_from_forge_at = ?
WHERE repository_id = ? AND target_branch = ? AND state = 'open'`
	if len(openIndexes) > 0 {
		placeholders := make([]string, 0, len(openIndexes))
		for _, index := range openIndexes {
			if index <= 0 || index > 1_000_000 {
				return 0, ValidationError{Message: "pull request number is invalid"}
			}
			placeholders = append(placeholders, "?")
			args = append(args, index)
		}
		query += " AND pull_request_index NOT IN (" + strings.Join(placeholders, ",") + ")"
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("mark absent open pull requests closed: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mark absent open pull requests closed rows affected: %w", err)
	}
	return rows, nil
}

func normalizePullRequest(pr domain.PullRequest) domain.PullRequest {
	pr.State = strings.ToLower(strings.TrimSpace(pr.State))
	pr.TargetBranch = strings.TrimSpace(pr.TargetBranch)
	pr.HeadSHA = strings.ToLower(strings.TrimSpace(pr.HeadSHA))
	pr.Title = strings.TrimSpace(pr.Title)
	pr.URL = strings.TrimSpace(pr.URL)
	if pr.State == "" {
		pr.State = "open"
	}
	return pr
}

func validatePullRequest(pr domain.PullRequest) error {
	var missing []string
	if pr.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if pr.Index <= 0 {
		missing = append(missing, "pull request")
	}
	if pr.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if pr.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required pull request fields: %s", strings.Join(missing, ", "))}
	}
	if pr.Index > 1_000_000 {
		return ValidationError{Message: "pull request number is too large"}
	}
	if len(pr.State) > 50 || containsControl(pr.State) {
		return ValidationError{Message: "pull request state is invalid"}
	}
	if len(pr.TargetBranch) > 255 || containsControl(pr.TargetBranch) {
		return ValidationError{Message: "target branch is invalid"}
	}
	if len(pr.HeadSHA) < 6 || len(pr.HeadSHA) > 64 || containsControl(pr.HeadSHA) || !isHex(pr.HeadSHA) {
		return ValidationError{Message: "head SHA is invalid"}
	}
	if len(pr.Title) > 500 || containsControl(pr.Title) {
		return ValidationError{Message: "pull request title is invalid"}
	}
	if len(pr.URL) > 2048 || containsControl(pr.URL) {
		return ValidationError{Message: "pull request URL is invalid"}
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

type scanner interface {
	Scan(dest ...any) error
}

func scanPullRequest(row scanner) (domain.PullRequest, error) {
	var pr domain.PullRequest
	if err := row.Scan(&pr.ID, &pr.RepositoryID, &pr.Index, &pr.State, &pr.TargetBranch, &pr.HeadSHA, &pr.Title, &pr.URL); err != nil {
		return domain.PullRequest{}, fmt.Errorf("scan pull request cache: %w", err)
	}
	return pr, nil
}
