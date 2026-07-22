package thawexception

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

type database interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
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

type ApproveParams struct {
	RepositoryID     int64
	PullRequestIndex int
	PullRequestURL   string
	TargetBranch     string
	HeadSHA          string
	Reason           string
	ExpiresAt        *time.Time
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

func (s *Store) Approve(ctx context.Context, params ApproveParams, actor domain.Actor) (domain.ThawException, error) {
	if s == nil || s.db == nil {
		return domain.ThawException{}, errors.New("thaw exception store has no database")
	}
	params = normalizeApproveParams(params)
	if err := validateApproveParams(params); err != nil {
		return domain.ThawException{}, err
	}
	if err := s.requireEnforcementActiveRepository(ctx, params.RepositoryID); err != nil {
		return domain.ThawException{}, err
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	var pullRequestURL any
	if params.PullRequestURL != "" {
		pullRequestURL = params.PullRequestURL
	}
	var approvedBy any
	if actor.UserID != nil {
		approvedBy = *actor.UserID
	}
	var expiresAt any
	if params.ExpiresAt != nil {
		expiresAt = params.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}

	insert, err := s.db.ExecContext(ctx, `
INSERT INTO thaw_exceptions(repository_id, pull_request_index, pull_request_url, head_sha, target_branch, status, reason, approved_by, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`, params.RepositoryID, params.PullRequestIndex, pullRequestURL, params.HeadSHA, params.TargetBranch, params.Reason, approvedBy, expiresAt, now, now)
	if err != nil {
		return domain.ThawException{}, fmt.Errorf("approve thaw exception: %w", err)
	}
	id, err := insert.LastInsertId()
	if err != nil {
		return domain.ThawException{}, fmt.Errorf("approved thaw exception id: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *Store) Get(ctx context.Context, id int64) (domain.ThawException, error) {
	if s == nil || s.db == nil {
		return domain.ThawException{}, errors.New("thaw exception store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, pull_request_index, pull_request_url, head_sha, target_branch, status, reason, expires_at, created_at, updated_at
FROM thaw_exceptions
WHERE id = ?`, id)
	return scanThawException(row)
}

func (s *Store) ActiveForPullRequest(ctx context.Context, pr domain.PullRequest) (*domain.ThawException, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("thaw exception store has no database")
	}
	pr = normalizePullRequest(pr)
	if err := validatePullRequest(pr); err != nil {
		return nil, err
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, pull_request_index, pull_request_url, head_sha, target_branch, status, reason, expires_at, created_at, updated_at
FROM thaw_exceptions
WHERE repository_id = ?
  AND pull_request_index = ?
  AND head_sha = ?
  AND target_branch = ?
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > ?)
ORDER BY id DESC
LIMIT 1`, pr.RepositoryID, pr.Index, pr.HeadSHA, pr.TargetBranch, now)
	exception, err := scanThawException(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if pr.ID > 0 {
		exception.PullRequestID = pr.ID
	}
	return &exception, nil
}

// CountActive counts thaw exceptions that are in effect right now: status
// 'active' and either no expiry or an expiry still in the future.
func (s *Store) CountActive(ctx context.Context) (int, error) {
	return s.CountActiveForScope(ctx, repositoryscope.All())
}

// CountActiveForScope counts the currently active, unexpired thaw exceptions
// on repositories visible through the caller's read scope. The scope predicate
// intersects with the active/expiry conditions inside SQL, so invisible
// repositories never contribute to the count.
func (s *Store) CountActiveForScope(ctx context.Context, scope repositoryscope.ReadScope) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("thaw exception store has no database")
	}
	predicate, args := scope.SQLPredicate("repository_id")
	now := s.now().UTC().Format(time.RFC3339Nano)
	args = append(args, now)
	var count int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM thaw_exceptions
WHERE `+predicate+`
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > ?)`, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active thaw exceptions: %w", err)
	}
	return count, nil
}

func (s *Store) requireEnforcementActiveRepository(ctx context.Context, repositoryID int64) error {
	var existing int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE id = ? AND active = 1 AND enforcement_state = ?`, repositoryID, domain.EnforcementActive).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: domain.EnforcementNotActiveMessage}
	}
	if err != nil {
		return fmt.Errorf("check thaw exception repository enforcement: %w", err)
	}
	return nil
}

func normalizeApproveParams(params ApproveParams) ApproveParams {
	params.PullRequestURL = strings.TrimSpace(params.PullRequestURL)
	params.TargetBranch = strings.TrimSpace(params.TargetBranch)
	params.HeadSHA = strings.ToLower(strings.TrimSpace(params.HeadSHA))
	params.Reason = strings.TrimSpace(params.Reason)
	return params
}

func normalizePullRequest(pr domain.PullRequest) domain.PullRequest {
	pr.TargetBranch = strings.TrimSpace(pr.TargetBranch)
	pr.HeadSHA = strings.ToLower(strings.TrimSpace(pr.HeadSHA))
	return pr
}

func validateApproveParams(params ApproveParams) error {
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
	if params.Reason == "" {
		missing = append(missing, "reason")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required thaw exception fields: %s", strings.Join(missing, ", "))}
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
	if len(params.Reason) > 500 || containsControl(params.Reason) {
		return ValidationError{Message: "reason is invalid"}
	}
	if len(params.PullRequestURL) > 2048 || containsControl(params.PullRequestURL) {
		return ValidationError{Message: "pull request URL is invalid"}
	}
	return nil
}

func validatePullRequest(pr domain.PullRequest) error {
	return validateApproveParams(ApproveParams{RepositoryID: pr.RepositoryID, PullRequestIndex: pr.Index, TargetBranch: pr.TargetBranch, HeadSHA: pr.HeadSHA, Reason: "lookup"})
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

func scanThawException(row scanner) (domain.ThawException, error) {
	var thaw domain.ThawException
	var pullRequestURL sql.NullString
	var expiresAt sql.NullString
	var createdAt string
	var updatedAt string
	if err := row.Scan(&thaw.ID, &thaw.RepositoryID, &thaw.PullRequestIndex, &pullRequestURL, &thaw.HeadSHA, &thaw.TargetBranch, &thaw.Status, &thaw.Reason, &expiresAt, &createdAt, &updatedAt); err != nil {
		return domain.ThawException{}, fmt.Errorf("scan thaw exception: %w", err)
	}
	thaw.PullRequestURL = pullRequestURL.String
	thaw.Active = thaw.Status == "active"
	if expiresAt.Valid && strings.TrimSpace(expiresAt.String) != "" {
		parsed, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil {
			return domain.ThawException{}, fmt.Errorf("parse thaw exception expiry: %w", err)
		}
		thaw.ExpiresAt = &parsed
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return domain.ThawException{}, fmt.Errorf("parse thaw exception created_at: %w", err)
	}
	parsedUpdatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return domain.ThawException{}, fmt.Errorf("parse thaw exception updated_at: %w", err)
	}
	thaw.CreatedAt = parsedCreatedAt
	thaw.UpdatedAt = parsedUpdatedAt
	return thaw, nil
}
