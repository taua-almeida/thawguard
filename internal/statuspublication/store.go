package statuspublication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

// Historical databases may still hold 'local_record' intents and 'dry_run'
// attempts with a 'planned' result from the removed shadow mode. Those rows
// stay readable; the store only writes forgejo_status records now.
const (
	DeliveryModeForgejoStatus = "forgejo_status"
	AttemptModeForgejoStatus  = "forgejo_status"
	AttemptResultPosted       = "posted"
	AttemptResultFailed       = "failed"
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

type Publication struct {
	ID               int64
	StatusResultID   int64
	RepositoryID     int64
	PullRequestIndex int
	TargetBranch     string
	HeadSHA          string
	Context          string
	State            domain.CommitStatusState
	Description      string
	TargetURL        string
	DeliveryMode     string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Attempt struct {
	ID               int64
	PublicationID    int64
	StatusResultID   int64
	RepositoryID     int64
	PullRequestIndex int
	TargetBranch     string
	HeadSHA          string
	Context          string
	State            domain.CommitStatusState
	Description      string
	TargetURL        string
	Mode             string
	Result           string
	Error            string
	AttemptedAt      time.Time
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

func (s *Store) PublishForgejoStatus(ctx context.Context, result statusresult.Result) (Publication, error) {
	return s.publish(ctx, result, DeliveryModeForgejoStatus)
}

func (s *Store) publish(ctx context.Context, result statusresult.Result, deliveryMode string) (Publication, error) {
	if s == nil || s.db == nil {
		return Publication{}, errors.New("status publication store has no database")
	}
	publication := publicationFromResult(result)
	publication.DeliveryMode = deliveryMode
	publication.CreatedAt = s.now().UTC()
	publication.UpdatedAt = publication.CreatedAt
	publication = normalizePublication(publication)
	if err := validatePublication(publication); err != nil {
		return Publication{}, err
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO status_publication_intents(status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(repository_id, head_sha, context, delivery_mode) DO UPDATE SET
  status_result_id = excluded.status_result_id,
  pull_request_index = excluded.pull_request_index,
  target_branch = excluded.target_branch,
  state = excluded.state,
  description = excluded.description,
  target_url = excluded.target_url,
  updated_at = excluded.updated_at`, publication.StatusResultID, publication.RepositoryID, publication.PullRequestIndex, publication.TargetBranch, publication.HeadSHA, publication.Context, publication.State, publication.Description, nullableString(publication.TargetURL), publication.DeliveryMode, publication.CreatedAt.Format(time.RFC3339Nano), publication.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return Publication{}, fmt.Errorf("record status publication intent: %w", err)
	}
	return s.getByIdempotencyKey(ctx, publication)
}

func (s *Store) Get(ctx context.Context, id int64) (Publication, error) {
	if s == nil || s.db == nil {
		return Publication{}, errors.New("status publication store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at
FROM status_publication_intents
WHERE id = ?`, id)
	return scanPublication(row)
}

func (s *Store) ListRecent(ctx context.Context, limit int) ([]Publication, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("status publication store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at
FROM status_publication_intents
ORDER BY updated_at DESC, id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list status publication intents: %w", err)
	}
	defer rows.Close()

	publications := make([]Publication, 0)
	for rows.Next() {
		publication, err := scanPublication(rows)
		if err != nil {
			return nil, err
		}
		publications = append(publications, publication)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list status publication intents rows: %w", err)
	}
	return publications, nil
}

// ListPage returns one newest-first page of publication intents plus the total
// count matching the same filters. An empty state or zero repositoryID leaves
// that filter off; an unknown state simply matches nothing.
func (s *Store) ListPage(ctx context.Context, state string, repositoryID int64, offset, limit int) ([]Publication, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("status publication store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where, filterArgs := publicationPageFilter("state", state, repositoryID)

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM status_publication_intents "+where, filterArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count status publication intents: %w", err)
	}

	args := append(append([]any{}, filterArgs...), limit, offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at
FROM status_publication_intents
`+where+`
ORDER BY updated_at DESC, id DESC
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list status publication intents page: %w", err)
	}
	defer rows.Close()

	publications := make([]Publication, 0)
	for rows.Next() {
		publication, err := scanPublication(rows)
		if err != nil {
			return nil, 0, err
		}
		publications = append(publications, publication)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list status publication intents page rows: %w", err)
	}
	return publications, total, nil
}

// publicationPageFilter builds the shared WHERE clause for the paged list
// queries: an optional exact match on one text column plus an optional
// repository scope.
func publicationPageFilter(column, value string, repositoryID int64) (string, []any) {
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if value != "" {
		conditions = append(conditions, column+" = ?")
		args = append(args, value)
	}
	if repositoryID > 0 {
		conditions = append(conditions, "repository_id = ?")
		args = append(args, repositoryID)
	}
	if len(conditions) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) RecordForgejoStatusAttempt(ctx context.Context, publication Publication, result string, errorMessage string) (Attempt, error) {
	return s.recordAttempt(ctx, publication, AttemptModeForgejoStatus, result, errorMessage)
}

func (s *Store) recordAttempt(ctx context.Context, publication Publication, mode string, result string, errorMessage string) (Attempt, error) {
	if s == nil || s.db == nil {
		return Attempt{}, errors.New("status publication store has no database")
	}
	attempt := attemptFromPublication(publication)
	attempt.Mode = mode
	attempt.Result = result
	attempt.Error = errorMessage
	attempt.AttemptedAt = s.now().UTC()
	attempt = normalizeAttempt(attempt)
	if err := validateAttempt(attempt); err != nil {
		return Attempt{}, err
	}

	insert, err := s.db.ExecContext(ctx, `
INSERT INTO status_publication_attempts(publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, attempt.PublicationID, attempt.StatusResultID, attempt.RepositoryID, attempt.PullRequestIndex, attempt.TargetBranch, attempt.HeadSHA, attempt.Context, attempt.State, attempt.Description, nullableString(attempt.TargetURL), attempt.Mode, attempt.Result, nullableString(attempt.Error), attempt.AttemptedAt.Format(time.RFC3339Nano))
	if err != nil {
		return Attempt{}, fmt.Errorf("record status publication attempt: %w", err)
	}
	id, err := insert.LastInsertId()
	if err != nil {
		return Attempt{}, fmt.Errorf("recorded status publication attempt id: %w", err)
	}
	return s.GetAttempt(ctx, id)
}

func (s *Store) GetAttempt(ctx context.Context, id int64) (Attempt, error) {
	if s == nil || s.db == nil {
		return Attempt{}, errors.New("status publication store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at
FROM status_publication_attempts
WHERE id = ?`, id)
	return scanAttempt(row)
}

func (s *Store) ListRecentAttempts(ctx context.Context, limit int) ([]Attempt, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("status publication store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at
FROM status_publication_attempts
ORDER BY attempted_at DESC, id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list status publication attempts: %w", err)
	}
	defer rows.Close()

	attempts := make([]Attempt, 0)
	for rows.Next() {
		attempt, err := scanAttempt(rows)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list status publication attempts rows: %w", err)
	}
	return attempts, nil
}

// ListAttemptsPage returns one newest-first page of delivery attempts plus the
// total count matching the same filters. An empty result or zero repositoryID
// leaves that filter off; historical results from removed modes stay reachable
// through the unfiltered view.
func (s *Store) ListAttemptsPage(ctx context.Context, result string, repositoryID int64, offset, limit int) ([]Attempt, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("status publication store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where, filterArgs := publicationPageFilter("result", result, repositoryID)

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM status_publication_attempts "+where, filterArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count status publication attempts: %w", err)
	}

	args := append(append([]any{}, filterArgs...), limit, offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, mode, result, error, attempted_at
FROM status_publication_attempts
`+where+`
ORDER BY attempted_at DESC, id DESC
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list status publication attempts page: %w", err)
	}
	defer rows.Close()

	attempts := make([]Attempt, 0)
	for rows.Next() {
		attempt, err := scanAttempt(rows)
		if err != nil {
			return nil, 0, err
		}
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list status publication attempts page rows: %w", err)
	}
	return attempts, total, nil
}

func (s *Store) getByIdempotencyKey(ctx context.Context, publication Publication) (Publication, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at, updated_at
FROM status_publication_intents
WHERE repository_id = ? AND head_sha = ? AND context = ? AND delivery_mode = ?`, publication.RepositoryID, publication.HeadSHA, publication.Context, publication.DeliveryMode)
	return scanPublication(row)
}

func publicationFromResult(result statusresult.Result) Publication {
	return Publication{
		StatusResultID:   result.ID,
		RepositoryID:     result.RepositoryID,
		PullRequestIndex: result.PullRequestIndex,
		TargetBranch:     result.TargetBranch,
		HeadSHA:          result.HeadSHA,
		Context:          result.Context,
		State:            result.State,
		Description:      result.Description,
		TargetURL:        result.TargetURL,
	}
}

func attemptFromPublication(publication Publication) Attempt {
	return Attempt{
		PublicationID:    publication.ID,
		StatusResultID:   publication.StatusResultID,
		RepositoryID:     publication.RepositoryID,
		PullRequestIndex: publication.PullRequestIndex,
		TargetBranch:     publication.TargetBranch,
		HeadSHA:          publication.HeadSHA,
		Context:          publication.Context,
		State:            publication.State,
		Description:      publication.Description,
		TargetURL:        publication.TargetURL,
	}
}

func normalizePublication(publication Publication) Publication {
	publication.TargetBranch = strings.TrimSpace(publication.TargetBranch)
	publication.HeadSHA = strings.ToLower(strings.TrimSpace(publication.HeadSHA))
	publication.Context = strings.TrimSpace(publication.Context)
	publication.Description = strings.TrimSpace(publication.Description)
	publication.TargetURL = strings.TrimSpace(publication.TargetURL)
	publication.DeliveryMode = strings.TrimSpace(publication.DeliveryMode)
	return publication
}

func normalizeAttempt(attempt Attempt) Attempt {
	attempt.TargetBranch = strings.TrimSpace(attempt.TargetBranch)
	attempt.HeadSHA = strings.ToLower(strings.TrimSpace(attempt.HeadSHA))
	attempt.Context = strings.TrimSpace(attempt.Context)
	attempt.Description = strings.TrimSpace(attempt.Description)
	attempt.TargetURL = strings.TrimSpace(attempt.TargetURL)
	attempt.Mode = strings.TrimSpace(attempt.Mode)
	attempt.Result = strings.TrimSpace(attempt.Result)
	attempt.Error = strings.TrimSpace(attempt.Error)
	return attempt
}

func validatePublication(publication Publication) error {
	var missing []string
	if publication.StatusResultID <= 0 {
		missing = append(missing, "status result")
	}
	if publication.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if publication.PullRequestIndex <= 0 {
		missing = append(missing, "pull request")
	}
	if publication.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if publication.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if publication.Context == "" {
		missing = append(missing, "context")
	}
	if publication.Description == "" {
		missing = append(missing, "description")
	}
	if publication.DeliveryMode == "" {
		missing = append(missing, "delivery mode")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required status publication fields: %s", strings.Join(missing, ", "))}
	}
	if publication.DeliveryMode != DeliveryModeForgejoStatus {
		return ValidationError{Message: "status publication delivery mode is invalid"}
	}
	if !validState(publication.State) {
		return ValidationError{Message: "status publication state is invalid"}
	}
	return nil
}

func validateAttempt(attempt Attempt) error {
	var missing []string
	if attempt.PublicationID <= 0 {
		missing = append(missing, "publication")
	}
	if attempt.StatusResultID <= 0 {
		missing = append(missing, "status result")
	}
	if attempt.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if attempt.PullRequestIndex <= 0 {
		missing = append(missing, "pull request")
	}
	if attempt.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if attempt.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if attempt.Context == "" {
		missing = append(missing, "context")
	}
	if attempt.Description == "" {
		missing = append(missing, "description")
	}
	if attempt.Mode == "" {
		missing = append(missing, "mode")
	}
	if attempt.Result == "" {
		missing = append(missing, "result")
	}
	if attempt.AttemptedAt.IsZero() {
		missing = append(missing, "attempted at")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required status publication attempt fields: %s", strings.Join(missing, ", "))}
	}
	if attempt.Mode != AttemptModeForgejoStatus {
		return ValidationError{Message: "status publication attempt mode is invalid"}
	}
	if attempt.Result != AttemptResultPosted && attempt.Result != AttemptResultFailed {
		return ValidationError{Message: "status publication attempt result is invalid"}
	}
	if attempt.Mode == AttemptModeForgejoStatus && attempt.Result == AttemptResultFailed && attempt.Error == "" {
		return ValidationError{Message: "status publication attempt error is required for failed forgejo status attempts"}
	}
	if !validState(attempt.State) {
		return ValidationError{Message: "status publication attempt state is invalid"}
	}
	return nil
}

func validState(state domain.CommitStatusState) bool {
	switch state {
	case domain.CommitStatusSuccess, domain.CommitStatusFailure, domain.CommitStatusPending, domain.CommitStatusError:
		return true
	default:
		return false
	}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type scanner interface {
	Scan(dest ...any) error
}

func scanPublication(row scanner) (Publication, error) {
	var publication Publication
	var targetURL sql.NullString
	var createdAt string
	var updatedAt string
	if err := row.Scan(&publication.ID, &publication.StatusResultID, &publication.RepositoryID, &publication.PullRequestIndex, &publication.TargetBranch, &publication.HeadSHA, &publication.Context, &publication.State, &publication.Description, &targetURL, &publication.DeliveryMode, &createdAt, &updatedAt); err != nil {
		return Publication{}, fmt.Errorf("scan status publication intent: %w", err)
	}
	if targetURL.Valid {
		publication.TargetURL = targetURL.String
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Publication{}, fmt.Errorf("parse status publication intent created_at: %w", err)
	}
	publication.CreatedAt = parsedCreatedAt
	parsedUpdatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Publication{}, fmt.Errorf("parse status publication intent updated_at: %w", err)
	}
	publication.UpdatedAt = parsedUpdatedAt
	return publication, nil
}

func scanAttempt(row scanner) (Attempt, error) {
	var attempt Attempt
	var targetURL sql.NullString
	var attemptError sql.NullString
	var attemptedAt string
	if err := row.Scan(&attempt.ID, &attempt.PublicationID, &attempt.StatusResultID, &attempt.RepositoryID, &attempt.PullRequestIndex, &attempt.TargetBranch, &attempt.HeadSHA, &attempt.Context, &attempt.State, &attempt.Description, &targetURL, &attempt.Mode, &attempt.Result, &attemptError, &attemptedAt); err != nil {
		return Attempt{}, fmt.Errorf("scan status publication attempt: %w", err)
	}
	if targetURL.Valid {
		attempt.TargetURL = targetURL.String
	}
	if attemptError.Valid {
		attempt.Error = attemptError.String
	}
	parsedAttemptedAt, err := time.Parse(time.RFC3339Nano, attemptedAt)
	if err != nil {
		return Attempt{}, fmt.Errorf("parse status publication attempt attempted_at: %w", err)
	}
	attempt.AttemptedAt = parsedAttemptedAt
	return attempt, nil
}
