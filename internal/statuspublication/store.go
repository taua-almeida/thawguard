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

const DeliveryModeLocalRecord = "local_record"

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

func (s *Store) Publish(ctx context.Context, result statusresult.Result) (Publication, error) {
	if s == nil || s.db == nil {
		return Publication{}, errors.New("status publication store has no database")
	}
	publication := publicationFromResult(result)
	publication.DeliveryMode = DeliveryModeLocalRecord
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

func normalizePublication(publication Publication) Publication {
	publication.TargetBranch = strings.TrimSpace(publication.TargetBranch)
	publication.HeadSHA = strings.ToLower(strings.TrimSpace(publication.HeadSHA))
	publication.Context = strings.TrimSpace(publication.Context)
	publication.Description = strings.TrimSpace(publication.Description)
	publication.TargetURL = strings.TrimSpace(publication.TargetURL)
	publication.DeliveryMode = strings.TrimSpace(publication.DeliveryMode)
	return publication
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
	if publication.DeliveryMode != DeliveryModeLocalRecord {
		return ValidationError{Message: "status publication delivery mode is invalid"}
	}
	if !validState(publication.State) {
		return ValidationError{Message: "status publication state is invalid"}
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
