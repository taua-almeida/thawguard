package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	ActionRepositoryCreated                 = "repository.created"
	ActionRepositoryWebhookSecretConfigured = "repository.webhook_secret_configured"
	ActionBranchFreezeCreated               = "branch_freeze.created"
	ActionBranchFreezeEnded                 = "branch_freeze.ended"
	ActionBranchFreezeCancelled             = "branch_freeze.cancelled"

	SubjectTypeRepository   = "repository"
	SubjectTypeBranchFreeze = "branch_freeze"
)

type Event struct {
	ID          int64
	ActorUserID *int64
	Action      string
	SubjectType string
	SubjectID   string
	DetailsJSON string
	CreatedAt   time.Time
}

type database interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type Store struct {
	db  database
	now func() time.Time
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

func (s *Store) Record(ctx context.Context, event Event) error {
	if s == nil || s.db == nil {
		return errors.New("audit store has no database")
	}
	event = normalizeEvent(event, s.now())
	if err := validateEvent(event); err != nil {
		return err
	}

	var actorUserID any
	if event.ActorUserID != nil {
		actorUserID = *event.ActorUserID
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events(actor_user_id, action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?, ?)`, actorUserID, event.Action, event.SubjectType, event.SubjectID, event.DetailsJSON, event.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, limit int) ([]Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, actor_user_id, action, subject_type, subject_id, details_json, created_at
FROM audit_events
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit events rows: %w", err)
	}
	return events, nil
}

func (s *Store) ListBySubjectType(ctx context.Context, subjectType string, limit int) ([]Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit store has no database")
	}
	if subjectType == "" {
		return nil, errors.New("audit event subject type is required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, actor_user_id, action, subject_type, subject_id, details_json, created_at
FROM audit_events
WHERE subject_type = ?
ORDER BY id DESC
LIMIT ?`, subjectType, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events by subject type: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit events by subject type rows: %w", err)
	}
	return events, nil
}

func normalizeEvent(event Event, now time.Time) Event {
	if event.DetailsJSON == "" {
		event.DetailsJSON = "{}"
	}
	event.CreatedAt = now.UTC()
	return event
}

func validateEvent(event Event) error {
	if event.Action == "" {
		return errors.New("audit event action is required")
	}
	if event.SubjectType == "" {
		return errors.New("audit event subject type is required")
	}
	if event.SubjectID == "" {
		return errors.New("audit event subject id is required")
	}
	if !json.Valid([]byte(event.DetailsJSON)) {
		return errors.New("audit event details must be valid JSON")
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEvent(row scanner) (Event, error) {
	var event Event
	var actorUserID sql.NullInt64
	var createdAt string
	if err := row.Scan(&event.ID, &actorUserID, &event.Action, &event.SubjectType, &event.SubjectID, &event.DetailsJSON, &createdAt); err != nil {
		return Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	if actorUserID.Valid {
		id := actorUserID.Int64
		event.ActorUserID = &id
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Event{}, fmt.Errorf("parse audit event created_at: %w", err)
	}
	event.CreatedAt = parsedCreatedAt
	return event, nil
}
