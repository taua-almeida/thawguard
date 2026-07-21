package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
)

// Service wraps Store so every schedule mutation and its audit event commit
// in one transaction, mirroring freeze.Service.
type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Get(ctx context.Context, id int64) (domain.Schedule, error) {
	if s == nil || s.db == nil {
		return domain.Schedule{}, errors.New("schedule service has no database")
	}
	return NewStore(s.db).Get(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]domain.Schedule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule service has no database")
	}
	return NewStore(s.db).List(ctx)
}

func (s *Service) Create(ctx context.Context, params CreateParams, actor domain.Actor) (domain.Schedule, error) {
	params.CreatedByUserID = actor.UserID
	params.CreatedByKind = actor.Kind
	return s.withAudit(ctx, actor, audit.ActionScheduleCreated, func(store *Store) (domain.Schedule, error) {
		return store.Create(ctx, params)
	})
}

func (s *Service) Delete(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	return s.withAudit(ctx, actor, audit.ActionScheduleDeleted, func(store *Store) (domain.Schedule, error) {
		return store.Delete(ctx, id)
	})
}

func (s *Service) withAudit(ctx context.Context, actor domain.Actor, action string, mutate func(*Store) (domain.Schedule, error)) (domain.Schedule, error) {
	if s == nil || s.db == nil {
		return domain.Schedule{}, errors.New("schedule service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("begin schedule mutation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	mutated, err := mutate(NewStoreTx(tx))
	if err != nil {
		return domain.Schedule{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, scheduleEvent(mutated, actor, action)); err != nil {
		return domain.Schedule{}, fmt.Errorf("record %s audit event: %w", action, err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Schedule{}, fmt.Errorf("commit schedule mutation: %w", err)
	}
	committed = true
	return mutated, nil
}

func scheduleEvent(schedule domain.Schedule, actor domain.Actor, action string) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(schedule.RepositoryID, 10),
		"branch":        schedule.Branch,
		"name":          schedule.Name,
		"kind":          string(schedule.Kind),
		"timezone":      schedule.Timezone,
		"reason":        schedule.Reason,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      action,
		SubjectType: audit.SubjectTypeSchedule,
		SubjectID:   strconv.FormatInt(schedule.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}
