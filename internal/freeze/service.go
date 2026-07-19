package freeze

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Get(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	return NewStore(s.db).Get(ctx, id)
}

func (s *Service) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListActive(ctx)
}

func (s *Service) ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListScheduled(ctx, limit)
}

func (s *Service) ListScheduledPage(ctx context.Context, status domain.BranchFreezeStatus, offset, limit int) ([]domain.BranchFreeze, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListScheduledPage(ctx, status, offset, limit)
}

func (s *Service) ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListDueScheduled(ctx, limit)
}

func (s *Service) ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListDuePlannedUnfreezes(ctx, limit)
}

func (s *Service) ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListNeedsRecompute(ctx, limit)
}

func (s *Service) MarkRecomputed(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	return NewStore(s.db).MarkRecomputed(ctx, id)
}

func (s *Service) MarkRepositoryRecomputed(ctx context.Context, repositoryID int64) error {
	if s == nil || s.db == nil {
		return errors.New("freeze service has no database")
	}
	return NewStore(s.db).MarkRepositoryRecomputed(ctx, repositoryID)
}

func (s *Service) CreateActive(ctx context.Context, params CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin freeze creation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	params.CreatedByUserID = actor.UserID
	params.CreatedByKind = actor.Kind
	created, err := NewStoreTx(tx).CreateActive(ctx, params)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, branchFreezeCreatedEvent(created, actor)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record branch_freeze.created audit event: %w", err)
	}
	if _, err := jobs.NewStoreTx(tx).EnqueueReconciliation(ctx, created.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit freeze creation: %w", err)
	}
	committed = true
	return created, nil
}

func (s *Service) CreateScheduled(ctx context.Context, params ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin scheduled freeze creation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	params.CreatedByUserID = actor.UserID
	params.CreatedByKind = actor.Kind
	created, err := NewStoreTx(tx).CreateScheduled(ctx, params)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, scheduledFreezeEvent(created, actor, audit.ActionFreezeScheduleCreated)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record freeze_schedule.created audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit scheduled freeze creation: %w", err)
	}
	committed = true
	return created, nil
}

func (s *Service) End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return s.close(ctx, id, actor, domain.BranchFreezeStatusEnded)
}

func (s *Service) Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return s.close(ctx, id, actor, domain.BranchFreezeStatusCancelled)
}

func (s *Service) CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	return s.withScheduledFreezeAudit(ctx, id, actor, audit.ActionFreezeScheduleCancelled, false, func(store *Store) (domain.BranchFreeze, error) {
		return store.CancelScheduled(ctx, id)
	})
}

func (s *Service) EditScheduled(ctx context.Context, params EditScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	if params.ID <= 0 {
		return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is required"}
	}
	before, err := NewStore(s.db).Get(ctx, params.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BranchFreeze{}, ValidationError{Message: "scheduled freeze is no longer pending"}
	}
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("load scheduled freeze before edit: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin scheduled freeze edit: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	store := NewStoreTx(tx)
	updated, err := store.editScheduled(ctx, params, &before.UpdatedAt)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, scheduledFreezeUpdatedEvent(before, updated, actor)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record freeze_schedule.updated audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit scheduled freeze edit: %w", err)
	}
	committed = true
	return updated, nil
}

func (s *Service) ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	return s.withScheduledFreezeAudit(ctx, id, actor, audit.ActionFreezeScheduleActivated, true, func(store *Store) (domain.BranchFreeze, error) {
		return store.ActivateScheduled(ctx, id)
	})
}

func (s *Service) StartScheduledNow(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	return s.withScheduledFreezeAudit(ctx, id, actor, audit.ActionFreezeScheduleStartedNow, true, func(store *Store) (domain.BranchFreeze, error) {
		return store.StartScheduledNow(ctx, id)
	})
}

func (s *Service) ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin planned unfreeze: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	ended, err := NewStoreTx(tx).ExecutePlannedUnfreeze(ctx, id)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	action := audit.ActionBranchFreezePlannedUnfreeze
	if ended.Scheduled {
		action = audit.ActionFreezeSchedulePlannedUnfreeze
	}
	if err := audit.NewStoreTx(tx).Record(ctx, scheduledFreezeEvent(ended, actor, action)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record planned unfreeze audit event: %w", err)
	}
	if _, err := jobs.NewStoreTx(tx).EnqueueReconciliation(ctx, ended.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit planned unfreeze: %w", err)
	}
	committed = true
	return ended, nil
}

func (s *Service) withScheduledFreezeAudit(ctx context.Context, id int64, actor domain.Actor, action string, enqueue bool, mutate func(*Store) (domain.BranchFreeze, error)) (domain.BranchFreeze, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin scheduled freeze update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	updated, err := mutate(NewStoreTx(tx))
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, scheduledFreezeEvent(updated, actor, action)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record scheduled freeze audit event: %w", err)
	}
	if enqueue {
		if _, err := jobs.NewStoreTx(tx).EnqueueReconciliation(ctx, updated.RepositoryID); err != nil {
			return domain.BranchFreeze{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit scheduled freeze update: %w", err)
	}
	committed = true
	return updated, nil
}

func (s *Service) close(ctx context.Context, id int64, actor domain.Actor, status domain.BranchFreezeStatus) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin freeze close: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	closed, err := NewStoreTx(tx).closeActive(ctx, CloseParams{ID: id, Status: status})
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, branchFreezeClosedEvent(closed, actor)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record branch freeze close audit event: %w", err)
	}
	if _, err := jobs.NewStoreTx(tx).EnqueueReconciliation(ctx, closed.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit freeze close: %w", err)
	}
	committed = true
	return closed, nil
}

func branchFreezeCreatedEvent(freeze domain.BranchFreeze, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(freeze.RepositoryID, 10),
		"branch":        freeze.Branch,
		"status":        string(freeze.Status),
		"reason":        freeze.Reason,
	}
	if freeze.PlannedEndsAt != nil {
		details["planned_ends_at"] = freeze.PlannedEndsAt.UTC().Format(time.RFC3339Nano)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionBranchFreezeCreated,
		SubjectType: audit.SubjectTypeBranchFreeze,
		SubjectID:   strconv.FormatInt(freeze.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func branchFreezeClosedEvent(freeze domain.BranchFreeze, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(freeze.RepositoryID, 10),
		"branch":        freeze.Branch,
		"status":        string(freeze.Status),
		"reason":        freeze.Reason,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      branchFreezeCloseAction(freeze.Status),
		SubjectType: audit.SubjectTypeBranchFreeze,
		SubjectID:   strconv.FormatInt(freeze.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func scheduledFreezeEvent(freeze domain.BranchFreeze, actor domain.Actor, action string) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(freeze.RepositoryID, 10),
		"branch":        freeze.Branch,
		"status":        string(freeze.Status),
		"reason":        freeze.Reason,
	}
	if freeze.StartsAt != nil {
		details["starts_at"] = freeze.StartsAt.UTC().Format(time.RFC3339Nano)
	}
	if freeze.PlannedEndsAt != nil {
		details["planned_ends_at"] = freeze.PlannedEndsAt.UTC().Format(time.RFC3339Nano)
	}
	if freeze.EndsAt != nil {
		details["ends_at"] = freeze.EndsAt.UTC().Format(time.RFC3339Nano)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      action,
		SubjectType: audit.SubjectTypeBranchFreeze,
		SubjectID:   strconv.FormatInt(freeze.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func scheduledFreezeUpdatedEvent(before, after domain.BranchFreeze, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":             actor.Kind,
		"actor_role":             actor.Role,
		"repository_id":          strconv.FormatInt(after.RepositoryID, 10),
		"branch":                 after.Branch,
		"status":                 string(after.Status),
		"reason_before":          scheduleReasonDetail(before.Reason),
		"reason_after":           scheduleReasonDetail(after.Reason),
		"starts_at_before":       scheduleTimeDetail(before.StartsAt),
		"starts_at_after":        scheduleTimeDetail(after.StartsAt),
		"planned_ends_at_before": scheduleTimeDetail(before.PlannedEndsAt),
		"planned_ends_at_after":  scheduleTimeDetail(after.PlannedEndsAt),
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionFreezeScheduleUpdated,
		SubjectType: audit.SubjectTypeBranchFreeze,
		SubjectID:   strconv.FormatInt(after.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func scheduleReasonDetail(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > scheduledFreezeReasonMaxLength {
		return "unavailable"
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "unavailable"
		}
	}
	return value
}

func scheduleTimeDetail(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func branchFreezeCloseAction(status domain.BranchFreezeStatus) string {
	if status == domain.BranchFreezeStatusCancelled {
		return audit.ActionBranchFreezeCancelled
	}
	return audit.ActionBranchFreezeEnded
}
