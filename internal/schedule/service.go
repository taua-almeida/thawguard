package schedule

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

func (s *Service) ListRules(ctx context.Context, scheduleID int64) ([]domain.ScheduleWeeklyRule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule service has no database")
	}
	return NewStore(s.db).ListRules(ctx, scheduleID)
}

// AddRules records one audit event per form submission, not one per inserted
// row: a multi-day submission is a single operator action.
func (s *Service) AddRules(ctx context.Context, params AddRulesParams, actor domain.Actor) ([]domain.ScheduleWeeklyRule, error) {
	var added []domain.ScheduleWeeklyRule
	err := s.transact(ctx, func(store *Store, recorder *audit.Store) error {
		var err error
		if added, err = store.AddRules(ctx, params); err != nil {
			return err
		}
		schedule, err := store.Get(ctx, params.ScheduleID)
		if err != nil {
			return err
		}
		event := scheduleRulesEvent(schedule, added, actor, audit.ActionScheduleRulesAdded)
		if err := recorder.Record(ctx, event); err != nil {
			return fmt.Errorf("record %s audit event: %w", audit.ActionScheduleRulesAdded, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return added, nil
}

func (s *Service) DeleteRule(ctx context.Context, scheduleID, ruleID int64, actor domain.Actor) (domain.ScheduleWeeklyRule, error) {
	var removed domain.ScheduleWeeklyRule
	err := s.transact(ctx, func(store *Store, recorder *audit.Store) error {
		schedule, err := store.Get(ctx, scheduleID)
		if err != nil {
			return err
		}
		if removed, err = store.DeleteRule(ctx, scheduleID, ruleID); err != nil {
			return err
		}
		event := scheduleRulesEvent(schedule, []domain.ScheduleWeeklyRule{removed}, actor, audit.ActionScheduleRuleRemoved)
		if err := recorder.Record(ctx, event); err != nil {
			return fmt.Errorf("record %s audit event: %w", audit.ActionScheduleRuleRemoved, err)
		}
		return nil
	})
	if err != nil {
		return domain.ScheduleWeeklyRule{}, err
	}
	return removed, nil
}

func (s *Service) withAudit(ctx context.Context, actor domain.Actor, action string, mutate func(*Store) (domain.Schedule, error)) (domain.Schedule, error) {
	var mutated domain.Schedule
	err := s.transact(ctx, func(store *Store, recorder *audit.Store) error {
		var err error
		if mutated, err = mutate(store); err != nil {
			return err
		}
		if err := recorder.Record(ctx, scheduleEvent(mutated, actor, action)); err != nil {
			return fmt.Errorf("record %s audit event: %w", action, err)
		}
		return nil
	})
	if err != nil {
		return domain.Schedule{}, err
	}
	return mutated, nil
}

// transact runs one schedule mutation and its audit recording in a single
// committed transaction, mirroring freeze.Service.
func (s *Service) transact(ctx context.Context, fn func(store *Store, recorder *audit.Store) error) error {
	if s == nil || s.db == nil {
		return errors.New("schedule service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schedule mutation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(NewStoreTx(tx), audit.NewStoreTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schedule mutation: %w", err)
	}
	committed = true
	return nil
}

// scheduleRulesEvent describes one rule submission or removal. Every rule in
// the slice shares the same times and end-day relation by construction, so
// the details stay one flat human-readable set.
func scheduleRulesEvent(schedule domain.Schedule, rules []domain.ScheduleWeeklyRule, actor domain.Actor, action string) audit.Event {
	days := make([]string, 0, len(rules))
	for _, rule := range rules {
		days = append(days, WeekdayShort(rule.StartWeekday))
	}
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(schedule.RepositoryID, 10),
		"branch":        schedule.Branch,
		"name":          schedule.Name,
		"days":          strings.Join(days, ", "),
		"start_time":    rules[0].StartTime,
		"end_time":      rules[0].EndTime,
		"end_day":       ruleEndDayLabel(rules),
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

// WeekdayShort is the three-letter weekday label used across rule displays
// and audit details ("Mon", "Tue", ...).
func WeekdayShort(weekday time.Weekday) string {
	return weekday.String()[:3]
}

// ruleEndDayLabel names how the rules' end weekday relates to their start:
// "same day", "next day", or the end weekday's full name.
func ruleEndDayLabel(rules []domain.ScheduleWeeklyRule) string {
	same, next := true, true
	for _, rule := range rules {
		wrap := RuleWrapDays(rule)
		same = same && wrap == 0
		next = next && wrap == 1
	}
	switch {
	case same:
		return "same day"
	case next:
		return "next day"
	default:
		return rules[0].EndWeekday.String()
	}
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
