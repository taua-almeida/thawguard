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
	"github.com/taua-almeida/thawguard/internal/freeze"
)

// CoverageLookback and CoverageHorizon bound every materialization-facing
// expansion window around now. Lookback exceeds the longest possible segment
// (a rule wraps at most 7 days), so a segment containing now always has its
// true start inside the window; the horizon bounds how far ahead planned ends
// and suppression are computed.
const (
	CoverageLookback = 8 * 24 * time.Hour
	CoverageHorizon  = 30 * 24 * time.Hour
)

// Service wraps Store so every schedule mutation and its audit event commit
// in one transaction, mirroring freeze.Service.
type Service struct {
	db  *sql.DB
	now func() time.Time
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db, now: func() time.Time { return time.Now().UTC() }}
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

// Delete removes a schedule and, in the same transaction, ends any live
// freeze it materialized: ON DELETE SET NULL alone would leave the branch
// frozen by a row no schedule owns and no window will ever end.
func (s *Service) Delete(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	var deleted domain.Schedule
	err := s.transactTx(ctx, func(tx *sql.Tx, store *Store, recorder *audit.Store) error {
		if _, _, err := freeze.CloseLinkedActiveTx(ctx, tx, id, actor); err != nil {
			return err
		}
		var err error
		if deleted, err = store.Delete(ctx, id); err != nil {
			return err
		}
		if err := recorder.Record(ctx, scheduleEvent(deleted, actor, audit.ActionScheduleDeleted)); err != nil {
			return fmt.Errorf("record %s audit event: %w", audit.ActionScheduleDeleted, err)
		}
		return nil
	})
	if err != nil {
		return domain.Schedule{}, err
	}
	return deleted, nil
}

// Activate enables a schedule's windows and clears any suppression. A
// schedule with nothing to expand — a weekly schedule with no rules, a dated
// schedule with no windows — is rejected: activating it would claim coverage
// that cannot exist, and the UI disables the button with the same reason.
func (s *Service) Activate(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	return s.withAudit(ctx, actor, audit.ActionScheduleActivated, func(store *Store) (domain.Schedule, error) {
		schedule, err := store.Get(ctx, id)
		if err != nil {
			return domain.Schedule{}, err
		}
		switch schedule.Kind {
		case domain.ScheduleKindWeekly:
			rules, err := store.ListRules(ctx, id)
			if err != nil {
				return domain.Schedule{}, err
			}
			if len(rules) == 0 {
				return domain.Schedule{}, ValidationError{Message: "add at least one rule before activating"}
			}
		case domain.ScheduleKindDated:
			windows, err := store.ListWindows(ctx, id)
			if err != nil {
				return domain.Schedule{}, err
			}
			if len(windows) == 0 {
				return domain.Schedule{}, ValidationError{Message: "add at least one date window before activating"}
			}
		}
		return store.SetActive(ctx, id, true)
	})
}

// Pause disables a schedule's windows and, in the same transaction, ends any
// live freeze it materialized — a paused schedule never keeps a branch frozen.
func (s *Service) Pause(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error) {
	var paused domain.Schedule
	err := s.transactTx(ctx, func(tx *sql.Tx, store *Store, recorder *audit.Store) error {
		var err error
		if paused, err = store.SetActive(ctx, id, false); err != nil {
			return err
		}
		if err := recorder.Record(ctx, scheduleEvent(paused, actor, audit.ActionSchedulePaused)); err != nil {
			return fmt.Errorf("record %s audit event: %w", audit.ActionSchedulePaused, err)
		}
		if _, _, err := freeze.CloseLinkedActiveTx(ctx, tx, id, actor); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return domain.Schedule{}, err
	}
	return paused, nil
}

// ListActiveCoverages returns the materializer's input outside any
// transaction.
func (s *Service) ListActiveCoverages(ctx context.Context) ([]Coverage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule service has no database")
	}
	return NewStore(s.db).ListActiveCoverages(ctx)
}

// EndMaterializedFreeze implements manual "End freeze" on a schedule-created
// occurrence: the freeze row ends now, and every active schedule currently
// covering the branch is suppressed until its own current window's end, so
// the branch stays thawed until the next scheduled window. All of it — the
// freeze close, each suppression, and their audit events — commits in one
// transaction.
func (s *Service) EndMaterializedFreeze(ctx context.Context, freezeID int64, actor domain.Actor) (domain.BranchFreeze, error) {
	var ended domain.BranchFreeze
	err := s.transactTx(ctx, func(tx *sql.Tx, store *Store, recorder *audit.Store) error {
		closed, err := freeze.CloseActiveTx(ctx, tx, freezeID, actor, domain.BranchFreezeStatusEnded)
		if err != nil {
			return err
		}
		if closed.ScheduleID == nil {
			return ValidationError{Message: "freeze was not created by a recurring schedule"}
		}
		ended = closed

		coverages, err := store.ListActiveCoverages(ctx)
		if err != nil {
			return err
		}
		branchCoverages := make([]Coverage, 0, len(coverages))
		for _, coverage := range coverages {
			if coverage.Schedule.RepositoryID == closed.RepositoryID && coverage.Schedule.Branch == closed.Branch {
				branchCoverages = append(branchCoverages, coverage)
			}
		}
		now := s.now().UTC()
		segments, _, err := ExpandCoverage(branchCoverages, now.Add(-CoverageLookback), now.Add(CoverageHorizon))
		if err != nil {
			return err
		}
		for _, coverage := range branchCoverages {
			current, ok := containingSegment(segments, coverage.Schedule.ID, now)
			if !ok {
				continue
			}
			suppressed, err := store.Suppress(ctx, coverage.Schedule.ID, current.End)
			if err != nil {
				return err
			}
			resumesAt := nextSegmentStart(segments, coverage.Schedule.ID, current.End)
			event := scheduleSuppressedEvent(suppressed, closed, current.End, resumesAt, actor)
			if err := recorder.Record(ctx, event); err != nil {
				return fmt.Errorf("record %s audit event: %w", audit.ActionScheduleSuppressed, err)
			}
		}
		return nil
	})
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	return ended, nil
}

// containingSegment finds the schedule's merged segment covering the instant.
func containingSegment(segments []Segment, scheduleID int64, at time.Time) (Segment, bool) {
	for _, segment := range segments {
		if segment.ScheduleID != scheduleID {
			continue
		}
		if !segment.Start.After(at) && segment.End.After(at) {
			return segment, true
		}
	}
	return Segment{}, false
}

// nextSegmentStart finds when the schedule next covers the branch at or after
// the instant; nil when no window starts inside the expansion horizon.
func nextSegmentStart(segments []Segment, scheduleID int64, after time.Time) *time.Time {
	for _, segment := range segments {
		if segment.ScheduleID != scheduleID {
			continue
		}
		if !segment.Start.Before(after) {
			start := segment.Start
			return &start
		}
	}
	return nil
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

func (s *Service) ListWindows(ctx context.Context, scheduleID int64) ([]domain.ScheduleDatedWindow, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule service has no database")
	}
	return NewStore(s.db).ListWindows(ctx, scheduleID)
}

// AddWindow records one audit event per form submission, mirroring AddRules:
// one submitted window is a single operator action. The bool passes through
// the store's already-started determination so callers surface the
// coverage-begins-immediately note from the same clock reading that accepted
// the window.
func (s *Service) AddWindow(ctx context.Context, params AddWindowParams, actor domain.Actor) (domain.ScheduleDatedWindow, bool, error) {
	var added domain.ScheduleDatedWindow
	var alreadyStarted bool
	err := s.transact(ctx, func(store *Store, recorder *audit.Store) error {
		var err error
		if added, alreadyStarted, err = store.AddWindow(ctx, params); err != nil {
			return err
		}
		schedule, err := store.Get(ctx, params.ScheduleID)
		if err != nil {
			return err
		}
		event := scheduleWindowEvent(schedule, added, actor, audit.ActionScheduleWindowAdded)
		if err := recorder.Record(ctx, event); err != nil {
			return fmt.Errorf("record %s audit event: %w", audit.ActionScheduleWindowAdded, err)
		}
		return nil
	})
	if err != nil {
		return domain.ScheduleDatedWindow{}, false, err
	}
	return added, alreadyStarted, nil
}

func (s *Service) DeleteWindow(ctx context.Context, scheduleID, windowID int64, actor domain.Actor) (domain.ScheduleDatedWindow, error) {
	var removed domain.ScheduleDatedWindow
	err := s.transact(ctx, func(store *Store, recorder *audit.Store) error {
		schedule, err := store.Get(ctx, scheduleID)
		if err != nil {
			return err
		}
		if removed, err = store.DeleteWindow(ctx, scheduleID, windowID); err != nil {
			return err
		}
		event := scheduleWindowEvent(schedule, removed, actor, audit.ActionScheduleWindowRemoved)
		if err := recorder.Record(ctx, event); err != nil {
			return fmt.Errorf("record %s audit event: %w", audit.ActionScheduleWindowRemoved, err)
		}
		return nil
	})
	if err != nil {
		return domain.ScheduleDatedWindow{}, err
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
	return s.transactTx(ctx, func(_ *sql.Tx, store *Store, recorder *audit.Store) error {
		return fn(store, recorder)
	})
}

// transactTx additionally exposes the raw transaction for mutations that must
// commit a freeze close (via the freeze package's tx helpers) atomically with
// the schedule change.
func (s *Service) transactTx(ctx context.Context, fn func(tx *sql.Tx, store *Store, recorder *audit.Store) error) error {
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

	if err := fn(tx, NewStoreTx(tx), audit.NewStoreTx(tx)); err != nil {
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

// scheduleWindowEvent describes one window addition or removal. starts_at and
// ends_at are the window's literal local wall clocks in the schedule's
// timezone, not UTC instants, matching how the window is defined.
func scheduleWindowEvent(schedule domain.Schedule, window domain.ScheduleDatedWindow, actor domain.Actor, action string) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(schedule.RepositoryID, 10),
		"branch":        schedule.Branch,
		"name":          schedule.Name,
		"window_name":   window.Name,
		"starts_at":     window.StartsAt,
		"ends_at":       window.EndsAt,
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

// scheduleSuppressedEvent records the manual end of a materialized freeze
// from the schedule's point of view: which occurrence was ended, until when
// the schedule stays quiet, and when it next freezes the branch again.
func scheduleSuppressedEvent(schedule domain.Schedule, endedFreeze domain.BranchFreeze, suppressedUntil time.Time, resumesAt *time.Time, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":       actor.Kind,
		"actor_role":       actor.Role,
		"repository_id":    strconv.FormatInt(schedule.RepositoryID, 10),
		"branch":           schedule.Branch,
		"name":             schedule.Name,
		"ended_freeze_id":  strconv.FormatInt(endedFreeze.ID, 10),
		"suppressed_until": suppressedUntil.UTC().Format(time.RFC3339Nano),
	}
	if resumesAt != nil {
		details["resumes_at"] = resumesAt.UTC().Format(time.RFC3339Nano)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionScheduleSuppressed,
		SubjectType: audit.SubjectTypeSchedule,
		SubjectID:   strconv.FormatInt(schedule.ID, 10),
		DetailsJSON: string(detailsJSON),
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
