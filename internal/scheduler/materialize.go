package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

// ScheduleSource lists the active weekly schedules whose coverage the
// materializer turns into freeze rows.
type ScheduleSource interface {
	ListActiveWeeklyCoverages(ctx context.Context) ([]schedule.Coverage, error)
}

// FreezeStore is the freeze surface the materializer drives. CreateActive and
// EndMaterialized must publish enforcement state the same way operator-driven
// freezes do; EndMaterialized must end without triggering manual-end
// suppression — a lapse in coverage is the schedule's own doing, not an
// operator overriding it.
type FreezeStore interface {
	GetActiveForBranch(ctx context.Context, repositoryID int64, branch string) (domain.BranchFreeze, bool, error)
	ListActiveMaterialized(ctx context.Context) ([]domain.BranchFreeze, error)
	CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error)
	EndMaterialized(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

// Materializer reconciles active weekly schedule coverage into ordinary
// branch_freezes rows: covered branches get a live linked row, linked rows
// whose coverage lapsed get ended. It is idempotent — every run recomputes
// the desired state from scratch, so restarts and double ticks are safe.
type Materializer struct {
	schedules ScheduleSource
	freezes   FreezeStore
	clock     Clock
	logger    *slog.Logger
}

func NewMaterializer(schedules ScheduleSource, freezes FreezeStore, clock Clock, logger *slog.Logger) *Materializer {
	if clock == nil {
		clock = SystemClock{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Materializer{schedules: schedules, freezes: freezes, clock: clock, logger: logger}
}

type branchKey struct {
	RepositoryID int64
	Branch       string
}

// RunOnce reconciles every candidate branch once. Candidates are the branches
// of active weekly schedules plus the branches of live materialized rows, so
// orphaned rows (schedule paused, deleted, or rules removed mid-window) fall
// out of the same decision table as regular coverage. Per-branch failures are
// joined, not fatal: one broken repository must not stall the rest.
func (m *Materializer) RunOnce(ctx context.Context) error {
	if m == nil || m.schedules == nil || m.freezes == nil {
		return nil
	}
	now := m.clock.Now().UTC()
	windowStart := now.Add(-schedule.CoverageLookback)
	windowEnd := now.Add(schedule.CoverageHorizon)

	coverages, err := m.schedules.ListActiveWeeklyCoverages(ctx)
	if err != nil {
		return fmt.Errorf("list active weekly coverages: %w", err)
	}
	segments, _, err := schedule.ExpandCoverage(coverages, windowStart, windowEnd)
	if err != nil {
		return fmt.Errorf("expand schedule coverage: %w", err)
	}
	liveMaterialized, err := m.freezes.ListActiveMaterialized(ctx)
	if err != nil {
		return fmt.Errorf("list active materialized freezes: %w", err)
	}

	schedulesByBranch := make(map[branchKey][]domain.Schedule)
	for _, coverage := range coverages {
		key := branchKey{RepositoryID: coverage.Schedule.RepositoryID, Branch: coverage.Schedule.Branch}
		schedulesByBranch[key] = append(schedulesByBranch[key], coverage.Schedule)
	}
	candidates := make(map[branchKey]struct{}, len(schedulesByBranch))
	for key := range schedulesByBranch {
		candidates[key] = struct{}{}
	}
	for _, live := range liveMaterialized {
		candidates[branchKey{RepositoryID: live.RepositoryID, Branch: live.Branch}] = struct{}{}
	}
	keys := make([]branchKey, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].RepositoryID != keys[j].RepositoryID {
			return keys[i].RepositoryID < keys[j].RepositoryID
		}
		return keys[i].Branch < keys[j].Branch
	})

	var joined error
	for _, key := range keys {
		if err := m.reconcileBranch(ctx, now, windowEnd, key, schedulesByBranch[key], segments); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func (m *Materializer) reconcileBranch(ctx context.Context, now, windowEnd time.Time, key branchKey, branchSchedules []domain.Schedule, allSegments []schedule.Segment) error {
	scheduleIDs := make(map[int64]struct{}, len(branchSchedules))
	for _, sched := range branchSchedules {
		scheduleIDs[sched.ID] = struct{}{}
	}
	branchSegments := make([]schedule.Segment, 0)
	for _, segment := range allSegments {
		if _, ok := scheduleIDs[segment.ScheduleID]; ok {
			branchSegments = append(branchSegments, segment)
		}
	}

	state := BranchState{
		RepositoryID: key.RepositoryID,
		Branch:       key.Branch,
		Schedules:    branchSchedules,
		Segments:     branchSegments,
	}
	live, found, err := m.freezes.GetActiveForBranch(ctx, key.RepositoryID, key.Branch)
	if err != nil {
		return fmt.Errorf("load active freeze for %s#%d: %w", key.Branch, key.RepositoryID, err)
	}
	if found {
		state.Live = &live
	}

	decision := Decide(now, windowEnd, state)
	switch decision.Action {
	case DecisionCreate:
		params := freeze.CreateParams{
			RepositoryID:  key.RepositoryID,
			Branch:        key.Branch,
			Reason:        decision.Reason,
			PlannedEndsAt: decision.PlannedEndsAt,
			ScheduleID:    &decision.ScheduleID,
		}
		if _, err := m.freezes.CreateActive(ctx, params, materializerActor); err != nil {
			// Enforcement not active, branch no longer managed, or a race
			// with an operator freezing manually: skip and retry next tick.
			var validation freeze.ValidationError
			if errors.As(err, &validation) {
				m.logger.Warn("schedule materialization skipped",
					"repository_id", key.RepositoryID, "branch", key.Branch,
					"schedule_id", decision.ScheduleID, "reason", validation.Message)
				return nil
			}
			return fmt.Errorf("materialize freeze for %s#%d: %w", key.Branch, key.RepositoryID, err)
		}
	case DecisionEnd:
		if _, err := m.freezes.EndMaterialized(ctx, decision.EndFreezeID, materializerActor); err != nil {
			// A race with an operator ending the freeze first: skip.
			var validation freeze.ValidationError
			if errors.As(err, &validation) {
				m.logger.Warn("schedule dematerialization skipped",
					"repository_id", key.RepositoryID, "branch", key.Branch,
					"freeze_id", decision.EndFreezeID, "reason", validation.Message)
				return nil
			}
			return fmt.Errorf("end materialized freeze %d: %w", decision.EndFreezeID, err)
		}
	case DecisionNone:
	}
	return nil
}

var materializerActor = domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}
