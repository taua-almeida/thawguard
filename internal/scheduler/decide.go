package scheduler

import (
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

// BranchState is everything Decide needs to know about one branch: its active
// schedules, their expanded coverage segments, and the live freeze row if one
// exists. It carries no clock and no database handle, so decisions are
// table-testable.
type BranchState struct {
	RepositoryID int64
	Branch       string
	// Schedules are the branch's active schedules, weekly and dated.
	// Suppression is honored here, not by the caller: a suppressed schedule
	// stays in the slice and Decide ignores its current window.
	Schedules []domain.Schedule
	// Segments are the merged coverage segments for those schedules from
	// schedule.ExpandCoverage over [now-CoverageLookback, now+CoverageHorizon).
	Segments []schedule.Segment
	// Live is the branch's active freeze row, if any — manual or materialized.
	Live *domain.BranchFreeze
}

// DecisionAction is what the materializer should do for one branch.
type DecisionAction string

const (
	// DecisionNone leaves the branch alone: it is either uncovered and thawed,
	// covered and already frozen (union model — any live freeze suffices), or
	// frozen manually where only the operator may thaw it.
	DecisionNone DecisionAction = "none"
	// DecisionCreate freezes the branch because schedule coverage contains now
	// and nothing else keeps it frozen.
	DecisionCreate DecisionAction = "create"
	// DecisionEnd thaws the branch because its live freeze was materialized by
	// a schedule and no active schedule covers now — the coverage shrank, the
	// schedule was paused or deleted mid-window, or a crash orphaned the row.
	DecisionEnd DecisionAction = "end"
	// DecisionUpdate relabels a live materialized freeze in place: coverage
	// still contains now, but the winning source's identity or the union
	// block's end changed — a dated window took over from a weekly rule at
	// midnight, or an added schedule extended the block. Coverage itself never
	// changes here, only attribution and the planned end.
	DecisionUpdate DecisionAction = "update"
)

// Decision is the materializer's plan for one branch.
type Decision struct {
	Action DecisionAction
	// ScheduleID attributes a created or updated freeze to the winning
	// covering schedule: Dated outranks Weekly, ties break to the most
	// recently created schedule. Precedence decides naming only — which name
	// appears on the timeline and in the forge status — never coverage.
	ScheduleID int64
	// ScheduleName is the winning schedule's name, snapshotted onto the
	// freeze row so deleting the schedule mid-window cannot silently relabel
	// an already-posted status.
	ScheduleName string
	// Reason is the winning schedule's freeze reason.
	Reason string
	// PlannedEndsAt is when union coverage over all schedules ends; nil when
	// coverage reaches the expansion horizon (effectively continuous).
	PlannedEndsAt *time.Time
	// EndFreezeID is the live row to end for DecisionEnd.
	EndFreezeID int64
	// UpdateFreezeID is the live row to relabel for DecisionUpdate.
	UpdateFreezeID int64
}

// Decide maps one branch's coverage and live freeze onto an action. windowEnd
// must be the exclusive end of the expansion window that produced
// state.Segments: a union block reaching it is treated as continuous coverage
// with no planned end.
func Decide(now time.Time, windowEnd time.Time, state BranchState) Decision {
	eligible := eligibleSegments(state)
	block, covered := unionBlockContaining(eligible, now)

	if state.Live != nil {
		if !covered {
			if state.Live.ScheduleID != nil {
				return Decision{Action: DecisionEnd, EndFreezeID: state.Live.ID}
			}
			return Decision{Action: DecisionNone}
		}
		if state.Live.ScheduleID == nil {
			// Manual freeze: the operator's row is never touched.
			return Decision{Action: DecisionNone}
		}
		winner, ok := attributingSchedule(state, eligible, now)
		if !ok {
			return Decision{Action: DecisionNone}
		}
		planned := plannedEnd(block, windowEnd)
		if winner.ID == *state.Live.ScheduleID &&
			winner.Name == state.Live.ScheduleName &&
			winner.Reason == state.Live.Reason &&
			plannedEndsEqual(planned, state.Live.PlannedEndsAt) {
			return Decision{Action: DecisionNone}
		}
		return Decision{
			Action:         DecisionUpdate,
			UpdateFreezeID: state.Live.ID,
			ScheduleID:     winner.ID,
			ScheduleName:   winner.Name,
			Reason:         winner.Reason,
			PlannedEndsAt:  planned,
		}
	}
	if !covered {
		return Decision{Action: DecisionNone}
	}

	winner, ok := attributingSchedule(state, eligible, now)
	if !ok {
		// Unreachable when covered, but never create an unattributable row.
		return Decision{Action: DecisionNone}
	}
	return Decision{
		Action:        DecisionCreate,
		ScheduleID:    winner.ID,
		ScheduleName:  winner.Name,
		Reason:        winner.Reason,
		PlannedEndsAt: plannedEnd(block, windowEnd),
	}
}

// plannedEnd converts the union block's end into a planned freeze end: a
// block reaching the expansion window's edge is effectively continuous
// coverage with no planned end.
func plannedEnd(block interval, windowEnd time.Time) *time.Time {
	if block.End.Before(windowEnd) {
		end := block.End
		return &end
	}
	return nil
}

func plannedEndsEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// eligibleSegments drops the windows suppression turns off: while a schedule
// is suppressed, its current window (any segment starting before
// suppressed_until) must not freeze the branch, while windows starting at or
// after suppressed_until resume normally.
func eligibleSegments(state BranchState) []schedule.Segment {
	suppressedUntil := make(map[int64]*time.Time, len(state.Schedules))
	for _, sched := range state.Schedules {
		suppressedUntil[sched.ID] = sched.SuppressedUntil
	}
	eligible := make([]schedule.Segment, 0, len(state.Segments))
	for _, segment := range state.Segments {
		until, known := suppressedUntil[segment.ScheduleID]
		if !known {
			// Segment from a schedule not in state — stale input; ignore it.
			continue
		}
		if until != nil && segment.Start.Before(*until) {
			continue
		}
		eligible = append(eligible, segment)
	}
	return eligible
}

// interval is a schedule-agnostic [Start, End) union block.
type interval struct {
	Start time.Time
	End   time.Time
}

// unionBlockContaining merges segments across schedules and returns the
// contiguous covered block containing now, if any. Touching segments merge:
// one schedule ending 08:00 and another starting 08:00 is one uninterrupted
// period of "merges blocked".
func unionBlockContaining(segments []schedule.Segment, now time.Time) (interval, bool) {
	if len(segments) == 0 {
		return interval{}, false
	}
	intervals := make([]interval, len(segments))
	for i, segment := range segments {
		intervals[i] = interval{Start: segment.Start, End: segment.End}
	}
	sortIntervals(intervals)
	merged := intervals[:1]
	for _, current := range intervals[1:] {
		last := &merged[len(merged)-1]
		if !current.Start.After(last.End) {
			if current.End.After(last.End) {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}
	for _, block := range merged {
		if !block.Start.After(now) && block.End.After(now) {
			return block, true
		}
	}
	return interval{}, false
}

func sortIntervals(intervals []interval) {
	for i := 1; i < len(intervals); i++ {
		for j := i; j > 0 && intervals[j].Start.Before(intervals[j-1].Start); j-- {
			intervals[j], intervals[j-1] = intervals[j-1], intervals[j]
		}
	}
}

// attributingSchedule picks which schedule the freeze names, by peer
// precedence among schedules with an eligible segment containing now: Dated
// outranks Weekly, ties break to the most recently created schedule (then
// highest ID for determinism). Precedence decides naming only — which name
// appears on the timeline and in the forge status description — it never
// changes coverage.
func attributingSchedule(state BranchState, eligible []schedule.Segment, now time.Time) (domain.Schedule, bool) {
	byID := make(map[int64]domain.Schedule, len(state.Schedules))
	for _, sched := range state.Schedules {
		byID[sched.ID] = sched
	}
	var winner domain.Schedule
	found := false
	for _, segment := range eligible {
		if segment.Start.After(now) || !segment.End.After(now) {
			continue
		}
		sched, ok := byID[segment.ScheduleID]
		if !ok {
			continue
		}
		if !found || Outranks(sched, winner) {
			winner = sched
			found = true
		}
	}
	return winner, found
}

// Outranks reports whether schedule a beats schedule b for freeze
// attribution: Dated outranks Weekly, ties break to the most recently created
// schedule, then to the highest id. It decides naming only, never coverage;
// the web timeline shares it so labels match the forge status.
func Outranks(a, b domain.Schedule) bool {
	if (a.Kind == domain.ScheduleKindDated) != (b.Kind == domain.ScheduleKindDated) {
		return a.Kind == domain.ScheduleKindDated
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return a.ID > b.ID
}
