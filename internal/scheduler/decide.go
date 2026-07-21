package scheduler

import (
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

// BranchState is everything Decide needs to know about one branch: its active
// weekly schedules, their expanded coverage segments, and the live freeze row
// if one exists. It carries no clock and no database handle, so decisions are
// table-testable.
type BranchState struct {
	RepositoryID int64
	Branch       string
	// Schedules are the branch's active weekly schedules. Suppression is
	// honored here, not by the caller: a suppressed schedule stays in the
	// slice and Decide ignores its current window.
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
)

// Decision is the materializer's plan for one branch.
type Decision struct {
	Action DecisionAction
	// ScheduleID attributes a created freeze to the covering schedule whose
	// current window started earliest (ties broken by lowest ID).
	ScheduleID int64
	// Reason is the attributing schedule's freeze reason.
	Reason string
	// PlannedEndsAt is when union coverage over all schedules ends; nil when
	// coverage reaches the expansion horizon (effectively continuous).
	PlannedEndsAt *time.Time
	// EndFreezeID is the live row to end for DecisionEnd.
	EndFreezeID int64
}

// Decide maps one branch's coverage and live freeze onto an action. windowEnd
// must be the exclusive end of the expansion window that produced
// state.Segments: a union block reaching it is treated as continuous coverage
// with no planned end.
func Decide(now time.Time, windowEnd time.Time, state BranchState) Decision {
	eligible := eligibleSegments(state)
	block, covered := unionBlockContaining(eligible, now)

	if state.Live != nil {
		if covered {
			return Decision{Action: DecisionNone}
		}
		if state.Live.ScheduleID != nil {
			return Decision{Action: DecisionEnd, EndFreezeID: state.Live.ID}
		}
		return Decision{Action: DecisionNone}
	}
	if !covered {
		return Decision{Action: DecisionNone}
	}

	attributing, ok := attributingSchedule(state, eligible, now)
	if !ok {
		// Unreachable when covered, but never create an unattributable row.
		return Decision{Action: DecisionNone}
	}
	decision := Decision{
		Action:     DecisionCreate,
		ScheduleID: attributing.ID,
		Reason:     attributing.Reason,
	}
	if block.End.Before(windowEnd) {
		end := block.End
		decision.PlannedEndsAt = &end
	}
	return decision
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

// attributingSchedule picks which schedule a created freeze names: the one
// whose eligible window containing now started earliest, ties broken by
// lowest schedule ID for determinism.
func attributingSchedule(state BranchState, eligible []schedule.Segment, now time.Time) (domain.Schedule, bool) {
	byID := make(map[int64]domain.Schedule, len(state.Schedules))
	for _, sched := range state.Schedules {
		byID[sched.ID] = sched
	}
	var best *schedule.Segment
	for i := range eligible {
		segment := &eligible[i]
		if segment.Start.After(now) || !segment.End.After(now) {
			continue
		}
		if best == nil ||
			segment.Start.Before(best.Start) ||
			(segment.Start.Equal(best.Start) && segment.ScheduleID < best.ScheduleID) {
			best = segment
		}
	}
	if best == nil {
		return domain.Schedule{}, false
	}
	sched, ok := byID[best.ScheduleID]
	return sched, ok
}
