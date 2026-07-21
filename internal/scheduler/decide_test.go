package scheduler

import (
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

var decideNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// decideWindowEnd mirrors the materializer's expansion horizon so
// horizon-touching blocks are exercised with realistic inputs.
var decideWindowEnd = decideNow.Add(schedule.CoverageHorizon)

func at(offset time.Duration) time.Time { return decideNow.Add(offset) }

func timePtr(t time.Time) *time.Time { return &t }

func segment(scheduleID int64, start, end time.Time) schedule.Segment {
	return schedule.Segment{ScheduleID: scheduleID, Start: start, End: end}
}

func activeSchedule(id int64, reason string) domain.Schedule {
	return domain.Schedule{ID: id, RepositoryID: 1, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC", Reason: reason, Active: true}
}

func TestDecide(t *testing.T) {
	materialized := &domain.BranchFreeze{ID: 40, RepositoryID: 1, Branch: "main", ScheduleID: int64Ptr(7)}
	manual := &domain.BranchFreeze{ID: 41, RepositoryID: 1, Branch: "main"}

	cases := []struct {
		name  string
		state BranchState
		want  Decision
	}{
		{
			name:  "no coverage and no live freeze does nothing",
			state: BranchState{Schedules: []domain.Schedule{activeSchedule(7, "")}},
			want:  Decision{Action: DecisionNone},
		},
		{
			name: "covered branch without a live freeze is frozen with attribution",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "Nightly lock")},
				Segments:  []schedule.Segment{segment(7, at(-2*time.Hour), at(3*time.Hour))},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, Reason: "Nightly lock", PlannedEndsAt: timePtr(at(3 * time.Hour))},
		},
		{
			name: "covered branch with any live freeze is left alone",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "")},
				Segments:  []schedule.Segment{segment(7, at(-2*time.Hour), at(3*time.Hour))},
				Live:      manual,
			},
			want: Decision{Action: DecisionNone},
		},
		{
			name: "uncovered materialized freeze is ended",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "")},
				Segments:  []schedule.Segment{segment(7, at(4*time.Hour), at(8*time.Hour))},
				Live:      materialized,
			},
			want: Decision{Action: DecisionEnd, EndFreezeID: 40},
		},
		{
			name: "orphaned materialized freeze with no schedules left is ended",
			state: BranchState{
				Live: materialized,
			},
			want: Decision{Action: DecisionEnd, EndFreezeID: 40},
		},
		{
			name: "uncovered manual freeze is never ended",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "")},
				Live:      manual,
			},
			want: Decision{Action: DecisionNone},
		},
		{
			name: "suppressed schedule's current window does not freeze",
			state: BranchState{
				Schedules: []domain.Schedule{func() domain.Schedule {
					sched := activeSchedule(7, "")
					sched.SuppressedUntil = timePtr(at(3 * time.Hour))
					return sched
				}()},
				Segments: []schedule.Segment{segment(7, at(-2*time.Hour), at(3*time.Hour))},
			},
			want: Decision{Action: DecisionNone},
		},
		{
			name: "window starting at suppressed_until resumes normally",
			state: BranchState{
				Schedules: []domain.Schedule{func() domain.Schedule {
					sched := activeSchedule(7, "Resumed lock")
					sched.SuppressedUntil = timePtr(at(-time.Hour))
					return sched
				}()},
				Segments: []schedule.Segment{segment(7, at(-time.Hour), at(3*time.Hour))},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, Reason: "Resumed lock", PlannedEndsAt: timePtr(at(3 * time.Hour))},
		},
		{
			name: "touching segments from different schedules form one union block",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "First window"), activeSchedule(9, "Second window")},
				Segments: []schedule.Segment{
					segment(9, at(2*time.Hour), at(6*time.Hour)),
					segment(7, at(-2*time.Hour), at(2*time.Hour)),
				},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, Reason: "First window", PlannedEndsAt: timePtr(at(6 * time.Hour))},
		},
		{
			name: "attribution ties on equal starts break to the lowest schedule id",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(9, "Higher id"), activeSchedule(7, "Lower id")},
				Segments: []schedule.Segment{
					segment(9, at(-time.Hour), at(4*time.Hour)),
					segment(7, at(-time.Hour), at(2*time.Hour)),
				},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, Reason: "Lower id", PlannedEndsAt: timePtr(at(4 * time.Hour))},
		},
		{
			name: "suppressed attributing schedule leaves attribution to the other coverer",
			state: BranchState{
				Schedules: []domain.Schedule{
					func() domain.Schedule {
						sched := activeSchedule(7, "Suppressed")
						sched.SuppressedUntil = timePtr(at(2 * time.Hour))
						return sched
					}(),
					activeSchedule(9, "Still covering"),
				},
				Segments: []schedule.Segment{
					segment(7, at(-2*time.Hour), at(2*time.Hour)),
					segment(9, at(-time.Hour), at(4*time.Hour)),
				},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 9, Reason: "Still covering", PlannedEndsAt: timePtr(at(4 * time.Hour))},
		},
		{
			name: "coverage reaching the horizon has no planned end",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "Continuous")},
				Segments:  []schedule.Segment{segment(7, at(-time.Hour), decideWindowEnd)},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, Reason: "Continuous"},
		},
		{
			name: "segments from unknown schedules are ignored",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "")},
				Segments:  []schedule.Segment{segment(99, at(-time.Hour), at(time.Hour))},
			},
			want: Decision{Action: DecisionNone},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(decideNow, decideWindowEnd, tc.state)
			if got.Action != tc.want.Action || got.ScheduleID != tc.want.ScheduleID || got.Reason != tc.want.Reason || got.EndFreezeID != tc.want.EndFreezeID {
				t.Fatalf("Decide() = %+v, want %+v", got, tc.want)
			}
			switch {
			case got.PlannedEndsAt == nil && tc.want.PlannedEndsAt != nil:
				t.Fatalf("expected planned end %v, got none", tc.want.PlannedEndsAt)
			case got.PlannedEndsAt != nil && tc.want.PlannedEndsAt == nil:
				t.Fatalf("expected no planned end, got %v", got.PlannedEndsAt)
			case got.PlannedEndsAt != nil && !got.PlannedEndsAt.Equal(*tc.want.PlannedEndsAt):
				t.Fatalf("planned end = %v, want %v", got.PlannedEndsAt, tc.want.PlannedEndsAt)
			}
		})
	}
}

func int64Ptr(v int64) *int64 { return &v }
