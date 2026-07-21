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

func activeDatedSchedule(id int64, name, reason string, createdAt time.Time) domain.Schedule {
	return domain.Schedule{ID: id, RepositoryID: 1, Branch: "main", Name: name, Kind: domain.ScheduleKindDated, Timezone: "UTC", Reason: reason, Active: true, CreatedAt: createdAt}
}

func TestDecide(t *testing.T) {
	materialized := &domain.BranchFreeze{ID: 40, RepositoryID: 1, Branch: "main", ScheduleID: int64Ptr(7)}
	manual := &domain.BranchFreeze{ID: 41, RepositoryID: 1, Branch: "main"}
	// settled matches what the single weekly schedule 7 would attribute right
	// now, so a covered branch carrying it must be left completely alone.
	settled := &domain.BranchFreeze{
		ID: 40, RepositoryID: 1, Branch: "main",
		ScheduleID: int64Ptr(7), ScheduleName: "Nightly release lock",
		Reason: "Nightly lock", PlannedEndsAt: timePtr(at(3 * time.Hour)),
	}

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
			want: Decision{Action: DecisionCreate, ScheduleID: 7, ScheduleName: "Nightly release lock", Reason: "Nightly lock", PlannedEndsAt: timePtr(at(3 * time.Hour))},
		},
		{
			name: "covered branch with a manual live freeze is left alone",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "")},
				Segments:  []schedule.Segment{segment(7, at(-2*time.Hour), at(3*time.Hour))},
				Live:      manual,
			},
			want: Decision{Action: DecisionNone},
		},
		{
			name: "covered materialized freeze with unchanged attribution does nothing",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "Nightly lock")},
				Segments:  []schedule.Segment{segment(7, at(-2*time.Hour), at(3*time.Hour))},
				Live:      settled,
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
			want: Decision{Action: DecisionCreate, ScheduleID: 7, ScheduleName: "Nightly release lock", Reason: "Resumed lock", PlannedEndsAt: timePtr(at(3 * time.Hour))},
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
			// Only schedule 7's segment contains now, so it names the freeze;
			// the planned end still comes from the whole union block.
			want: Decision{Action: DecisionCreate, ScheduleID: 7, ScheduleName: "Nightly release lock", Reason: "First window", PlannedEndsAt: timePtr(at(6 * time.Hour))},
		},
		{
			name: "dated outranks weekly for naming without changing coverage",
			state: BranchState{
				Schedules: []domain.Schedule{
					activeSchedule(7, "Weekly lock"),
					activeDatedSchedule(9, "Christmas maintenance", "Holiday change stop", at(-24*time.Hour)),
				},
				Segments: []schedule.Segment{
					segment(7, at(-2*time.Hour), at(6*time.Hour)),
					segment(9, at(-time.Hour), at(2*time.Hour)),
				},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 9, ScheduleName: "Christmas maintenance", Reason: "Holiday change stop", PlannedEndsAt: timePtr(at(6 * time.Hour))},
		},
		{
			name: "peer ties break to the most recently created schedule",
			state: BranchState{
				Schedules: []domain.Schedule{
					activeDatedSchedule(9, "Older window", "", at(-48*time.Hour)),
					activeDatedSchedule(7, "Newer window", "", at(-24*time.Hour)),
				},
				Segments: []schedule.Segment{
					segment(9, at(-time.Hour), at(4*time.Hour)),
					segment(7, at(-time.Hour), at(2*time.Hour)),
				},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, ScheduleName: "Newer window", PlannedEndsAt: timePtr(at(4 * time.Hour))},
		},
		{
			name: "equal creation times break to the highest schedule id",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(9, "Higher id"), activeSchedule(7, "Lower id")},
				Segments: []schedule.Segment{
					segment(9, at(-time.Hour), at(4*time.Hour)),
					segment(7, at(-time.Hour), at(2*time.Hour)),
				},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 9, ScheduleName: "Nightly release lock", Reason: "Higher id", PlannedEndsAt: timePtr(at(4 * time.Hour))},
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
			want: Decision{Action: DecisionCreate, ScheduleID: 9, ScheduleName: "Nightly release lock", Reason: "Still covering", PlannedEndsAt: timePtr(at(4 * time.Hour))},
		},
		{
			name: "coverage reaching the horizon has no planned end",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "Continuous")},
				Segments:  []schedule.Segment{segment(7, at(-time.Hour), decideWindowEnd)},
			},
			want: Decision{Action: DecisionCreate, ScheduleID: 7, ScheduleName: "Nightly release lock", Reason: "Continuous"},
		},
		{
			name: "winning source change relabels the live freeze in place",
			state: BranchState{
				Schedules: []domain.Schedule{
					activeSchedule(7, "Nightly lock"),
					activeDatedSchedule(9, "Christmas maintenance", "Holiday change stop", at(-24*time.Hour)),
				},
				Segments: []schedule.Segment{
					segment(7, at(-2*time.Hour), at(3*time.Hour)),
					segment(9, at(-time.Hour), at(2*time.Hour)),
				},
				Live: settled,
			},
			want: Decision{Action: DecisionUpdate, UpdateFreezeID: 40, ScheduleID: 9, ScheduleName: "Christmas maintenance", Reason: "Holiday change stop", PlannedEndsAt: timePtr(at(3 * time.Hour))},
		},
		{
			name: "extended union end relabels the planned end in place",
			state: BranchState{
				Schedules: []domain.Schedule{activeSchedule(7, "Nightly lock")},
				Segments: []schedule.Segment{
					segment(7, at(-2*time.Hour), at(3*time.Hour)),
					segment(7, at(3*time.Hour), at(6*time.Hour)),
				},
				Live: settled,
			},
			want: Decision{Action: DecisionUpdate, UpdateFreezeID: 40, ScheduleID: 7, ScheduleName: "Nightly release lock", Reason: "Nightly lock", PlannedEndsAt: timePtr(at(6 * time.Hour))},
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
			if got.Action != tc.want.Action || got.ScheduleID != tc.want.ScheduleID ||
				got.ScheduleName != tc.want.ScheduleName || got.Reason != tc.want.Reason ||
				got.EndFreezeID != tc.want.EndFreezeID || got.UpdateFreezeID != tc.want.UpdateFreezeID {
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
