package schedule

import (
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func weeklyCoverage(timezone string, rules ...domain.ScheduleWeeklyRule) Coverage {
	return Coverage{
		Schedule: domain.Schedule{ID: 1, Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: timezone},
		Rules:    rules,
	}
}

func mustExpand(t *testing.T, coverages []Coverage, from, to time.Time) ([]Segment, []DSTNote) {
	t.Helper()
	segments, notes, err := ExpandCoverage(coverages, from, to)
	if err != nil {
		t.Fatal(err)
	}
	return segments, notes
}

func utc(year int, month time.Month, day, hour, minute int) time.Time {
	return time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
}

func TestExpandSimpleWeeklyRule(t *testing.T) {
	// 2026-07-20 is a Monday.
	coverage := weeklyCoverage("UTC", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "09:00", EndWeekday: time.Monday, EndTime: "17:00",
	})
	segments, notes := mustExpand(t, []Coverage{coverage}, utc(2026, time.July, 20, 0, 0), utc(2026, time.August, 3, 0, 0))
	if len(notes) != 0 {
		t.Fatalf("expected no DST notes, got %+v", notes)
	}
	if len(segments) != 2 {
		t.Fatalf("expected 2 segments, got %+v", segments)
	}
	for i, wantDay := range []int{20, 27} {
		if !segments[i].Start.Equal(utc(2026, time.July, wantDay, 9, 0)) || !segments[i].End.Equal(utc(2026, time.July, wantDay, 17, 0)) {
			t.Fatalf("unexpected segment %d: %+v", i, segments[i])
		}
		if segments[i].ScheduleID != 1 || segments[i].ScheduleName != "Nightly release lock" {
			t.Fatalf("segment %d lost its schedule attribution: %+v", i, segments[i])
		}
	}
}

func TestExpandWrapKeepsTrueStartBeforeWindow(t *testing.T) {
	// São Paulo is a stable UTC-3 (no DST since 2019). 2026-07-17 is a
	// Friday; the window opens mid-weekend on Saturday.
	coverage := weeklyCoverage("America/Sao_Paulo", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Friday, StartTime: "16:00", EndWeekday: time.Monday, EndTime: "08:00",
	})
	from := utc(2026, time.July, 18, 12, 0)
	segments, _ := mustExpand(t, []Coverage{coverage}, from, from.AddDate(0, 0, 8))
	if len(segments) != 2 {
		t.Fatalf("expected 2 weekend segments, got %+v", segments)
	}
	// Friday 16:00 -03 is 19:00 UTC; Monday 08:00 -03 is 11:00 UTC. The
	// first segment began before the window and keeps its true start.
	if !segments[0].Start.Equal(utc(2026, time.July, 17, 19, 0)) || !segments[0].End.Equal(utc(2026, time.July, 20, 11, 0)) {
		t.Fatalf("unexpected first weekend segment: %+v", segments[0])
	}
	if !segments[1].Start.Equal(utc(2026, time.July, 24, 19, 0)) || !segments[1].End.Equal(utc(2026, time.July, 27, 11, 0)) {
		t.Fatalf("unexpected second weekend segment: %+v", segments[1])
	}
}

func TestExpandMergesTouchingRulesAndKeepsGapsDistinct(t *testing.T) {
	coverage := weeklyCoverage("UTC",
		domain.ScheduleWeeklyRule{ID: 1, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "08:00"},
		// Touches the first rule's end exactly: one continuous period.
		domain.ScheduleWeeklyRule{ID: 2, ScheduleID: 1, StartWeekday: time.Tuesday, StartTime: "08:00", EndWeekday: time.Tuesday, EndTime: "12:00"},
		// A separate night with a daytime gap before it stays its own segment.
		domain.ScheduleWeeklyRule{ID: 3, ScheduleID: 1, StartWeekday: time.Wednesday, StartTime: "22:00", EndWeekday: time.Thursday, EndTime: "06:00"},
	)
	segments, _ := mustExpand(t, []Coverage{coverage}, utc(2026, time.July, 20, 0, 0), utc(2026, time.July, 27, 0, 0))
	if len(segments) != 2 {
		t.Fatalf("expected merged Monday-Tuesday plus distinct Wednesday night, got %+v", segments)
	}
	if !segments[0].Start.Equal(utc(2026, time.July, 20, 18, 0)) || !segments[0].End.Equal(utc(2026, time.July, 21, 12, 0)) {
		t.Fatalf("expected touching rules to merge, got %+v", segments[0])
	}
	if !segments[1].Start.Equal(utc(2026, time.July, 22, 22, 0)) || !segments[1].End.Equal(utc(2026, time.July, 23, 6, 0)) {
		t.Fatalf("expected the gapped night to stay distinct, got %+v", segments[1])
	}
}

func TestExpandDoesNotMergeAcrossSchedules(t *testing.T) {
	first := weeklyCoverage("UTC", domain.ScheduleWeeklyRule{ID: 1, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "08:00", EndWeekday: time.Monday, EndTime: "12:00"})
	second := Coverage{
		Schedule: domain.Schedule{ID: 2, Name: "Afternoon lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"},
		Rules:    []domain.ScheduleWeeklyRule{{ID: 2, ScheduleID: 2, StartWeekday: time.Monday, StartTime: "12:00", EndWeekday: time.Monday, EndTime: "16:00"}},
	}
	segments, _ := mustExpand(t, []Coverage{first, second}, utc(2026, time.July, 20, 0, 0), utc(2026, time.July, 21, 0, 0))
	if len(segments) != 2 {
		t.Fatalf("expected one segment per schedule, got %+v", segments)
	}
	if segments[0].ScheduleID != 1 || segments[1].ScheduleID != 2 {
		t.Fatalf("expected segments sorted by start with attribution intact, got %+v", segments)
	}
}

func TestExpandSpringForwardNonexistentStart(t *testing.T) {
	// America/New_York skips 02:00–03:00 on Sunday 2026-03-08 (EST→EDT at
	// 07:00 UTC). A 02:30 start does not exist that day and resolves to the
	// first valid instant, 03:00 EDT.
	coverage := weeklyCoverage("America/New_York", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Sunday, StartTime: "02:30", EndWeekday: time.Sunday, EndTime: "06:00",
	})
	segments, notes := mustExpand(t, []Coverage{coverage}, utc(2026, time.March, 7, 0, 0), utc(2026, time.March, 9, 0, 0))
	if len(segments) != 1 {
		t.Fatalf("expected one segment, got %+v", segments)
	}
	if !segments[0].Start.Equal(utc(2026, time.March, 8, 7, 0)) || !segments[0].End.Equal(utc(2026, time.March, 8, 10, 0)) {
		t.Fatalf("expected coverage 03:00–06:00 EDT, got %+v", segments[0])
	}
	if len(notes) != 1 {
		t.Fatalf("expected one DST note, got %+v", notes)
	}
	note := notes[0]
	if note.Kind != DSTNoteNonexistent || note.Boundary != "start" || note.LocalDate != "2026-03-08" || note.LocalTime != "02:30" || !note.Resolved.Equal(utc(2026, time.March, 8, 7, 0)) {
		t.Fatalf("unexpected DST note: %+v", note)
	}

	// The week after the transition the wall time exists again: no note.
	segments, notes = mustExpand(t, []Coverage{coverage}, utc(2026, time.March, 14, 0, 0), utc(2026, time.March, 16, 0, 0))
	if len(segments) != 1 || len(notes) != 0 {
		t.Fatalf("expected a plain segment without notes, got %+v %+v", segments, notes)
	}
	if !segments[0].Start.Equal(utc(2026, time.March, 15, 6, 30)) {
		t.Fatalf("expected 02:30 EDT start, got %+v", segments[0])
	}
}

func TestExpandFallBackRepeatedTimesNeverShortenCoverage(t *testing.T) {
	// America/New_York repeats 01:00–02:00 on Sunday 2026-11-01 (EDT→EST at
	// 06:00 UTC): 01:30 EDT is 05:30 UTC, 01:30 EST is 06:30 UTC.
	endsAtRepeated := weeklyCoverage("America/New_York", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Sunday, StartTime: "00:30", EndWeekday: time.Sunday, EndTime: "01:30",
	})
	segments, notes := mustExpand(t, []Coverage{endsAtRepeated}, utc(2026, time.October, 31, 0, 0), utc(2026, time.November, 2, 0, 0))
	if len(segments) != 1 {
		t.Fatalf("expected one segment, got %+v", segments)
	}
	// The end takes the second occurrence: 00:30 EDT (04:30 UTC) → 01:30 EST
	// (06:30 UTC), two hours of coverage instead of a shortened one.
	if !segments[0].Start.Equal(utc(2026, time.November, 1, 4, 30)) || !segments[0].End.Equal(utc(2026, time.November, 1, 6, 30)) {
		t.Fatalf("expected coverage through both occurrences, got %+v", segments[0])
	}
	if len(notes) != 1 || notes[0].Kind != DSTNoteRepeated || notes[0].Boundary != "end" || !notes[0].Resolved.Equal(utc(2026, time.November, 1, 6, 30)) {
		t.Fatalf("unexpected DST notes: %+v", notes)
	}

	startsAtRepeated := weeklyCoverage("America/New_York", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Sunday, StartTime: "01:30", EndWeekday: time.Sunday, EndTime: "05:00",
	})
	segments, notes = mustExpand(t, []Coverage{startsAtRepeated}, utc(2026, time.October, 31, 0, 0), utc(2026, time.November, 2, 0, 0))
	if len(segments) != 1 {
		t.Fatalf("expected one segment, got %+v", segments)
	}
	// The start takes the first occurrence: 01:30 EDT (05:30 UTC) → 05:00
	// EST (10:00 UTC).
	if !segments[0].Start.Equal(utc(2026, time.November, 1, 5, 30)) || !segments[0].End.Equal(utc(2026, time.November, 1, 10, 0)) {
		t.Fatalf("expected coverage from the first occurrence, got %+v", segments[0])
	}
	if len(notes) != 1 || notes[0].Kind != DSTNoteRepeated || notes[0].Boundary != "start" || !notes[0].Resolved.Equal(utc(2026, time.November, 1, 5, 30)) {
		t.Fatalf("unexpected DST notes: %+v", notes)
	}
}

func TestExpandWindowBoundsAreHalfOpen(t *testing.T) {
	coverage := weeklyCoverage("UTC", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "09:00", EndWeekday: time.Monday, EndTime: "17:00",
	})
	// A segment ending exactly at the window start is over, not covering.
	if segments, _ := mustExpand(t, []Coverage{coverage}, utc(2026, time.July, 20, 17, 0), utc(2026, time.July, 21, 0, 0)); len(segments) != 0 {
		t.Fatalf("expected segment ending at window start to be excluded, got %+v", segments)
	}
	// A segment starting exactly at the window end has not begun inside it.
	if segments, _ := mustExpand(t, []Coverage{coverage}, utc(2026, time.July, 19, 0, 0), utc(2026, time.July, 20, 9, 0)); len(segments) != 0 {
		t.Fatalf("expected segment starting at window end to be excluded, got %+v", segments)
	}
}

func TestExpandAcrossYearBoundary(t *testing.T) {
	// 2026-12-31 is a Thursday.
	coverage := weeklyCoverage("UTC", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Thursday, StartTime: "22:00", EndWeekday: time.Friday, EndTime: "06:00",
	})
	segments, _ := mustExpand(t, []Coverage{coverage}, utc(2026, time.December, 28, 0, 0), utc(2027, time.January, 4, 0, 0))
	if len(segments) != 1 {
		t.Fatalf("expected one segment, got %+v", segments)
	}
	if !segments[0].Start.Equal(utc(2026, time.December, 31, 22, 0)) || !segments[0].End.Equal(utc(2027, time.January, 1, 6, 0)) {
		t.Fatalf("expected the segment to cross into 2027, got %+v", segments[0])
	}
}

func TestExpandSkipsDatedSchedulesAndEmptyRuleSets(t *testing.T) {
	dated := Coverage{
		Schedule: domain.Schedule{ID: 1, Kind: domain.ScheduleKindDated, Timezone: "UTC"},
		Rules:    []domain.ScheduleWeeklyRule{{ID: 1, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "09:00", EndWeekday: time.Monday, EndTime: "17:00"}},
	}
	empty := weeklyCoverage("UTC")
	segments, notes := mustExpand(t, []Coverage{dated, empty}, utc(2026, time.July, 20, 0, 0), utc(2026, time.August, 3, 0, 0))
	if len(segments) != 0 || len(notes) != 0 {
		t.Fatalf("expected nothing from dated or empty coverages, got %+v %+v", segments, notes)
	}
}

func TestExpandRejectsInvalidTimezone(t *testing.T) {
	broken := weeklyCoverage("Not/AZone", domain.ScheduleWeeklyRule{
		ID: 1, ScheduleID: 1, StartWeekday: time.Monday, StartTime: "09:00", EndWeekday: time.Monday, EndTime: "17:00",
	})
	if _, _, err := ExpandCoverage([]Coverage{broken}, utc(2026, time.July, 20, 0, 0), utc(2026, time.July, 27, 0, 0)); err == nil {
		t.Fatal("expected an error for an unloadable timezone")
	}
}

func TestWallInstants(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	// A normal wall time maps to exactly one instant.
	instants := wallInstants(2026, time.July, 20, 9*60, loc)
	if len(instants) != 1 || !instants[0].Equal(utc(2026, time.July, 20, 13, 0)) {
		t.Fatalf("expected one EDT instant, got %+v", instants)
	}
	// A spring-forward wall time maps to none.
	if instants := wallInstants(2026, time.March, 8, 2*60+30, loc); len(instants) != 0 {
		t.Fatalf("expected no instants inside the gap, got %+v", instants)
	}
	// A fall-back wall time maps to two, earliest first.
	instants = wallInstants(2026, time.November, 1, 60+30, loc)
	if len(instants) != 2 || !instants[0].Equal(utc(2026, time.November, 1, 5, 30)) || !instants[1].Equal(utc(2026, time.November, 1, 6, 30)) {
		t.Fatalf("expected both occurrences earliest-first, got %+v", instants)
	}
}
