package schedule

import (
	"fmt"
	"sort"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

// Coverage pairs a schedule with its weekly rules for expansion. Dated
// schedules and paused state are the caller's concern: ExpandCoverage expands
// whatever it is given, which is what lets the preview show a paused
// schedule's would-be coverage truthfully labeled as a preview.
type Coverage struct {
	Schedule domain.Schedule
	Rules    []domain.ScheduleWeeklyRule
}

// Segment is one concrete coverage interval in absolute time. Segments are
// not clipped to the requested window, so a segment that started before the
// window keeps its true start.
type Segment struct {
	ScheduleID   int64
	ScheduleName string
	Start        time.Time
	End          time.Time
}

type DSTNoteKind string

const (
	// DSTNoteNonexistent marks a rule boundary whose wall time was skipped
	// by a spring-forward transition; coverage uses the first valid instant.
	DSTNoteNonexistent DSTNoteKind = "nonexistent"
	// DSTNoteRepeated marks a rule boundary whose wall time occurs twice in
	// a fall-back transition; coverage starts at the first occurrence and
	// ends at the second, so it is never shortened.
	DSTNoteRepeated DSTNoteKind = "repeated"
)

// DSTNote records a rule boundary that fell on a DST transition inside the
// expansion window, so the preview can explain the adjusted boundary.
type DSTNote struct {
	ScheduleID int64
	Kind       DSTNoteKind
	// Boundary is "start" or "end" — which side of the segment moved.
	Boundary string
	// LocalDate and LocalTime are the rule's literal wall clock in the
	// schedule's timezone ("2026-03-08", "02:30").
	LocalDate string
	LocalTime string
	// Resolved is the instant coverage actually starts or ends.
	Resolved time.Time
}

// maxNonexistentScanMinutes bounds the forward scan for the first valid wall
// time after a spring-forward gap. Real gaps are 30–120 minutes; the historic
// maximum (Lord Howe pre-1985 aside) is well under six hours.
const maxNonexistentScanMinutes = 6 * 60

// ExpandCoverage turns weekly rules into concrete coverage segments whose
// [Start, End) overlaps the window [from, to). It is a pure function and the
// only place recurrence logic lives: the preview timeline renders its output
// directly, and the activation scheduler will consume the same output.
//
// Per schedule, overlapping or touching segments merge into one, because two
// rules covering Friday night and Saturday morning are one continuous period
// of "merges blocked". Segments from different schedules never merge.
func ExpandCoverage(coverages []Coverage, from, to time.Time) ([]Segment, []DSTNote, error) {
	segments := make([]Segment, 0)
	notes := make([]DSTNote, 0)
	seenNotes := make(map[DSTNote]bool)

	for _, coverage := range coverages {
		if coverage.Schedule.Kind != domain.ScheduleKindWeekly || len(coverage.Rules) == 0 {
			continue
		}
		loc, err := time.LoadLocation(coverage.Schedule.Timezone)
		if err != nil {
			return nil, nil, fmt.Errorf("load schedule %d timezone %q: %w", coverage.Schedule.ID, coverage.Schedule.Timezone, err)
		}
		expanded := make([]Segment, 0)
		for _, rule := range coverage.Rules {
			ruleSegments, ruleNotes, err := expandRule(coverage.Schedule, rule, loc, from, to)
			if err != nil {
				return nil, nil, err
			}
			expanded = append(expanded, ruleSegments...)
			for _, note := range ruleNotes {
				if !seenNotes[note] {
					seenNotes[note] = true
					notes = append(notes, note)
				}
			}
		}
		segments = append(segments, mergeSegments(expanded)...)
	}

	sort.Slice(segments, func(i, j int) bool {
		if !segments[i].Start.Equal(segments[j].Start) {
			return segments[i].Start.Before(segments[j].Start)
		}
		return segments[i].ScheduleID < segments[j].ScheduleID
	})
	sort.Slice(notes, func(i, j int) bool { return notes[i].Resolved.Before(notes[j].Resolved) })
	return segments, notes, nil
}

func expandRule(schedule domain.Schedule, rule domain.ScheduleWeeklyRule, loc *time.Location, from, to time.Time) ([]Segment, []DSTNote, error) {
	startMinutes, ok := parseWallMinutes(rule.StartTime)
	if !ok {
		return nil, nil, fmt.Errorf("schedule %d rule %d: invalid start time %q", schedule.ID, rule.ID, rule.StartTime)
	}
	endMinutes, ok := parseWallMinutes(rule.EndTime)
	if !ok {
		return nil, nil, fmt.Errorf("schedule %d rule %d: invalid end time %q", schedule.ID, rule.ID, rule.EndTime)
	}
	wrapDays := RuleWrapDays(rule)

	segments := make([]Segment, 0)
	notes := make([]DSTNote, 0)

	// Walk local calendar days across the window, starting far enough back
	// that a rule spanning up to wrapDays days and starting before the window
	// is still seen. The noon anchor keeps AddDate stable across DST days.
	fromLocal := from.In(loc)
	toLocal := to.In(loc)
	day := time.Date(fromLocal.Year(), fromLocal.Month(), fromLocal.Day(), 12, 0, 0, 0, loc).AddDate(0, 0, -(wrapDays + 1))
	lastDay := time.Date(toLocal.Year(), toLocal.Month(), toLocal.Day(), 12, 0, 0, 0, loc)

	for !day.After(lastDay) {
		if day.Weekday() != rule.StartWeekday {
			day = day.AddDate(0, 0, 1)
			continue
		}
		endDay := day.AddDate(0, 0, wrapDays)
		start, startNote := resolveWall(day.Year(), day.Month(), day.Day(), startMinutes, loc, "start", schedule.ID)
		end, endNote := resolveWall(endDay.Year(), endDay.Month(), endDay.Day(), endMinutes, loc, "end", schedule.ID)
		day = day.AddDate(0, 0, 1)

		if !end.After(from) || !start.Before(to) {
			continue
		}
		segments = append(segments, Segment{
			ScheduleID:   schedule.ID,
			ScheduleName: schedule.Name,
			Start:        start,
			End:          end,
		})
		if startNote != nil {
			notes = append(notes, *startNote)
		}
		if endNote != nil {
			notes = append(notes, *endNote)
		}
	}
	return segments, notes, nil
}

// resolveWall maps a local wall clock to one instant. An exact wall time maps
// directly. A wall time repeated by fall-back resolves so coverage is never
// shortened: a start takes the first occurrence, an end takes the second. A
// wall time skipped by spring-forward resolves to the first valid instant
// after the gap for both boundaries.
func resolveWall(year int, month time.Month, dayOfMonth, minutes int, loc *time.Location, boundary string, scheduleID int64) (time.Time, *DSTNote) {
	note := &DSTNote{
		ScheduleID: scheduleID,
		Boundary:   boundary,
		LocalDate:  fmt.Sprintf("%04d-%02d-%02d", year, int(month), dayOfMonth),
		LocalTime:  fmt.Sprintf("%02d:%02d", minutes/60, minutes%60),
	}
	instants := wallInstants(year, month, dayOfMonth, minutes, loc)
	switch len(instants) {
	case 1:
		return instants[0], nil
	case 0:
		note.Kind = DSTNoteNonexistent
		note.Resolved = firstValidWallAfter(year, month, dayOfMonth, minutes, loc)
		return note.Resolved, note
	default:
		note.Kind = DSTNoteRepeated
		if boundary == "start" {
			note.Resolved = instants[0]
		} else {
			note.Resolved = instants[len(instants)-1]
		}
		return note.Resolved, note
	}
}

// wallInstants returns every instant whose wall clock in loc reads the given
// date and minute: one for a normal time, none for a time skipped by spring
// forward, two for a time repeated by fall back. It probes the zone's UTC
// offsets shortly before and after the target, builds one candidate instant
// per distinct offset, and keeps the candidates that round-trip back to the
// requested wall time.
func wallInstants(year int, month time.Month, dayOfMonth, minutes int, loc *time.Location) []time.Time {
	utcWall := time.Date(year, month, dayOfMonth, minutes/60, minutes%60, 0, 0, time.UTC)
	offsets := make(map[int]bool, 3)
	for _, probe := range [...]time.Time{utcWall.Add(-26 * time.Hour), utcWall, utcWall.Add(26 * time.Hour)} {
		_, offset := probe.In(loc).Zone()
		offsets[offset] = true
	}
	instants := make([]time.Time, 0, 2)
	for offset := range offsets {
		candidate := utcWall.Add(-time.Duration(offset) * time.Second)
		local := candidate.In(loc)
		if local.Year() == year && local.Month() == month && local.Day() == dayOfMonth && local.Hour()*60+local.Minute() == minutes {
			instants = append(instants, candidate)
		}
	}
	sort.Slice(instants, func(i, j int) bool { return instants[i].Before(instants[j]) })
	return instants
}

// firstValidWallAfter scans forward minute by minute from a nonexistent wall
// time to the first wall time the zone actually has; its instant is where the
// spring-forward gap ends.
func firstValidWallAfter(year int, month time.Month, dayOfMonth, minutes int, loc *time.Location) time.Time {
	base := time.Date(year, month, dayOfMonth, minutes/60, minutes%60, 0, 0, time.UTC)
	for offset := 1; offset <= maxNonexistentScanMinutes; offset++ {
		wall := base.Add(time.Duration(offset) * time.Minute)
		if instants := wallInstants(wall.Year(), wall.Month(), wall.Day(), wall.Hour()*60+wall.Minute(), loc); len(instants) > 0 {
			return instants[0]
		}
	}
	// Unreachable for real zone data; Go's own normalization is the fallback.
	return time.Date(year, month, dayOfMonth, minutes/60, minutes%60, 0, 0, loc)
}

// mergeSegments merges overlapping or touching segments of one schedule.
func mergeSegments(segments []Segment) []Segment {
	if len(segments) <= 1 {
		return segments
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].Start.Before(segments[j].Start) })
	merged := segments[:1]
	for _, segment := range segments[1:] {
		last := &merged[len(merged)-1]
		if !segment.Start.After(last.End) {
			if segment.End.After(last.End) {
				last.End = segment.End
			}
			continue
		}
		merged = append(merged, segment)
	}
	return merged
}
