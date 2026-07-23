package web

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
	"github.com/taua-almeida/thawguard/internal/schedule"
	"github.com/taua-almeida/thawguard/internal/scheduler"
)

// scheduleContextView is the branch's combined coverage over the next 14
// days: union blocks across every active schedule on the same repository and
// branch. Each block names its winning source exactly the way the
// materializer and forge status will, and expands to list every contributing
// source with its own start and end — precedence decides naming only, never
// coverage.
type scheduleContextView struct {
	BranchLabel   string
	TimezoneLabel string
	FromLabel     string
	ToLabel       string
	Blocks        []scheduleContextBlockView
}

type scheduleContextBlockView struct {
	RangeLabel string
	// NameSummary is the collapsed row's label sequence: one name, or the
	// handover order when the winning source changes inside the block.
	NameSummary string
	// Names are the naming spans: the block sliced at every point where the
	// winning source changes.
	Names []scheduleContextSpanView
	// Sources are every schedule segment contributing to the block, each with
	// its own true start and end.
	Sources []scheduleContextSpanView
}

type scheduleContextSpanView struct {
	Name       string
	KindLabel  string
	RangeLabel string
	Current    bool
}

// scheduleContext builds the combined-coverage section for a schedule's
// branch. It only appears when at least two active schedules cover the same
// repository and branch: with a single source there is no precedence to
// explain and the preview already tells the whole story.
func (s *Server) scheduleContext(ctx context.Context, scope repositoryscope.ReadScope, repositories []domain.Repository, current domain.Schedule, now time.Time) (scheduleContextView, bool, error) {
	all, err := s.cfg.ScheduleStore.ListForScope(ctx, scope)
	if err != nil {
		return scheduleContextView{}, false, err
	}
	peers := make([]domain.Schedule, 0, len(all))
	for _, sched := range all {
		if sched.Active && sched.RepositoryID == current.RepositoryID && sched.Branch == current.Branch {
			peers = append(peers, sched)
		}
	}
	if len(peers) < 2 {
		return scheduleContextView{}, false, nil
	}
	coverages := make([]schedule.Coverage, 0, len(peers))
	for _, sched := range peers {
		coverage := schedule.Coverage{Schedule: sched}
		switch sched.Kind {
		case domain.ScheduleKindWeekly:
			if coverage.Rules, err = s.cfg.ScheduleStore.ListRules(ctx, sched.ID); err != nil {
				return scheduleContextView{}, false, err
			}
		case domain.ScheduleKindDated:
			if coverage.Windows, err = s.cfg.ScheduleStore.ListWindows(ctx, sched.ID); err != nil {
				return scheduleContextView{}, false, err
			}
		}
		coverages = append(coverages, coverage)
	}
	view, err := scheduleContextViewFrom(current, peers, coverages, now)
	if err != nil {
		return scheduleContextView{}, false, err
	}
	return view, true, nil
}

func scheduleContextViewFrom(current domain.Schedule, peers []domain.Schedule, coverages []schedule.Coverage, now time.Time) (scheduleContextView, error) {
	loc, err := time.LoadLocation(current.Timezone)
	if err != nil {
		return scheduleContextView{}, fmt.Errorf("load schedule %d timezone %q: %w", current.ID, current.Timezone, err)
	}
	localNow := now.In(loc)
	windowStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, loc)
	windowEnd := windowStart.AddDate(0, 0, 14)
	segments, _, err := schedule.ExpandCoverage(coverages, windowStart, windowEnd)
	if err != nil {
		return scheduleContextView{}, err
	}
	byID := make(map[int64]domain.Schedule, len(peers))
	for _, sched := range peers {
		byID[sched.ID] = sched
	}

	view := scheduleContextView{
		BranchLabel:   current.Branch,
		TimezoneLabel: timezoneOffsetLabel(current.Timezone, now),
		FromLabel:     windowStart.Format("Mon 2 Jan"),
		ToLabel:       windowEnd.AddDate(0, 0, -1).Format("Mon 2 Jan"),
	}
	for _, block := range contextUnionBlocks(segments) {
		blockView := scheduleContextBlockView{
			RangeLabel: contextRangeLabel(block.Start, block.End, loc),
		}
		spans := contextNameSpans(block, segments, byID)
		names := make([]string, 0, len(spans))
		for _, span := range spans {
			sched := byID[span.scheduleID]
			blockView.Names = append(blockView.Names, scheduleContextSpanView{
				Name:       sched.Name,
				KindLabel:  scheduleKindLabel(sched.Kind),
				RangeLabel: contextRangeLabel(span.Start, span.End, loc),
				Current:    span.scheduleID == current.ID,
			})
			names = append(names, sched.Name)
		}
		blockView.NameSummary = strings.Join(names, ", then ")
		for _, segment := range segments {
			if !segment.End.After(block.Start) || !segment.Start.Before(block.End) {
				continue
			}
			sched := byID[segment.ScheduleID]
			blockView.Sources = append(blockView.Sources, scheduleContextSpanView{
				Name:       segment.ScheduleName,
				KindLabel:  scheduleKindLabel(sched.Kind),
				RangeLabel: contextRangeLabel(segment.Start, segment.End, loc),
				Current:    segment.ScheduleID == current.ID,
			})
		}
		view.Blocks = append(view.Blocks, blockView)
	}
	return view, nil
}

func contextRangeLabel(start, end time.Time, loc *time.Location) string {
	return fmt.Sprintf("%s → %s",
		start.In(loc).Format("Mon 2 Jan 15:04"), end.In(loc).Format("Mon 2 Jan 15:04"))
}

// contextInterval is a schedule-agnostic [Start, End) union block.
type contextInterval struct {
	Start time.Time
	End   time.Time
}

// contextUnionBlocks merges segments across schedules into contiguous covered
// blocks. Touching segments merge: one schedule ending 08:00 and another
// starting 08:00 is one uninterrupted period of "merges blocked".
func contextUnionBlocks(segments []schedule.Segment) []contextInterval {
	if len(segments) == 0 {
		return nil
	}
	intervals := make([]contextInterval, len(segments))
	for i, segment := range segments {
		intervals[i] = contextInterval{Start: segment.Start, End: segment.End}
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].Start.Before(intervals[j].Start) })
	merged := intervals[:1]
	for _, interval := range intervals[1:] {
		last := &merged[len(merged)-1]
		if !interval.Start.After(last.End) {
			if interval.End.After(last.End) {
				last.End = interval.End
			}
			continue
		}
		merged = append(merged, interval)
	}
	return merged
}

// contextNameSpan is one stretch of a union block owned by a single winning
// schedule for naming purposes.
type contextNameSpan struct {
	scheduleID int64
	Start      time.Time
	End        time.Time
}

// contextNameSpans slices one union block at every contributing segment
// boundary and names each slice via the scheduler's own precedence, so the
// labels here can never disagree with what the materializer writes to the
// forge status: Dated outranks Weekly, ties break to the most recently
// created schedule. Adjacent slices with the same winner merge back together.
func contextNameSpans(block contextInterval, segments []schedule.Segment, byID map[int64]domain.Schedule) []contextNameSpan {
	cuts := []time.Time{block.Start, block.End}
	for _, segment := range segments {
		for _, boundary := range []time.Time{segment.Start, segment.End} {
			if boundary.After(block.Start) && boundary.Before(block.End) {
				cuts = append(cuts, boundary)
			}
		}
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i].Before(cuts[j]) })

	var spans []contextNameSpan
	for i := 0; i+1 < len(cuts); i++ {
		start, end := cuts[i], cuts[i+1]
		if !end.After(start) {
			continue
		}
		var winner domain.Schedule
		found := false
		for _, segment := range segments {
			if segment.Start.After(start) || !segment.End.After(start) {
				continue
			}
			sched, ok := byID[segment.ScheduleID]
			if !ok {
				continue
			}
			if !found || scheduler.Outranks(sched, winner) {
				winner = sched
				found = true
			}
		}
		if !found {
			continue
		}
		if len(spans) > 0 && spans[len(spans)-1].scheduleID == winner.ID && spans[len(spans)-1].End.Equal(start) {
			spans[len(spans)-1].End = end
			continue
		}
		spans = append(spans, contextNameSpan{scheduleID: winner.ID, Start: start, End: end})
	}
	return spans
}
