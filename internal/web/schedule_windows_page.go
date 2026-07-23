package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

// wallDateTimeFormat matches the wall-clock text dated windows store and the
// browser's datetime-local input emit.
const wallDateTimeFormat = "2006-01-02T15:04"

// scheduleWindowFormState mirrors the add-window form so a validation error
// re-renders with the submitted values preserved.
type scheduleWindowFormState struct {
	Submitted bool
	Name      string
	StartsAt  string
	EndsAt    string
}

func scheduleWindowFormStateFromRequest(r *http.Request) scheduleWindowFormState {
	return scheduleWindowFormState{
		Submitted: true,
		Name:      r.PostFormValue("name"),
		StartsAt:  r.PostFormValue("starts_at"),
		EndsAt:    r.PostFormValue("ends_at"),
	}
}

// scheduleWindowView is one row in the date-windows card. Only windows that
// have not ended become views: past windows are never rendered — their rows
// exist purely for occurrence idempotency.
type scheduleWindowView struct {
	ID         int64
	Name       string
	RangeLabel string
	// InProgress marks a window whose start is already past: its remaining
	// range still covers, and coverage under an active schedule is live now.
	InProgress   bool
	DeleteAction string
}

// scheduleWallLabel formats a stored "2006-01-02T15:04" wall clock for
// display; the raw text is the fallback for an unparseable value.
func scheduleWallLabel(wall string) string {
	t, err := time.Parse(wallDateTimeFormat, wall)
	if err != nil {
		return wall
	}
	return t.Format("Mon 2 Jan 2006 15:04")
}

// upcomingScheduleWindows keeps the windows that have not ended yet. An
// in-progress window stays: it still freezes.
func upcomingScheduleWindows(sched domain.Schedule, windows []domain.ScheduleDatedWindow, now time.Time) ([]domain.ScheduleDatedWindow, error) {
	upcoming := make([]domain.ScheduleDatedWindow, 0, len(windows))
	for _, window := range windows {
		_, end, err := schedule.WindowBounds(sched, window)
		if err != nil {
			return nil, err
		}
		if end.After(now) {
			upcoming = append(upcoming, window)
		}
	}
	return upcoming, nil
}

func scheduleWindowViews(sched domain.Schedule, windows []domain.ScheduleDatedWindow, now time.Time) []scheduleWindowView {
	views := make([]scheduleWindowView, 0, len(windows))
	for _, window := range windows {
		view := scheduleWindowView{
			ID:           window.ID,
			Name:         window.Name,
			RangeLabel:   fmt.Sprintf("%s → %s", scheduleWallLabel(window.StartsAt), scheduleWallLabel(window.EndsAt)),
			DeleteAction: fmt.Sprintf("%s/%d/windows/%d/delete", schedulesBasePath, sched.ID, window.ID),
		}
		if start, _, err := schedule.WindowBounds(sched, window); err == nil && !start.After(now) {
			view.InProgress = true
		}
		views = append(views, view)
	}
	return views
}

func (s *Server) handleScheduleWindowAdd(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	session, ok := s.requireActionForm(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	sched, authorized := s.authorizeSchedule(w, r, session, id)
	if !authorized {
		return
	}
	form := scheduleWindowFormStateFromRequest(r)
	_, alreadyStarted, err := s.cfg.ScheduleStore.AddWindow(r.Context(), schedule.AddWindowParams{
		ScheduleID: id,
		Name:       form.Name,
		StartsAt:   form.StartsAt,
		EndsAt:     form.EndsAt,
	}, session.auditActor())
	if err == nil {
		// An accepted window whose start is already past gets the explicit
		// "coverage begins immediately" notice instead of the plain one. The
		// store decided that fact with the same clock reading that accepted
		// the window, so the notice can never contradict the validation.
		notice := "window-added"
		if alreadyStarted {
			notice = "window-added-started"
		}
		http.Redirect(w, r, fmt.Sprintf("%s/%d?notice=%s", schedulesBasePath, id, notice), http.StatusSeeOther)
		return
	}
	if errors.Is(err, schedule.ErrNotFound) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if !schedule.IsValidationError(err) {
		internalServerError(w)
		return
	}
	forms := defaultScheduleDetailForms()
	forms.WindowForm = form
	forms.WindowFormError = err.Error()
	data, ok := s.scheduleDetailPageData(w, r, sched, forms, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, http.StatusBadRequest, "layouts/schedule-detail", data)
}

func (s *Server) handleScheduleWindowDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	session, ok := s.requireActionForm(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if _, authorized := s.authorizeSchedule(w, r, session, id); !authorized {
		return
	}
	windowID, err := strconv.ParseInt(r.PathValue("windowID"), 10, 64)
	if err != nil || windowID <= 0 {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if _, err := s.cfg.ScheduleStore.DeleteWindow(r.Context(), id, windowID, session.auditActor()); err != nil {
		if errors.Is(err, schedule.ErrNotFound) || errors.Is(err, schedule.ErrWindowNotFound) {
			s.renderErrorPage(w, http.StatusNotFound, false)
			return
		}
		internalServerError(w)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s/%d?notice=window-removed", schedulesBasePath, id), http.StatusSeeOther)
}

// scheduleNextLabel summarizes a schedule's next coverage for its overview
// card. Weekly schedules look at the next 14 days of expansion; dated
// schedules resolve their windows directly, so a window far beyond the strip
// horizon still shows here. An empty string hides the line.
func scheduleNextLabel(sched domain.Schedule, rules []domain.ScheduleWeeklyRule, windows []domain.ScheduleDatedWindow, now time.Time) string {
	loc, err := time.LoadLocation(sched.Timezone)
	if err != nil {
		return ""
	}
	switch sched.Kind {
	case domain.ScheduleKindWeekly:
		if len(rules) == 0 {
			return "Next: — · no rules yet"
		}
		segments, _, err := schedule.ExpandCoverage([]schedule.Coverage{{Schedule: sched, Rules: rules}}, now, now.AddDate(0, 0, 14))
		if err != nil || len(segments) == 0 {
			return ""
		}
		first := segments[0]
		end := first.End.In(loc).Format("Mon 15:04")
		if !first.Start.After(now) {
			return fmt.Sprintf("Next: now → %s", end)
		}
		return fmt.Sprintf("Next: %s → %s", first.Start.In(loc).Format("Mon 15:04"), end)
	case domain.ScheduleKindDated:
		var nextStart, nextEnd time.Time
		found := false
		for _, window := range windows {
			start, end, err := schedule.WindowBounds(sched, window)
			if err != nil || !end.After(now) {
				continue
			}
			if !found || start.Before(nextStart) {
				nextStart, nextEnd, found = start, end, true
			}
		}
		if !found {
			return "Next: — · no upcoming dates"
		}
		if !nextStart.After(now) {
			return fmt.Sprintf("Next: now → %s", nextEnd.In(loc).Format("2 Jan 15:04"))
		}
		return fmt.Sprintf("Next: %s", nextStart.In(loc).Format("2 Jan 15:04"))
	default:
		return ""
	}
}
