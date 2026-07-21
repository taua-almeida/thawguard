package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/schedule"
)

const schedulesBasePath = "/scheduled-freezes/schedules"

func scheduleKindLabel(kind domain.ScheduleKind) string {
	switch kind {
	case domain.ScheduleKindWeekly:
		return "Weekly"
	case domain.ScheduleKindDated:
		return "Special dates"
	default:
		return string(kind)
	}
}

// timezoneOffsetLabel renders "America/Sao_Paulo (UTC-03:00)" using the
// zone's offset at the given instant, so DST shifts the label across the
// year. UTC stays plain; an unresolvable name falls back to itself.
func timezoneOffsetLabel(name string, at time.Time) string {
	if name == "UTC" {
		return "UTC"
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return name
	}
	_, offset := at.In(location).Zone()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("%s (UTC%s%02d:%02d)", name, sign, offset/3600, offset%3600/60)
}

// scheduleCardView is one schedule in the overview card grid. Every card
// carries the "Paused" truth: shells never freeze anything.
type scheduleCardView struct {
	ID              int64
	Name            string
	RepositoryLabel string
	Branch          string
	KindLabel       string
	TimezoneLabel   string
	DetailURL       string
}

func scheduleCardViews(repositories []domain.Repository, schedules []domain.Schedule) []scheduleCardView {
	byID := repositoriesByID(repositories)
	now := time.Now()
	cards := make([]scheduleCardView, 0, len(schedules))
	for _, sched := range schedules {
		cards = append(cards, scheduleCardView{
			ID:              sched.ID,
			Name:            sched.Name,
			RepositoryLabel: publicationRepositoryLabel(byID[sched.RepositoryID], sched.RepositoryID),
			Branch:          sched.Branch,
			KindLabel:       scheduleKindLabel(sched.Kind),
			TimezoneLabel:   timezoneOffsetLabel(sched.Timezone, now),
			DetailURL:       fmt.Sprintf("%s/%d", schedulesBasePath, sched.ID),
		})
	}
	return cards
}

// scheduleFormState mirrors the new-schedule form so a validation error
// re-renders with the submitted values preserved.
type scheduleFormState struct {
	Submitted    bool
	RepositoryID int64
	Branch       string
	Name         string
	Kind         string
	Timezone     string
	Reason       string
}

func scheduleFormStateFromRequest(r *http.Request) scheduleFormState {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	return scheduleFormState{
		Submitted:    true,
		RepositoryID: repositoryID,
		Branch:       r.PostFormValue("branch"),
		Name:         r.PostFormValue("name"),
		Kind:         r.PostFormValue("kind"),
		Timezone:     r.PostFormValue("timezone"),
		Reason:       r.PostFormValue("reason"),
	}
}

type scheduleTimezoneOption struct {
	Value    string
	Label    string
	Selected bool
}

// scheduleTimezoneOptions builds the timezone select, UTC first so the
// no-JS default is explicit rather than the server's local zone.
func scheduleTimezoneOptions(selected string) []scheduleTimezoneOption {
	now := time.Now()
	zones := schedule.Timezones()
	options := make([]scheduleTimezoneOption, 0, len(zones))
	for _, zone := range zones {
		options = append(options, scheduleTimezoneOption{
			Value:    zone,
			Label:    timezoneOffsetLabel(zone, now),
			Selected: zone == selected,
		})
	}
	return options
}

type scheduleNewPageData struct {
	AppName                 string
	PageTitle               string
	Theme                   string
	ActivePage              string
	CurrentUser             currentUserView
	EnforceableRepositories []domain.Repository
	BranchOptions           []managedBranchOption
	TimezoneOptions         []scheduleTimezoneOption
	Form                    scheduleFormState
	FormError               string
	CSRFToken               string
	CSRFField               string
	Toasts                  []toastView
}

// scheduleDetailView is the detail page's schedule: presentation strings
// only, plus the raw kind for the honest empty coverage region.
type scheduleDetailView struct {
	ID              int64
	Name            string
	RepositoryLabel string
	Branch          string
	Kind            string
	KindLabel       string
	TimezoneLabel   string
	Reason          string
	CreatedAt       string
	CreatedAtUTC    string
	URL             string
	DeleteAction    string
}

type scheduleDetailPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	Schedule    scheduleDetailView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView
}

func scheduleDetailViewFrom(repositories []domain.Repository, sched domain.Schedule) scheduleDetailView {
	return scheduleDetailView{
		ID:              sched.ID,
		Name:            sched.Name,
		RepositoryLabel: publicationRepositoryLabel(repositoriesByID(repositories)[sched.RepositoryID], sched.RepositoryID),
		Branch:          sched.Branch,
		Kind:            string(sched.Kind),
		KindLabel:       scheduleKindLabel(sched.Kind),
		TimezoneLabel:   timezoneOffsetLabel(sched.Timezone, time.Now()),
		Reason:          sched.Reason,
		CreatedAt:       sched.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		CreatedAtUTC:    sched.CreatedAt.UTC().Format(time.RFC3339),
		URL:             fmt.Sprintf("%s/%d", schedulesBasePath, sched.ID),
		DeleteAction:    fmt.Sprintf("%s/%d/delete", schedulesBasePath, sched.ID),
	}
}

// scheduleNewPageData assembles the new-schedule form view model. Writes a
// 500 and returns ok=false on load failure.
func (s *Server) scheduleNewPageData(w http.ResponseWriter, r *http.Request, form scheduleFormState, formError string, session sessionState) (scheduleNewPageData, bool) {
	ctx := r.Context()
	repositories, err := s.repositories(ctx)
	if err != nil {
		internalServerError(w)
		return scheduleNewPageData{}, false
	}
	branchOptions, err := s.managedBranchOptions(ctx, repositories)
	if err != nil {
		internalServerError(w)
		return scheduleNewPageData{}, false
	}
	return scheduleNewPageData{
		AppName:                 s.cfg.AppName,
		PageTitle:               "New schedule",
		ActivePage:              "scheduled",
		CurrentUser:             currentUserFromSession(session),
		EnforceableRepositories: enforcementActiveRepositories(repositories),
		BranchOptions:           branchOptions,
		TimezoneOptions:         scheduleTimezoneOptions(form.Timezone),
		Form:                    form,
		FormError:               formError,
		CSRFToken:               session.CSRFToken,
		CSRFField:               csrfFormField,
	}, true
}

// requireScheduleStore guards every schedule route behind the optional
// ScheduleStore seam: an unwired store answers 503 instead of panicking.
func (s *Server) requireScheduleStore(w http.ResponseWriter) bool {
	if s.cfg.ScheduleStore == nil {
		http.Error(w, "schedule store is not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (s *Server) handleScheduleNew(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	data, ok := s.scheduleNewPageData(w, r, scheduleFormState{Timezone: "UTC"}, "", session)
	if !ok {
		return
	}
	s.renderPage(w, "layouts/schedule-new", data)
}

func (s *Server) handleScheduleCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	session, ok := s.requireScheduleManagerForm(w, r)
	if !ok {
		return
	}
	form := scheduleFormStateFromRequest(r)
	created, err := s.cfg.ScheduleStore.Create(r.Context(), schedule.CreateParams{
		RepositoryID: form.RepositoryID,
		Branch:       form.Branch,
		Name:         form.Name,
		Kind:         domain.ScheduleKind(strings.TrimSpace(form.Kind)),
		Timezone:     form.Timezone,
		Reason:       form.Reason,
	}, session.auditActor())
	if err != nil {
		if !schedule.IsValidationError(err) {
			internalServerError(w)
			return
		}
		data, ok := s.scheduleNewPageData(w, r, form, err.Error(), session)
		if !ok {
			return
		}
		s.renderPageStatus(w, http.StatusBadRequest, "layouts/schedule-new", data)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s/%d?notice=created", schedulesBasePath, created.ID), http.StatusSeeOther)
}

func (s *Server) handleScheduleDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	sched, err := s.cfg.ScheduleStore.Get(r.Context(), id)
	if errors.Is(err, schedule.ErrNotFound) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if err != nil {
		internalServerError(w)
		return
	}
	repositories, err := s.repositories(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	view := scheduleDetailViewFrom(repositories, sched)
	data := scheduleDetailPageData{
		AppName:     s.cfg.AppName,
		PageTitle:   view.Name,
		ActivePage:  "scheduled",
		CurrentUser: currentUserFromSession(session),
		Schedule:    view,
		CSRFToken:   session.CSRFToken,
		CSRFField:   csrfFormField,
	}
	if r.URL.Query().Get("notice") == "created" {
		data.Toasts = []toastView{{Message: "Schedule created. It is paused and does not freeze anything.", Tone: "success", DismissHref: view.URL}}
	}
	s.renderPage(w, "layouts/schedule-detail", data)
}

func (s *Server) handleScheduleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	session, ok := s.requireScheduleManagerForm(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if _, err := s.cfg.ScheduleStore.Delete(r.Context(), id, session.auditActor()); err != nil {
		if errors.Is(err, schedule.ErrNotFound) {
			s.renderErrorPage(w, http.StatusNotFound, false)
			return
		}
		internalServerError(w)
		return
	}
	http.Redirect(w, r, "/scheduled-freezes?notice=recurring-schedule-deleted", http.StatusSeeOther)
}
