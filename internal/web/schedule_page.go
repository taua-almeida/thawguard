package web

import (
	"context"
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
// carries the Active/Paused truth: paused schedules never freeze anything.
type scheduleCardView struct {
	ID              int64
	Name            string
	RepositoryLabel string
	Branch          string
	KindLabel       string
	TimezoneLabel   string
	DetailURL       string
	Active          bool
	// NextLabel is the card's "Next: …" coverage line; empty hides it.
	NextLabel string
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
			Active:          sched.Active,
		})
	}
	return cards
}

// scheduleCardViewsWithNext decorates the overview cards with each schedule's
// next coverage, loading rules or windows per schedule. A card whose lookup
// fails fails the page: a silently missing "Next:" line would read as "no
// coverage" and that is a lie.
func (s *Server) scheduleCardViewsWithNext(ctx context.Context, repositories []domain.Repository, schedules []domain.Schedule) ([]scheduleCardView, error) {
	cards := scheduleCardViews(repositories, schedules)
	now := time.Now()
	for i, sched := range schedules {
		var rules []domain.ScheduleWeeklyRule
		var windows []domain.ScheduleDatedWindow
		var err error
		switch sched.Kind {
		case domain.ScheduleKindWeekly:
			rules, err = s.cfg.ScheduleStore.ListRules(ctx, sched.ID)
		case domain.ScheduleKindDated:
			windows, err = s.cfg.ScheduleStore.ListWindows(ctx, sched.ID)
		}
		if err != nil {
			return nil, err
		}
		cards[i].NextLabel = scheduleNextLabel(sched, rules, windows, now)
	}
	return cards, nil
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
	ActivateAction  string
	PauseAction     string
	Active          bool
	// Suppressed is only true while the schedule is active and an operator's
	// manual "End freeze" is holding it back until the next window.
	Suppressed         bool
	SuppressedUntil    string
	SuppressedUntilUTC string
}

type scheduleDetailPageData struct {
	AppName           string
	PageTitle         string
	Theme             string
	ActivePage        string
	CurrentUser       currentUserView
	CanManage         bool
	Schedule          scheduleDetailView
	Rules             []scheduleRuleView
	RuleAddAction     string
	RuleDayOptions    []scheduleRuleDayOption
	RuleEndDayOptions []scheduleRuleEndDayOption
	RuleForm          scheduleRuleFormState
	RuleFormError     string
	Windows           []scheduleWindowView
	WindowAddAction   string
	WindowForm        scheduleWindowFormState
	WindowFormError   string
	// ActivateDisabledReason disables the Activate button while the schedule
	// has nothing to expand; it mirrors the service's own validation message.
	ActivateDisabledReason string
	HasPreview             bool
	Preview                schedulePreviewView
	HasContext             bool
	Context                scheduleContextView
	CSRFToken              string
	CSRFField              string
	Toasts                 []toastView
}

// scheduleDetailForms bundles the detail page's two mutation forms so a
// validation error on either re-renders the page with that form's submitted
// values and message preserved.
type scheduleDetailForms struct {
	RuleForm        scheduleRuleFormState
	RuleFormError   string
	WindowForm      scheduleWindowFormState
	WindowFormError string
}

func defaultScheduleDetailForms() scheduleDetailForms {
	return scheduleDetailForms{RuleForm: defaultScheduleRuleFormState()}
}

func scheduleDetailViewFrom(repositories []domain.Repository, sched domain.Schedule) scheduleDetailView {
	now := time.Now()
	view := scheduleDetailView{
		ID:              sched.ID,
		Name:            sched.Name,
		RepositoryLabel: publicationRepositoryLabel(repositoriesByID(repositories)[sched.RepositoryID], sched.RepositoryID),
		Branch:          sched.Branch,
		Kind:            string(sched.Kind),
		KindLabel:       scheduleKindLabel(sched.Kind),
		TimezoneLabel:   timezoneOffsetLabel(sched.Timezone, now),
		Reason:          sched.Reason,
		CreatedAt:       sched.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		CreatedAtUTC:    sched.CreatedAt.UTC().Format(time.RFC3339),
		URL:             fmt.Sprintf("%s/%d", schedulesBasePath, sched.ID),
		DeleteAction:    fmt.Sprintf("%s/%d/delete", schedulesBasePath, sched.ID),
		ActivateAction:  fmt.Sprintf("%s/%d/activate", schedulesBasePath, sched.ID),
		PauseAction:     fmt.Sprintf("%s/%d/pause", schedulesBasePath, sched.ID),
		Active:          sched.Active,
	}
	if sched.Active && sched.SuppressedUntil != nil && sched.SuppressedUntil.After(now) {
		view.Suppressed = true
		view.SuppressedUntil = sched.SuppressedUntil.UTC().Format("2006-01-02 15:04 UTC")
		view.SuppressedUntilUTC = sched.SuppressedUntil.UTC().Format(time.RFC3339)
	}
	return view
}

// scheduleNewPageData assembles the new-schedule form view model. Writes a
// 500 and returns ok=false on load failure.
func (s *Server) scheduleNewPageData(w http.ResponseWriter, r *http.Request, form scheduleFormState, formError string, session sessionState) (scheduleNewPageData, bool) {
	ctx := r.Context()
	repositories, err := s.repositories(ctx, session.Grants.RepositoryReadScope())
	if err != nil {
		internalServerError(w)
		return scheduleNewPageData{}, false
	}
	freezerRepositories := freezeRepositories(repositories, session.Grants)
	branchOptions, err := s.managedBranchOptions(ctx, freezerRepositories)
	if err != nil {
		internalServerError(w)
		return scheduleNewPageData{}, false
	}
	currentUser := currentUserFromSession(session)
	currentUser.CanFreeze = len(freezerRepositories) > 0
	return scheduleNewPageData{
		AppName:                 s.cfg.AppName,
		PageTitle:               "New schedule",
		ActivePage:              "scheduled",
		CurrentUser:             currentUser,
		EnforceableRepositories: enforcementActiveRepositories(freezerRepositories),
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
	session, ok := s.requireActionForm(w, r)
	if !ok {
		return
	}
	form := scheduleFormStateFromRequest(r)
	if _, authorized := s.requireFreezeRepository(w, r, session, form.RepositoryID); !authorized {
		return
	}
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
	sched, err := s.cfg.ScheduleStore.GetForScope(r.Context(), session.Grants.RepositoryReadScope(), id)
	if errors.Is(err, schedule.ErrNotFound) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if err != nil {
		internalServerError(w)
		return
	}
	data, ok := s.scheduleDetailPageData(w, r, sched, defaultScheduleDetailForms(), session)
	if !ok {
		return
	}
	notices := map[string]string{
		"created":              "Schedule created. It is paused and does not freeze anything.",
		"rules-added":          "Rules added.",
		"rule-removed":         "Rule removed.",
		"window-added":         "Window added.",
		"window-added-started": "Window added. This window has already started; coverage begins immediately.",
		"window-removed":       "Window removed.",
		"activated":            "Schedule activated. It now freezes this branch during covered windows.",
		"paused":               "Schedule paused. It no longer freezes its branch; any freeze it created was ended.",
	}
	if !sched.Active {
		notices["rules-added"] = "Rules added. The schedule stays paused and freezes nothing yet."
		pausedWindow := "Window added. The schedule stays paused and freezes nothing yet."
		notices["window-added"] = pausedWindow
		notices["window-added-started"] = pausedWindow
	}
	if message := notices[r.URL.Query().Get("notice")]; message != "" {
		data.Toasts = []toastView{{Message: message, Tone: "success", DismissHref: data.Schedule.URL}}
	}
	s.renderPage(w, "layouts/schedule-detail", data)
}

// scheduleDetailPageData assembles the detail page view model: the rules or
// date-windows card by kind, the coverage preview, and the branch's combined
// coverage context. Writes a 500 and returns ok=false on load failure.
func (s *Server) scheduleDetailPageData(w http.ResponseWriter, r *http.Request, sched domain.Schedule, forms scheduleDetailForms, session sessionState) (scheduleDetailPageData, bool) {
	repositories, err := s.repositories(r.Context(), session.Grants.RepositoryReadScope())
	if err != nil {
		internalServerError(w)
		return scheduleDetailPageData{}, false
	}
	now := time.Now()
	view := scheduleDetailViewFrom(repositories, sched)
	currentUser := currentUserFromSession(session)
	currentUser.CanFreeze = session.Grants.CanFreezeRepository(sched.RepositoryID)
	data := scheduleDetailPageData{
		AppName:           s.cfg.AppName,
		PageTitle:         view.Name,
		ActivePage:        "scheduled",
		CurrentUser:       currentUser,
		CanManage:         currentUser.CanFreeze,
		Schedule:          view,
		RuleAddAction:     fmt.Sprintf("%s/%d/rules", schedulesBasePath, sched.ID),
		RuleDayOptions:    scheduleRuleDayOptions(forms.RuleForm),
		RuleEndDayOptions: scheduleRuleEndDayOptions(forms.RuleForm),
		RuleForm:          forms.RuleForm,
		RuleFormError:     forms.RuleFormError,
		WindowAddAction:   fmt.Sprintf("%s/%d/windows", schedulesBasePath, sched.ID),
		WindowForm:        forms.WindowForm,
		WindowFormError:   forms.WindowFormError,
		CSRFToken:         session.CSRFToken,
		CSRFField:         csrfFormField,
	}
	switch sched.Kind {
	case domain.ScheduleKindWeekly:
		rules, err := s.cfg.ScheduleStore.ListRules(r.Context(), sched.ID)
		if err != nil {
			internalServerError(w)
			return scheduleDetailPageData{}, false
		}
		data.Rules = scheduleRuleViews(sched.ID, rules)
		if len(rules) == 0 {
			data.ActivateDisabledReason = "Add at least one rule before activating."
		} else {
			preview, err := schedulePreviewFrom(sched, schedule.Coverage{Schedule: sched, Rules: rules}, now)
			if err != nil {
				internalServerError(w)
				return scheduleDetailPageData{}, false
			}
			data.HasPreview = true
			data.Preview = preview
		}
	case domain.ScheduleKindDated:
		windows, err := s.cfg.ScheduleStore.ListWindows(r.Context(), sched.ID)
		if err != nil {
			internalServerError(w)
			return scheduleDetailPageData{}, false
		}
		if len(windows) == 0 {
			data.ActivateDisabledReason = "Add at least one date window before activating."
		}
		upcoming, err := upcomingScheduleWindows(sched, windows, now)
		if err != nil {
			internalServerError(w)
			return scheduleDetailPageData{}, false
		}
		data.Windows = scheduleWindowViews(sched, upcoming, now)
		if len(upcoming) > 0 {
			preview, err := schedulePreviewFrom(sched, schedule.Coverage{Schedule: sched, Windows: upcoming}, now)
			if err != nil {
				internalServerError(w)
				return scheduleDetailPageData{}, false
			}
			data.HasPreview = true
			data.Preview = preview
		}
	}
	context, hasContext, err := s.scheduleContext(r.Context(), session.Grants.RepositoryReadScope(), repositories, sched, now)
	if err != nil {
		internalServerError(w)
		return scheduleDetailPageData{}, false
	}
	data.HasContext = hasContext
	data.Context = context
	return data, true
}

func (s *Server) handleScheduleRuleAdd(w http.ResponseWriter, r *http.Request) {
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
	form := scheduleRuleFormStateFromRequest(r)
	_, err = s.cfg.ScheduleStore.AddRules(r.Context(), form.addRulesParams(id), session.auditActor())
	if err == nil {
		http.Redirect(w, r, fmt.Sprintf("%s/%d?notice=rules-added", schedulesBasePath, id), http.StatusSeeOther)
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
	forms.RuleForm = form
	forms.RuleFormError = err.Error()
	data, ok := s.scheduleDetailPageData(w, r, sched, forms, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, http.StatusBadRequest, "layouts/schedule-detail", data)
}

func (s *Server) handleScheduleRuleDelete(w http.ResponseWriter, r *http.Request) {
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
	ruleID, err := strconv.ParseInt(r.PathValue("ruleID"), 10, 64)
	if err != nil || ruleID <= 0 {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if _, err := s.cfg.ScheduleStore.DeleteRule(r.Context(), id, ruleID, session.auditActor()); err != nil {
		if errors.Is(err, schedule.ErrNotFound) || errors.Is(err, schedule.ErrRuleNotFound) {
			s.renderErrorPage(w, http.StatusNotFound, false)
			return
		}
		internalServerError(w)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s/%d?notice=rule-removed", schedulesBasePath, id), http.StatusSeeOther)
}

func (s *Server) handleScheduleDelete(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleScheduleActivate(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	s.handleScheduleActivation(w, r, s.cfg.ScheduleStore.Activate, "activated")
}

func (s *Server) handleSchedulePause(w http.ResponseWriter, r *http.Request) {
	if !s.requireScheduleStore(w) {
		return
	}
	s.handleScheduleActivation(w, r, s.cfg.ScheduleStore.Pause, "paused")
}

// handleScheduleActivation is the shared Activate/Pause POST handler. A
// validation error here only means a double submit (already active/paused),
// so it redirects back to the detail page without a notice.
func (s *Server) handleScheduleActivation(w http.ResponseWriter, r *http.Request, transition func(context.Context, int64, domain.Actor) (domain.Schedule, error), notice string) {
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
	if _, err := transition(r.Context(), id, session.auditActor()); err != nil {
		if errors.Is(err, schedule.ErrNotFound) {
			s.renderErrorPage(w, http.StatusNotFound, false)
			return
		}
		if schedule.IsValidationError(err) {
			http.Redirect(w, r, fmt.Sprintf("%s/%d", schedulesBasePath, id), http.StatusSeeOther)
			return
		}
		internalServerError(w)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s/%d?notice=%s", schedulesBasePath, id, notice), http.StatusSeeOther)
}

func (s *Server) authorizeSchedule(w http.ResponseWriter, r *http.Request, session sessionState, id int64) (domain.Schedule, bool) {
	sched, err := s.cfg.ScheduleStore.GetForScope(r.Context(), session.Grants.RepositoryReadScope(), id)
	if errors.Is(err, schedule.ErrNotFound) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return domain.Schedule{}, false
	}
	if err != nil {
		internalServerError(w)
		return domain.Schedule{}, false
	}
	if !session.Grants.CanFreezeRepository(sched.RepositoryID) {
		s.renderErrorPage(w, http.StatusForbidden, false)
		return domain.Schedule{}, false
	}
	return sched, true
}

// scheduleRuleFormState mirrors the add-rules form so a validation error
// re-renders with the submitted values preserved. Days holds the raw submitted
// day numbers; out-of-range or duplicate values pass through so the store
// rejects them with an honest message.
type scheduleRuleFormState struct {
	Submitted  bool
	Days       []int
	StartTime  string
	EndTime    string
	EndDayMode string
	EndWeekday string
}

func defaultScheduleRuleFormState() scheduleRuleFormState {
	return scheduleRuleFormState{
		StartTime:  "18:00",
		EndTime:    "08:00",
		EndDayMode: schedule.EndDayNext,
		EndWeekday: strconv.Itoa(int(time.Monday)),
	}
}

func scheduleRuleFormStateFromRequest(r *http.Request) scheduleRuleFormState {
	form := scheduleRuleFormState{
		Submitted:  true,
		StartTime:  r.PostFormValue("start_time"),
		EndTime:    r.PostFormValue("end_time"),
		EndDayMode: r.PostFormValue("end_day_mode"),
		EndWeekday: r.PostFormValue("end_weekday"),
	}
	for _, value := range r.PostForm["days"] {
		day, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			day = -1
		}
		form.Days = append(form.Days, day)
	}
	return form
}

func (f scheduleRuleFormState) addRulesParams(scheduleID int64) schedule.AddRulesParams {
	weekdays := make([]time.Weekday, 0, len(f.Days))
	for _, day := range f.Days {
		weekdays = append(weekdays, time.Weekday(day))
	}
	endWeekday, err := strconv.Atoi(strings.TrimSpace(f.EndWeekday))
	if err != nil {
		endWeekday = -1
	}
	return schedule.AddRulesParams{
		ScheduleID: scheduleID,
		Weekdays:   weekdays,
		StartTime:  f.StartTime,
		EndTime:    f.EndTime,
		EndDayMode: f.EndDayMode,
		EndWeekday: time.Weekday(endWeekday),
	}
}

func (f scheduleRuleFormState) hasDay(day time.Weekday) bool {
	for _, selected := range f.Days {
		if selected == int(day) {
			return true
		}
	}
	return false
}

// mondayFirstWeekdays orders day pickers the way the rules card and preview
// present a week, while values stay Go's time.Weekday numbering (0=Sunday).
var mondayFirstWeekdays = [...]time.Weekday{
	time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday,
}

type scheduleRuleDayOption struct {
	Value   int
	Label   string
	Checked bool
}

func scheduleRuleDayOptions(form scheduleRuleFormState) []scheduleRuleDayOption {
	options := make([]scheduleRuleDayOption, 0, len(mondayFirstWeekdays))
	for _, weekday := range mondayFirstWeekdays {
		options = append(options, scheduleRuleDayOption{
			Value:   int(weekday),
			Label:   schedule.WeekdayShort(weekday),
			Checked: form.hasDay(weekday),
		})
	}
	return options
}

type scheduleRuleEndDayOption struct {
	Value    int
	Label    string
	Selected bool
}

func scheduleRuleEndDayOptions(form scheduleRuleFormState) []scheduleRuleEndDayOption {
	options := make([]scheduleRuleEndDayOption, 0, len(mondayFirstWeekdays))
	for _, weekday := range mondayFirstWeekdays {
		options = append(options, scheduleRuleEndDayOption{
			Value:    int(weekday),
			Label:    weekday.String(),
			Selected: form.EndWeekday == strconv.Itoa(int(weekday)),
		})
	}
	return options
}

// scheduleRuleView is one row in the rules card.
type scheduleRuleView struct {
	ID            int64
	Label         string
	RelationLabel string
	DeleteAction  string
}

func scheduleRuleViews(scheduleID int64, rules []domain.ScheduleWeeklyRule) []scheduleRuleView {
	views := make([]scheduleRuleView, 0, len(rules))
	for _, rule := range rules {
		views = append(views, scheduleRuleView{
			ID: rule.ID,
			Label: fmt.Sprintf("%s %s → %s %s",
				schedule.WeekdayShort(rule.StartWeekday), rule.StartTime,
				schedule.WeekdayShort(rule.EndWeekday), rule.EndTime),
			RelationLabel: ruleRelationLabel(rule),
			DeleteAction:  fmt.Sprintf("%s/%d/rules/%d/delete", schedulesBasePath, scheduleID, rule.ID),
		})
	}
	return views
}

// ruleRelationLabel disambiguates rows whose weekday pair alone can be
// misread, like a full-week Mon 18:00 → Mon 08:00 rule.
func ruleRelationLabel(rule domain.ScheduleWeeklyRule) string {
	switch wrap := schedule.RuleWrapDays(rule); wrap {
	case 0:
		return "same day"
	case 1:
		return "next day"
	case 7:
		return "one week later"
	default:
		return fmt.Sprintf("%d days later", wrap)
	}
}

type schedulePreviewBlock struct {
	LeftPercent  string
	WidthPercent string
}

type schedulePreviewDay struct {
	Label      string
	Today      bool
	NowPercent string
	Blocks     []schedulePreviewBlock
}

type scheduleDSTNoteView struct {
	Tone    string
	Message string
}

// schedulePreviewView is the server-rendered 14-day coverage strip plus its
// accessible textual segment list, all in the schedule's timezone.
type schedulePreviewView struct {
	TimezoneLabel string
	FromLabel     string
	ToLabel       string
	Days          []schedulePreviewDay
	Segments      []string
	Notes         []scheduleDSTNoteView
}

func schedulePreviewFrom(sched domain.Schedule, coverage schedule.Coverage, now time.Time) (schedulePreviewView, error) {
	loc, err := time.LoadLocation(sched.Timezone)
	if err != nil {
		return schedulePreviewView{}, fmt.Errorf("load schedule %d timezone %q: %w", sched.ID, sched.Timezone, err)
	}
	localNow := now.In(loc)
	windowStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, loc)
	windowEnd := windowStart.AddDate(0, 0, 14)
	segments, notes, err := schedule.ExpandCoverage([]schedule.Coverage{coverage}, windowStart, windowEnd)
	if err != nil {
		return schedulePreviewView{}, err
	}

	view := schedulePreviewView{
		TimezoneLabel: timezoneOffsetLabel(sched.Timezone, now),
		FromLabel:     windowStart.Format("Mon 2 Jan"),
		ToLabel:       windowEnd.AddDate(0, 0, -1).Format("Mon 2 Jan"),
	}
	for i := 0; i < 14; i++ {
		dayStart := windowStart.AddDate(0, 0, i)
		dayEnd := windowStart.AddDate(0, 0, i+1)
		// A DST day is 23 or 25 real hours; positions are fractions of the
		// day's true duration so blocks always stay inside their cell.
		dayDuration := dayEnd.Sub(dayStart)
		day := schedulePreviewDay{Label: dayStart.Format("Mon 2")}
		if !now.Before(dayStart) && now.Before(dayEnd) {
			day.Today = true
			day.NowPercent = previewPercent(now.Sub(dayStart), dayDuration)
		}
		for _, segment := range segments {
			if !segment.End.After(dayStart) || !segment.Start.Before(dayEnd) {
				continue
			}
			start, end := segment.Start, segment.End
			if start.Before(dayStart) {
				start = dayStart
			}
			if end.After(dayEnd) {
				end = dayEnd
			}
			day.Blocks = append(day.Blocks, schedulePreviewBlock{
				LeftPercent:  previewPercent(start.Sub(dayStart), dayDuration),
				WidthPercent: previewPercent(end.Sub(start), dayDuration),
			})
		}
		view.Days = append(view.Days, day)
	}
	for _, segment := range segments {
		view.Segments = append(view.Segments, fmt.Sprintf("%s → %s",
			segment.Start.In(loc).Format("Mon 2 Jan 15:04"), segment.End.In(loc).Format("Mon 2 Jan 15:04")))
	}
	for _, note := range notes {
		view.Notes = append(view.Notes, dstNoteView(note, loc))
	}
	return view, nil
}

func previewPercent(part, whole time.Duration) string {
	if whole <= 0 {
		return "0"
	}
	return strconv.FormatFloat(float64(part)/float64(whole)*100, 'f', 2, 64)
}

// dstNoteView explains one adjusted rule boundary in plain language. The
// nonexistent case warns because the operator's literal wall time is skipped;
// the repeated case only informs because coverage is never shortened.
func dstNoteView(note schedule.DSTNote, loc *time.Location) scheduleDSTNoteView {
	boundary := "starts"
	if note.Boundary == "end" {
		boundary = "ends"
	}
	if note.Kind == schedule.DSTNoteNonexistent {
		return scheduleDSTNoteView{
			Tone: "warning",
			Message: fmt.Sprintf("%s %s does not exist (clocks move forward). Coverage %s at %s that day.",
				note.LocalDate, note.LocalTime, boundary, note.Resolved.In(loc).Format("15:04")),
		}
	}
	occurrence := "first"
	if note.Boundary == "end" {
		occurrence = "second"
	}
	return scheduleDSTNoteView{
		Tone: "info",
		Message: fmt.Sprintf("%s %s occurs twice (clocks move back). Coverage %s at the %s occurrence, so it is not shortened.",
			note.LocalDate, note.LocalTime, boundary, occurrence),
	}
}
