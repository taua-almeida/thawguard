package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
)

// scheduledFreezesPageSize caps one page of the scheduled windows table; the
// pagination footer walks the rest.
const scheduledFreezesPageSize = 20

// scheduledFreezeFormState mirrors freezeFormState for the schedule form so a
// validation error re-renders with the submitted values preserved.
type scheduledFreezeFormState struct {
	Submitted     bool
	RepositoryID  int64
	Branch        string
	StartsAt      string
	PlannedEndsAt string
	Reason        string
}

// scheduledFreezesQuery is the windows-list view selection: a status filter
// chip and a 1-based page. It travels as ?status=&page= on GETs and as hidden
// fields on mutations so the selection survives swaps and redirects.
type scheduledFreezesQuery struct {
	Filter string
	Page   int
}

// scheduledFilterChip is one status filter option in the windows section head.
type scheduledFilterChip struct {
	Label  string
	URL    string
	Active bool
}

// scheduledPaginationView is the "Showing X–Y of N" footer with Previous/Next
// links. Nil when everything fits on one page.
type scheduledPaginationView struct {
	From    int
	To      int
	Total   int
	PrevURL string
	NextURL string
}

// scheduledWindowCard wraps one window row with the request-scoped context
// its actions need: CSRF material, the caller's roles (cancel is
// freezer-only, edit/start-now allow manager-or-freezer), and the current
// filter/page so mutations return to the same view.
type scheduledWindowCard struct {
	scheduledFreezeView
	CSRFToken string
	CSRFField string
	CanFreeze bool
	CanManage bool
	Query     scheduledFreezesQuery
}

type scheduledFreezesPageData struct {
	AppName                 string
	PageTitle               string
	Theme                   string
	ActivePage              string
	CurrentUser             currentUserView
	EnforceableRepositories []domain.Repository
	BranchOptions           []managedBranchOption
	Windows                 []scheduledWindowCard
	Total                   int
	Filter                  string
	FilterLabel             string
	Chips                   []scheduledFilterChip
	Pagination              *scheduledPaginationView
	Query                   scheduledFreezesQuery
	FormError               string
	ActionError             string
	ScheduleForm            scheduledFreezeFormState
	CSRFToken               string
	CSRFField               string
	RequiredContext         string
	Toasts                  []toastView
}

// scheduledFreezesFragment is the htmx swap payload for scheduled-freeze
// mutations: the swapped region's page data plus an optional out-of-band toast
// for the shell's #toasts region.
type scheduledFreezesFragment struct {
	Data  scheduledFreezesPageData
	Toast *toastView
}

// scheduledFilterOptions orders the status chips; keys double as the ?status=
// values ("all" is normalized away).
var scheduledFilterOptions = []struct {
	Key    string
	Label  string
	Status domain.BranchFreezeStatus
}{
	{Key: "all", Label: "All"},
	{Key: "upcoming", Label: "Upcoming", Status: domain.BranchFreezeStatusScheduled},
	{Key: "active", Label: "Active", Status: domain.BranchFreezeStatusActive},
	{Key: "completed", Label: "Completed", Status: domain.BranchFreezeStatusEnded},
	{Key: "cancelled", Label: "Cancelled", Status: domain.BranchFreezeStatusCancelled},
}

// scheduledFilterStatus normalizes a raw ?status= value to a chip key and its
// store-level status filter ("" means no filter). Unknown values fall back to
// "all" instead of erroring.
func scheduledFilterStatus(raw string) (string, domain.BranchFreezeStatus) {
	key := strings.ToLower(strings.TrimSpace(raw))
	for _, option := range scheduledFilterOptions {
		if option.Key == key {
			return option.Key, option.Status
		}
	}
	return "all", ""
}

func scheduledFilterLabel(filter string) string {
	for _, option := range scheduledFilterOptions {
		if option.Key == filter {
			return option.Label
		}
	}
	return "All"
}

// scheduledFreezesQueryFromValues works for both URL queries (GET) and posted
// forms (mutations carry status/page as hidden fields).
func scheduledFreezesQueryFromValues(values url.Values) scheduledFreezesQuery {
	filter, _ := scheduledFilterStatus(values.Get("status"))
	page, err := strconv.Atoi(strings.TrimSpace(values.Get("page")))
	if err != nil || page < 1 {
		page = 1
	}
	return scheduledFreezesQuery{Filter: filter, Page: page}
}

func scheduledFreezesURL(query scheduledFreezesQuery) string {
	params := url.Values{}
	if query.Filter != "" && query.Filter != "all" {
		params.Set("status", query.Filter)
	}
	if query.Page > 1 {
		params.Set("page", strconv.Itoa(query.Page))
	}
	if len(params) == 0 {
		return "/scheduled-freezes"
	}
	return "/scheduled-freezes?" + params.Encode()
}

func scheduledFreezesNoticeURL(query scheduledFreezesQuery, notice string) string {
	base := scheduledFreezesURL(query)
	if strings.Contains(base, "?") {
		return base + "&notice=" + notice
	}
	return base + "?notice=" + notice
}

func scheduledFreezeFormStateFromRequest(r *http.Request) scheduledFreezeFormState {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	return scheduledFreezeFormState{
		Submitted:     true,
		RepositoryID:  repositoryID,
		Branch:        r.PostFormValue("branch"),
		StartsAt:      r.PostFormValue("starts_at"),
		PlannedEndsAt: r.PostFormValue("planned_ends_at"),
		Reason:        r.PostFormValue("reason"),
	}
}

// scheduledFreezeToastMessage resolves the repository name for the mutation
// toasts ("Freeze scheduled for taua/thawguard main."). Falls back to the
// repository id when the lookup fails; the toast is informational only.
func (s *Server) scheduledFreezeToastMessage(ctx context.Context, prefix string, scheduled domain.BranchFreeze) string {
	repoName := fmt.Sprintf("repository #%d", scheduled.RepositoryID)
	if repositories, err := s.repositories(ctx); err == nil {
		if repo, ok := repositoriesByID(repositories)[scheduled.RepositoryID]; ok && repo.ID != 0 {
			repoName = repo.FullName()
		}
	}
	return fmt.Sprintf("%s for %s %s.", prefix, repoName, scheduled.Branch)
}

func (s *Server) scheduledFreezesPageData(repositories []domain.Repository, windows []scheduledFreezeView, branchOptions []managedBranchOption, total int, state scheduledFreezePageState, csrfToken string, currentUser currentUserView) scheduledFreezesPageData {
	data := scheduledFreezesPageData{
		AppName:                 s.cfg.AppName,
		PageTitle:               "Scheduled Freezes",
		ActivePage:              "scheduled",
		CurrentUser:             currentUser,
		EnforceableRepositories: enforcementActiveRepositories(repositories),
		BranchOptions:           branchOptions,
		Total:                   total,
		Filter:                  state.Query.Filter,
		FilterLabel:             scheduledFilterLabel(state.Query.Filter),
		Query:                   state.Query,
		FormError:               state.FormError,
		ActionError:             state.ActionError,
		ScheduleForm:            state.ScheduleForm,
		CSRFToken:               csrfToken,
		CSRFField:               csrfFormField,
		RequiredContext:         domain.RequiredStatusContext,
	}
	data.Windows = make([]scheduledWindowCard, 0, len(windows))
	for _, view := range windows {
		data.Windows = append(data.Windows, scheduledWindowCard{
			scheduledFreezeView: view,
			CSRFToken:           csrfToken,
			CSRFField:           csrfFormField,
			CanFreeze:           currentUser.CanFreeze,
			CanManage:           currentUser.CanManageRepositories || currentUser.CanFreeze,
			Query:               state.Query,
		})
	}
	for _, option := range scheduledFilterOptions {
		data.Chips = append(data.Chips, scheduledFilterChip{
			Label:  option.Label,
			URL:    scheduledFreezesURL(scheduledFreezesQuery{Filter: option.Key, Page: 1}),
			Active: option.Key == state.Query.Filter,
		})
	}
	if total > scheduledFreezesPageSize {
		pagination := &scheduledPaginationView{
			From:  (state.Query.Page-1)*scheduledFreezesPageSize + 1,
			To:    (state.Query.Page-1)*scheduledFreezesPageSize + len(windows),
			Total: total,
		}
		if len(windows) == 0 {
			pagination.From = 0
		}
		if state.Query.Page > 1 {
			pagination.PrevURL = scheduledFreezesURL(scheduledFreezesQuery{Filter: state.Query.Filter, Page: state.Query.Page - 1})
		}
		if pagination.To < total {
			pagination.NextURL = scheduledFreezesURL(scheduledFreezesQuery{Filter: state.Query.Filter, Page: state.Query.Page + 1})
		}
		data.Pagination = pagination
	}
	if state.Notice != "" {
		tone := state.NoticeTone
		if tone == "" {
			tone = "success"
		}
		data.Toasts = []toastView{{Message: state.Notice, Tone: tone, DismissHref: scheduledFreezesURL(state.Query)}}
	}
	return data
}

// loadScheduledFreezesPageData assembles the full /scheduled-freezes view
// model for the requested filter and page, clamping an out-of-range page back
// to the last one. Writes a 500 and returns ok=false on load failure.
func (s *Server) loadScheduledFreezesPageData(w http.ResponseWriter, r *http.Request, state scheduledFreezePageState, session sessionState) (scheduledFreezesPageData, bool) {
	ctx := r.Context()
	repositories, err := s.repositories(ctx)
	if err != nil {
		internalServerError(w)
		return scheduledFreezesPageData{}, false
	}
	_, status := scheduledFilterStatus(state.Query.Filter)
	windows, total, err := s.cfg.ScheduledFreezeStore.ListScheduledPage(ctx, status, (state.Query.Page-1)*scheduledFreezesPageSize, scheduledFreezesPageSize)
	if err != nil {
		internalServerError(w)
		return scheduledFreezesPageData{}, false
	}
	if len(windows) == 0 && total > 0 && state.Query.Page > 1 {
		lastPage := (total + scheduledFreezesPageSize - 1) / scheduledFreezesPageSize
		state.Query.Page = lastPage
		windows, total, err = s.cfg.ScheduledFreezeStore.ListScheduledPage(ctx, status, (lastPage-1)*scheduledFreezesPageSize, scheduledFreezesPageSize)
		if err != nil {
			internalServerError(w)
			return scheduledFreezesPageData{}, false
		}
	}
	branchOptions, err := s.managedBranchOptions(ctx, repositories)
	if err != nil {
		internalServerError(w)
		return scheduledFreezesPageData{}, false
	}
	currentUser := currentUserFromSession(session)
	views := scheduledFreezeViews(repositories, windows, state)
	return s.scheduledFreezesPageData(repositories, views, branchOptions, total, state, session.CSRFToken, currentUser), true
}

// renderScheduledFreezes loads live data and renders the full page with the
// given status code (200 for views, 400 for non-HX validation errors).
func (s *Server) renderScheduledFreezes(w http.ResponseWriter, r *http.Request, statusCode int, state scheduledFreezePageState, session sessionState) {
	data, ok := s.loadScheduledFreezesPageData(w, r, state, session)
	if !ok {
		return
	}
	if statusCode != http.StatusOK {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(statusCode)
	}
	s.renderPage(w, "layouts/scheduled-freezes", data)
}

// renderScheduledFreezesFragment re-loads live data and renders one of the
// htmx swap payloads ("components/scheduled-live-fragment" for create,
// "components/scheduled-windows-fragment" for list-only updates).
func (s *Server) renderScheduledFreezesFragment(w http.ResponseWriter, r *http.Request, name string, state scheduledFreezePageState, session sessionState, toast *toastView) {
	data, ok := s.loadScheduledFreezesPageData(w, r, state, session)
	if !ok {
		return
	}
	s.renderPage(w, name, scheduledFreezesFragment{Data: data, Toast: toast})
}
