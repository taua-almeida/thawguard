package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

// decisionsPageSize caps one page of the freeze-decisions table; the
// pagination footer walks the rest.
const decisionsPageSize = 20

// decisionFormState mirrors scheduledFreezeFormState for the approve form so
// a validation error re-renders with the submitted values preserved.
// PullRequestIndex stays the raw submitted string so invalid input
// round-trips unchanged.
type decisionFormState struct {
	Submitted        bool
	RepositoryID     int64
	TargetBranch     string
	PullRequestIndex string
	Reason           string
}

// decisionsQuery is the decisions-table view selection: a state filter chip,
// a repository filter, and a 1-based page. It travels as ?state=&repo=&page=
// on GETs and as hidden fields on the approve/confirm POSTs so the selection
// survives swaps and redirects. The repository filter is named "repo", not
// "repository_id": the approve form already posts a repository_id select, and
// a hidden query field with the same name would collide with it in PostForm.
type decisionsQuery struct {
	State        string
	RepositoryID int64
	Page         int
}

// decisionFilterChip is one state filter option in the decisions section head.
type decisionFilterChip struct {
	Label  string
	URL    string
	Active bool
}

// decisionsPaginationView is the "Showing X–Y of N" footer with
// Previous/Next links. Nil when everything fits on one page.
type decisionsPaginationView struct {
	From    int
	To      int
	Total   int
	PrevURL string
	NextURL string
}

// decisionRowView is one recorded decision in the results table with the
// repository resolved and the badge and time fields precomputed. The badge
// labels describe merge eligibility under cooperative enforcement, never a
// hard security guarantee.
type decisionRowView struct {
	Result          statusresult.Result
	RepositoryLabel string // FullName, or "Repository #N" when the record is gone
	PullRequestURL  string // forge link; "" when it cannot be derived
	StateLabel      string
	BadgeTone       string
	BadgeIcon       string
	ShortHeadSHA    string
	CreatedAt       string // "2006-01-02 15:04 UTC" server-rendered fallback
	CreatedAtUTC    string // RFC3339 for the <time datetime> attribute
}

// thawEligibilityView drives the #thaw-eligibility region in the workbench
// aside. It reads only the webhook-synced cache; approval always re-checks
// the forge, so this is a preview, not a gate.
type thawEligibilityView struct {
	State            string // "prompt" | "found" | "missing"
	RepositoryLabel  string
	PullRequestIndex int
	Title            string
	URL              string
	TargetBranch     string
	TargetFrozen     bool
	ShortHeadSHA     string
	Companions       []thawEligibilityCompanionView
}

// thawEligibilityCompanionView is one other open pull request sharing the
// previewed head commit — the early warning for the shared-head interstitial.
type thawEligibilityCompanionView struct {
	Index int
	Title string
	URL   string
}

type decisionsPageData struct {
	AppName                 string
	PageTitle               string
	Theme                   string
	ActivePage              string
	CurrentUser             currentUserView
	EnforceableRepositories []domain.Repository
	BranchOptions           []managedBranchOption
	FilterRepositories      []domain.Repository
	Rows                    []decisionRowView
	Total                   int
	Filter                  string
	FilterLabel             string
	Chips                   []decisionFilterChip
	Pagination              *decisionsPaginationView
	Query                   decisionsQuery
	FormError               string
	DecisionForm            decisionFormState
	Confirmation            *sharedHeadConfirmationView
	Eligibility             *thawEligibilityView
	CSRFToken               string
	CSRFField               string
	RequiredContext         string
	Toasts                  []toastView
}

// decisionsFragment is the htmx swap payload for /decisions mutations: the
// swapped region's page data plus an optional out-of-band toast for the
// shell's #toasts region.
type decisionsFragment struct {
	Data  decisionsPageData
	Toast *toastView
}

// decisionsPageState carries request-scoped render state for /decisions:
// validation errors, redirect notices, the submitted form, the table query,
// and — when a shared-head confirmation is pending — the interstitial view.
type decisionsPageState struct {
	FormError    string
	Notice       string
	NoticeTone   string
	DecisionForm decisionFormState
	Query        decisionsQuery
	Confirmation *sharedHeadConfirmationView
}

// decisionFilterOptions orders the state chips; keys double as the ?state=
// values ("all" is normalized away).
var decisionFilterOptions = []struct {
	Key    string
	Label  string
	Status domain.CommitStatusState
}{
	{Key: "all", Label: "All"},
	{Key: "eligible", Label: "Eligible", Status: domain.CommitStatusSuccess},
	{Key: "blocked", Label: "Blocked", Status: domain.CommitStatusFailure},
	{Key: "pending", Label: "Pending", Status: domain.CommitStatusPending},
	{Key: "error", Label: "Error", Status: domain.CommitStatusError},
}

// decisionFilterState normalizes a raw ?state= value to a chip key and its
// store-level state filter ("" means no filter). Unknown values fall back to
// "all" instead of erroring.
func decisionFilterState(raw string) (string, domain.CommitStatusState) {
	key := strings.ToLower(strings.TrimSpace(raw))
	for _, option := range decisionFilterOptions {
		if option.Key == key {
			return option.Key, option.Status
		}
	}
	return "all", ""
}

func decisionFilterLabel(filter string) string {
	for _, option := range decisionFilterOptions {
		if option.Key == filter {
			return option.Label
		}
	}
	return "All"
}

// decisionStateBadge maps a stored commit-status state to the table badge.
// Blocked wears the frozen tone, not danger: a correct block is the product
// working as configured.
func decisionStateBadge(state domain.CommitStatusState) (label, tone, icon string) {
	switch state {
	case domain.CommitStatusSuccess:
		return "Eligible", "success", "tg-i-check"
	case domain.CommitStatusFailure:
		return "Blocked", "frozen", "tg-i-lock"
	case domain.CommitStatusPending:
		return "Pending", "neutral", ""
	case domain.CommitStatusError:
		return "Error", "warning", "tg-i-warning"
	default:
		return string(state), "neutral", ""
	}
}

// decisionsQueryFromValues works for both URL queries (GET) and posted forms
// (mutations carry state/repo/page as hidden fields).
func decisionsQueryFromValues(values url.Values) decisionsQuery {
	filter, _ := decisionFilterState(values.Get("state"))
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(values.Get("repo")), 10, 64)
	if err != nil || repositoryID < 0 {
		repositoryID = 0
	}
	page, err := strconv.Atoi(strings.TrimSpace(values.Get("page")))
	if err != nil || page < 1 {
		page = 1
	}
	return decisionsQuery{State: filter, RepositoryID: repositoryID, Page: page}
}

func decisionsURL(query decisionsQuery) string {
	params := url.Values{}
	if query.State != "" && query.State != "all" {
		params.Set("state", query.State)
	}
	if query.RepositoryID > 0 {
		params.Set("repo", strconv.FormatInt(query.RepositoryID, 10))
	}
	if query.Page > 1 {
		params.Set("page", strconv.Itoa(query.Page))
	}
	if len(params) == 0 {
		return "/decisions"
	}
	return "/decisions?" + params.Encode()
}

func decisionsNoticeURL(query decisionsQuery, notice string) string {
	base := decisionsURL(query)
	if strings.Contains(base, "?") {
		return base + "&notice=" + notice
	}
	return base + "?notice=" + notice
}

func decisionFormStateFromRequest(r *http.Request) decisionFormState {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	return decisionFormState{
		Submitted:        true,
		RepositoryID:     repositoryID,
		TargetBranch:     r.PostFormValue("target_branch"),
		PullRequestIndex: strings.TrimSpace(r.PostFormValue("pull_request_index")),
		Reason:           r.PostFormValue("reason"),
	}
}

// forgePullRequestURL derives the forge's pull request page from the
// repository record. Empty when any component is missing — the row then
// renders the index as plain text.
func forgePullRequestURL(repo domain.Repository, index int) string {
	base := strings.TrimRight(strings.TrimSpace(repo.BaseURL), "/")
	if base == "" || repo.Owner == "" || repo.Name == "" || index <= 0 {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s/pulls/%d", base, repo.Owner, repo.Name, index)
}

func decisionRowViews(repositories []domain.Repository, results []statusresult.Result) []decisionRowView {
	byID := repositoriesByID(repositories)
	rows := make([]decisionRowView, 0, len(results))
	for _, result := range results {
		row := decisionRowView{
			Result:          result,
			RepositoryLabel: fmt.Sprintf("Repository #%d", result.RepositoryID),
			ShortHeadSHA:    shortHeadSHA(result.HeadSHA),
			CreatedAt:       result.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			CreatedAtUTC:    result.CreatedAt.UTC().Format(time.RFC3339),
		}
		if repo, ok := byID[result.RepositoryID]; ok && repo.ID != 0 {
			row.RepositoryLabel = repo.FullName()
			row.PullRequestURL = forgePullRequestURL(repo, result.PullRequestIndex)
		}
		row.StateLabel, row.BadgeTone, row.BadgeIcon = decisionStateBadge(result.State)
		rows = append(rows, row)
	}
	return rows
}

func (s *Server) decisionsPageData(repositories []domain.Repository, results []statusresult.Result, branchOptions []managedBranchOption, total int, state decisionsPageState, eligibility *thawEligibilityView, csrfToken string, currentUser currentUserView) decisionsPageData {
	data := decisionsPageData{
		AppName:                 s.cfg.AppName,
		PageTitle:               "Thaw Requests",
		ActivePage:              "thaws",
		CurrentUser:             currentUser,
		EnforceableRepositories: enforcementActiveRepositories(repositories),
		BranchOptions:           branchOptions,
		FilterRepositories:      repositories,
		Rows:                    decisionRowViews(repositories, results),
		Total:                   total,
		Filter:                  state.Query.State,
		FilterLabel:             decisionFilterLabel(state.Query.State),
		Query:                   state.Query,
		FormError:               state.FormError,
		DecisionForm:            state.DecisionForm,
		Confirmation:            state.Confirmation,
		Eligibility:             eligibility,
		CSRFToken:               csrfToken,
		CSRFField:               csrfFormField,
		RequiredContext:         domain.RequiredStatusContext,
	}
	for _, option := range decisionFilterOptions {
		data.Chips = append(data.Chips, decisionFilterChip{
			Label:  option.Label,
			URL:    decisionsURL(decisionsQuery{State: option.Key, RepositoryID: state.Query.RepositoryID, Page: 1}),
			Active: option.Key == state.Query.State,
		})
	}
	if total > decisionsPageSize {
		pagination := &decisionsPaginationView{
			From:  (state.Query.Page-1)*decisionsPageSize + 1,
			To:    (state.Query.Page-1)*decisionsPageSize + len(results),
			Total: total,
		}
		if len(results) == 0 {
			pagination.From = 0
		}
		if state.Query.Page > 1 {
			pagination.PrevURL = decisionsURL(decisionsQuery{State: state.Query.State, RepositoryID: state.Query.RepositoryID, Page: state.Query.Page - 1})
		}
		if pagination.To < total {
			pagination.NextURL = decisionsURL(decisionsQuery{State: state.Query.State, RepositoryID: state.Query.RepositoryID, Page: state.Query.Page + 1})
		}
		data.Pagination = pagination
	}
	if state.Notice != "" {
		tone := state.NoticeTone
		if tone == "" {
			tone = "success"
		}
		data.Toasts = []toastView{{Message: state.Notice, Tone: tone, DismissHref: decisionsURL(state.Query)}}
	}
	return data
}

// loadDecisionsPageData assembles the full /decisions view model for the
// requested filters and page, clamping an out-of-range page back to the last
// one. Writes a 500 and returns ok=false on load failure. Callers must have
// already handled the nil-StatusDecisionStore 503 guard.
func (s *Server) loadDecisionsPageData(w http.ResponseWriter, r *http.Request, state decisionsPageState, session sessionState) (decisionsPageData, bool) {
	ctx := r.Context()
	scope := session.Grants.RepositoryReadScope()
	repositories, err := s.repositories(ctx, scope)
	if err != nil {
		internalServerError(w)
		return decisionsPageData{}, false
	}
	_, status := decisionFilterState(state.Query.State)
	results, total, err := s.cfg.StatusDecisionStore.ListDecisionsPageForScope(ctx, scope, status, state.Query.RepositoryID, (state.Query.Page-1)*decisionsPageSize, decisionsPageSize)
	if err != nil {
		internalServerError(w)
		return decisionsPageData{}, false
	}
	if len(results) == 0 && total > 0 && state.Query.Page > 1 {
		lastPage := (total + decisionsPageSize - 1) / decisionsPageSize
		state.Query.Page = lastPage
		results, total, err = s.cfg.StatusDecisionStore.ListDecisionsPageForScope(ctx, scope, status, state.Query.RepositoryID, (lastPage-1)*decisionsPageSize, decisionsPageSize)
		if err != nil {
			internalServerError(w)
			return decisionsPageData{}, false
		}
	}
	actionRepositories := thawRepositories(repositories, session.Grants)
	branchOptions, err := s.managedBranchOptions(ctx, actionRepositories)
	if err != nil {
		internalServerError(w)
		return decisionsPageData{}, false
	}
	var eligibility *thawEligibilityView
	if state.DecisionForm.Submitted {
		if index, convErr := strconv.Atoi(strings.TrimSpace(state.DecisionForm.PullRequestIndex)); convErr == nil {
			eligibility, err = s.thawEligibility(ctx, scope, actionRepositories, state.DecisionForm.RepositoryID, index)
			if err != nil {
				internalServerError(w)
				return decisionsPageData{}, false
			}
		}
	}
	currentUser := currentUserFromSession(session)
	currentUser.CanThaw = len(actionRepositories) > 0
	data := s.decisionsPageData(repositories, results, branchOptions, total, state, eligibility, session.CSRFToken, currentUser)
	data.EnforceableRepositories = enforcementActiveRepositories(actionRepositories)
	return data, true
}

// thawEligibility builds the #thaw-eligibility preview from the
// webhook-synced cache only — never the live forge; approval re-checks the
// forge regardless of what this preview showed. Nil (the prompt state) when
// there is nothing to preview yet: no repository, no positive index, an
// unknown repository, or no pull request cache configured.
func (s *Server) thawEligibility(ctx context.Context, scope repositoryscope.ReadScope, repositories []domain.Repository, repositoryID int64, pullRequestIndex int) (*thawEligibilityView, error) {
	if repositoryID <= 0 || pullRequestIndex <= 0 || s.cfg.PullRequestStore == nil {
		return nil, nil
	}
	repo, ok := repositoriesByID(repositories)[repositoryID]
	if !ok || repo.ID == 0 {
		return nil, nil
	}
	view := &thawEligibilityView{State: "missing", RepositoryLabel: repo.FullName(), PullRequestIndex: pullRequestIndex}
	pr, err := s.cfg.PullRequestStore.Get(ctx, repositoryID, pullRequestIndex)
	if errors.Is(err, sql.ErrNoRows) {
		return view, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cached pull request for eligibility preview: %w", err)
	}
	view.State = "found"
	view.Title = pr.Title
	view.URL = pr.URL
	view.TargetBranch = pr.TargetBranch
	view.ShortHeadSHA = shortHeadSHA(pr.HeadSHA)
	if s.cfg.FreezeStore != nil {
		freezes, err := s.cfg.FreezeStore.ListActiveForScope(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("list active freezes for eligibility preview: %w", err)
		}
		for _, frozen := range freezes {
			if frozen.RepositoryID == repositoryID && frozen.Branch == pr.TargetBranch {
				view.TargetFrozen = true
				break
			}
		}
	}
	if pr.HeadSHA != "" {
		open, err := s.cfg.PullRequestStore.ListOpenByHead(ctx, repositoryID, pr.HeadSHA)
		if err != nil {
			return nil, fmt.Errorf("list open pull requests by head for eligibility preview: %w", err)
		}
		for _, companion := range open {
			if companion.Index == pr.Index {
				continue
			}
			view.Companions = append(view.Companions, thawEligibilityCompanionView{Index: companion.Index, Title: companion.Title, URL: companion.URL})
		}
	}
	return view, nil
}

// handleThawEligibility refreshes the #thaw-eligibility panel when the
// approve form's repository or pull request number changes. GET-only
// enhancement endpoint mirroring handleFreezeImpact: no CSRF, htmx requests
// get the fragment, everything else goes back to the full page.
func (s *Server) handleThawEligibility(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	pullRequestIndex, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("pull_request_index")))
	if err != nil {
		pullRequestIndex = 0
	}
	if repositoryID > 0 {
		if _, authorized := s.requireThawRepository(w, r, session, repositoryID); !authorized {
			return
		}
	}
	if !isHXRequest(r) {
		http.Redirect(w, r, "/decisions", http.StatusSeeOther)
		return
	}
	scope := session.Grants.RepositoryReadScope()
	repositories, err := s.repositories(r.Context(), scope)
	if err != nil {
		internalServerError(w)
		return
	}
	eligibility, err := s.thawEligibility(r.Context(), scope, thawRepositories(repositories, session.Grants), repositoryID, pullRequestIndex)
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderPage(w, "components/thaw-eligibility", eligibility)
}

// renderDecisionsPage loads live data and renders the full page with the
// given status code (200 for views, 400 for non-HX validation errors, 409
// for non-HX shared-head confirmations).
func (s *Server) renderDecisionsPage(w http.ResponseWriter, r *http.Request, statusCode int, state decisionsPageState, session sessionState) {
	data, ok := s.loadDecisionsPageData(w, r, state, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, statusCode, "layouts/decisions", data)
}

// renderDecisionsFragment re-loads live data and renders the htmx swap
// payload for #decisions-live with the given status code (200 for validation
// re-renders and successes, honest 409 for shared-head confirmations).
func (s *Server) renderDecisionsFragment(w http.ResponseWriter, r *http.Request, statusCode int, state decisionsPageState, session sessionState, toast *toastView) {
	data, ok := s.loadDecisionsPageData(w, r, state, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, statusCode, "components/decisions-live-fragment", decisionsFragment{Data: data, Toast: toast})
}
