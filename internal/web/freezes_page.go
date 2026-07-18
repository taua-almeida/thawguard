package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

type freezeView struct {
	Freeze          domain.BranchFreeze
	Repository      domain.Repository
	PlannedEndsAt   string
	HasPlannedEndAt bool
	// StartedLabel is the StartsAt date (UTC, date only); StartedTitle holds
	// the full timestamp for the title attribute. CreatedByLabel resolves the
	// creator to an email or a role description, or stays empty when the
	// attribution is unknown (pre-migration rows) or no user data was loaded.
	StartedLabel   string
	StartedTitle   string
	CreatedByLabel string
}

type activeFreezeCard struct {
	freezeView
	CSRFToken string
	CSRFField string
	CanFreeze bool
}

type freezeFormState struct {
	Submitted     bool
	RepositoryID  int64
	Branch        string
	Reason        string
	PlannedEndsAt string
}

type freezesPageState struct {
	FormError   string
	ActionError string
	Notice      string
	NoticeTone  string
	FreezeForm  freezeFormState
}

type freezesPageData struct {
	AppName                 string
	PageTitle               string
	Theme                   string
	ActivePage              string
	CurrentUser             currentUserView
	EnforceableRepositories []domain.Repository
	BranchOptions           []managedBranchOption
	ActiveFreezes           []activeFreezeCard
	FormError               string
	ActionError             string
	FreezeForm              freezeFormState
	// Impact previews the known open pull requests a freeze on the selected
	// repository/branch would hit. Nil when there is no selection to preview
	// (viewer role or no enforceable repositories).
	Impact          *impactView
	CSRFToken       string
	CSRFField       string
	RequiredContext string
	Toasts          []toastView
}

// impactView is the #freeze-impact swap region: the repo→branch echo plus the
// open pull requests from the webhook-synced local cache. Rows past the
// visible cap render inside a closed <details> so every row stays in the DOM.
type impactView struct {
	Repository      string
	Branch          string
	Total           int
	Visible         []impactPRView
	Overflow        []impactPRView
	RequiredContext string
}

type impactPRView struct {
	Index int
	Title string
	URL   string
}

// freezeImpactVisibleLimit caps the rows shown before the "Show all N"
// disclosure takes over.
const freezeImpactVisibleLimit = 5

// freezesFragment is the htmx swap payload for freeze mutations: the swapped
// region's page data plus an optional out-of-band toast for the shell's
// #toasts region.
type freezesFragment struct {
	Data  freezesPageData
	Toast *toastView
}

func freezeFormStateFromRequest(r *http.Request) freezeFormState {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	return freezeFormState{
		Submitted:     true,
		RepositoryID:  repositoryID,
		Branch:        r.PostFormValue("branch"),
		Reason:        r.PostFormValue("reason"),
		PlannedEndsAt: r.PostFormValue("planned_ends_at"),
	}
}

func (s *Server) freezePageData(ctx context.Context) ([]domain.Repository, []domain.BranchFreeze, []managedBranchOption, map[int64]auth.User, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	freezes, err := s.activeFreezes(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	branchOptions, err := s.managedBranchOptions(ctx, repositories)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	usersByID, err := s.usersByID(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return repositories, freezes, branchOptions, usersByID, nil
}

func (s *Server) usersByID(ctx context.Context) (map[int64]auth.User, error) {
	if s.cfg.AuthService == nil {
		return map[int64]auth.User{}, nil
	}
	users, err := s.cfg.AuthService.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users for freeze attribution: %w", err)
	}
	byID := make(map[int64]auth.User, len(users))
	for _, user := range users {
		byID[user.ID] = user
	}
	return byID, nil
}

// freezeViews builds row views; a nil usersByID means "no user data loaded"
// and omits creator labels entirely instead of guessing "a removed user".
func (s *Server) freezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze, usersByID map[int64]auth.User) []freezeView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]freezeView, 0, len(freezes))
	for _, freeze := range freezes {
		startedAt := freeze.CreatedAt
		if freeze.StartsAt != nil && !freeze.StartsAt.IsZero() {
			startedAt = *freeze.StartsAt
		}
		view := freezeView{
			Freeze:          freeze,
			Repository:      repositoriesByID[freeze.RepositoryID],
			PlannedEndsAt:   optionalScheduleTime(freeze.PlannedEndsAt),
			HasPlannedEndAt: freeze.PlannedEndsAt != nil && !freeze.PlannedEndsAt.IsZero(),
			CreatedByLabel:  freezeCreatedByLabel(freeze, usersByID),
		}
		if !startedAt.IsZero() {
			view.StartedLabel = startedAt.UTC().Format("2006-01-02")
			view.StartedTitle = startedAt.UTC().Format(time.RFC3339)
		}
		views = append(views, view)
	}
	return views
}

func freezeCreatedByLabel(freeze domain.BranchFreeze, usersByID map[int64]auth.User) string {
	if usersByID == nil {
		return ""
	}
	if freeze.CreatedByUserID != nil {
		if user, ok := usersByID[*freeze.CreatedByUserID]; ok && user.Email != "" {
			return user.Email
		}
	}
	switch freeze.CreatedByKind {
	case domain.ActorKindBootstrapAdmin:
		return "bootstrap admin"
	case domain.ActorKindSystem:
		return "via schedule"
	case domain.ActorKindUser:
		// created_by is nulled when the user row is deleted (ON DELETE SET
		// NULL), so a user-kind freeze without a resolvable user means the
		// account is gone.
		return "a removed user"
	}
	if freeze.CreatedByUserID != nil {
		return "a removed user"
	}
	return ""
}

// freezeImpact resolves the repository/branch pair to preview: the submitted
// form pair when present, otherwise the first enforceable repository and its
// first managed branch (the pair the form initially selects). Returns nil
// when there is nothing to preview.
func (s *Server) freezeImpact(ctx context.Context, repositories []domain.Repository, branchOptions []managedBranchOption, form freezeFormState, canFreeze bool) (*impactView, error) {
	if !canFreeze {
		return nil, nil
	}
	enforceable := enforcementActiveRepositories(repositories)
	if len(enforceable) == 0 {
		return nil, nil
	}
	repo := enforceable[0]
	branch := ""
	if form.Submitted {
		branch = strings.TrimSpace(form.Branch)
		found := false
		for _, candidate := range enforceable {
			if candidate.ID == form.RepositoryID {
				repo, found = candidate, true
				break
			}
		}
		if !found {
			branch = ""
		}
	}
	if branch == "" {
		for _, option := range branchOptions {
			if option.RepositoryID == repo.ID {
				branch = option.Name
				break
			}
		}
	}
	impact := &impactView{Repository: repo.FullName(), Branch: branch, RequiredContext: domain.RequiredStatusContext}
	if branch == "" || s.cfg.PullRequestStore == nil {
		return impact, nil
	}
	pullRequests, err := s.cfg.PullRequestStore.ListOpenByTargetBranch(ctx, repo.ID, branch)
	if err != nil {
		return nil, fmt.Errorf("list open pull requests for freeze impact: %w", err)
	}
	impact.Total = len(pullRequests)
	for i, pullRequest := range pullRequests {
		row := impactPRView{Index: pullRequest.Index, Title: pullRequest.Title, URL: pullRequest.URL}
		if i < freezeImpactVisibleLimit {
			impact.Visible = append(impact.Visible, row)
		} else {
			impact.Overflow = append(impact.Overflow, row)
		}
	}
	return impact, nil
}

func (s *Server) freezesPageData(repositories []domain.Repository, freezes []freezeView, branchOptions []managedBranchOption, state freezesPageState, csrfToken string, currentUser currentUserView) freezesPageData {
	data := freezesPageData{
		AppName:                 s.cfg.AppName,
		PageTitle:               "Freezes",
		ActivePage:              "freezes",
		CurrentUser:             currentUser,
		EnforceableRepositories: enforcementActiveRepositories(repositories),
		BranchOptions:           branchOptions,
		FormError:               state.FormError,
		ActionError:             state.ActionError,
		FreezeForm:              state.FreezeForm,
		CSRFToken:               csrfToken,
		CSRFField:               csrfFormField,
		RequiredContext:         domain.RequiredStatusContext,
	}
	if state.Notice != "" {
		tone := state.NoticeTone
		if tone == "" {
			tone = "success"
		}
		data.Toasts = []toastView{{Message: state.Notice, Tone: tone, DismissHref: "/freezes"}}
	}
	data.ActiveFreezes = make([]activeFreezeCard, 0, len(freezes))
	for _, view := range freezes {
		data.ActiveFreezes = append(data.ActiveFreezes, activeFreezeCard{
			freezeView: view,
			CSRFToken:  csrfToken,
			CSRFField:  csrfFormField,
			CanFreeze:  currentUser.CanFreeze,
		})
	}
	return data
}

// renderFreezes loads live data and renders the full /freezes page with the
// given status code (200 for views, 400 for non-HX validation errors).
func (s *Server) renderFreezes(w http.ResponseWriter, r *http.Request, statusCode int, state freezesPageState, session sessionState) {
	data, ok := s.loadFreezesPageData(w, r, state, session)
	if !ok {
		return
	}
	if statusCode != http.StatusOK {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(statusCode)
	}
	s.renderPage(w, "layouts/freezes", data)
}

// renderFreezesFragment re-loads live data and renders one of the htmx swap
// payloads ("components/freezes-live-fragment" for create,
// "components/active-freezes-fragment" for lift/cancel).
func (s *Server) renderFreezesFragment(w http.ResponseWriter, r *http.Request, name string, state freezesPageState, session sessionState, toast *toastView) {
	data, ok := s.loadFreezesPageData(w, r, state, session)
	if !ok {
		return
	}
	s.renderPage(w, name, freezesFragment{Data: data, Toast: toast})
}

// handleFreezeImpact refreshes the #freeze-impact panel when the form's
// repository or branch selection changes. GET-only enhancement endpoint: no
// CSRF, htmx requests get the fragment, everything else goes back to the full
// page. An unknown pair simply previews zero pull requests.
func (s *Server) handleFreezeImpact(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	if !isHXRequest(r) {
		http.Redirect(w, r, "/freezes", http.StatusSeeOther)
		return
	}
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	form := freezeFormState{
		Submitted:    true,
		RepositoryID: repositoryID,
		Branch:       r.URL.Query().Get("branch"),
	}
	repositories, err := s.repositories(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	branchOptions, err := s.managedBranchOptions(r.Context(), repositories)
	if err != nil {
		internalServerError(w)
		return
	}
	impact, err := s.freezeImpact(r.Context(), repositories, branchOptions, form, currentUserFromSession(session).CanFreeze)
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderPage(w, "components/freeze-impact", impact)
}

// loadFreezesPageData assembles the full /freezes view model, including the
// freeze-impact preview for the submitted (or default) repository/branch
// pair. Writes a 500 and returns ok=false on load failure.
func (s *Server) loadFreezesPageData(w http.ResponseWriter, r *http.Request, state freezesPageState, session sessionState) (freezesPageData, bool) {
	repositories, freezes, branchOptions, usersByID, err := s.freezePageData(r.Context())
	if err != nil {
		internalServerError(w)
		return freezesPageData{}, false
	}
	currentUser := currentUserFromSession(session)
	impact, err := s.freezeImpact(r.Context(), repositories, branchOptions, state.FreezeForm, currentUser.CanFreeze)
	if err != nil {
		internalServerError(w)
		return freezesPageData{}, false
	}
	data := s.freezesPageData(repositories, s.freezeViews(repositories, freezes, usersByID), branchOptions, state, session.CSRFToken, currentUser)
	data.Impact = impact
	return data, true
}
