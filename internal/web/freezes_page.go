package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
)

type freezeView struct {
	Freeze          domain.BranchFreeze
	Repository      domain.Repository
	PlannedEndsAt   string
	HasPlannedEndAt bool
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
	FormError  string
	FreezeForm freezeFormState
}

type freezesPageData struct {
	AppName                 string
	ActivePage              string
	CurrentUser             currentUserView
	EnforceableRepositories []domain.Repository
	BranchOptions           []managedBranchOption
	ActiveFreezes           []activeFreezeCard
	FormError               string
	FreezeForm              freezeFormState
	CSRFToken               string
	CSRFField               string
	RequiredContext         string
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

func (s *Server) freezePageData(ctx context.Context) ([]domain.Repository, []domain.BranchFreeze, []managedBranchOption, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	freezes, err := s.activeFreezes(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	branchOptions, err := s.managedBranchOptions(ctx, repositories)
	if err != nil {
		return nil, nil, nil, err
	}
	return repositories, freezes, branchOptions, nil
}

func (s *Server) freezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze) []freezeView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]freezeView, 0, len(freezes))
	for _, freeze := range freezes {
		views = append(views, freezeView{
			Freeze:          freeze,
			Repository:      repositoriesByID[freeze.RepositoryID],
			PlannedEndsAt:   optionalScheduleTime(freeze.PlannedEndsAt),
			HasPlannedEndAt: freeze.PlannedEndsAt != nil && !freeze.PlannedEndsAt.IsZero(),
		})
	}
	return views
}

func (s *Server) renderFreezes(w http.ResponseWriter, repositories []domain.Repository, freezes []freezeView, branchOptions []managedBranchOption, state freezesPageState, session sessionState) {
	currentUser := currentUserFromSession(session)
	data := freezesPageData{
		AppName:                 s.cfg.AppName,
		ActivePage:              "freezes",
		CurrentUser:             currentUser,
		EnforceableRepositories: enforcementActiveRepositories(repositories),
		BranchOptions:           branchOptions,
		FormError:               state.FormError,
		FreezeForm:              state.FreezeForm,
		CSRFToken:               session.CSRFToken,
		CSRFField:               csrfFormField,
		RequiredContext:         domain.RequiredStatusContext,
	}
	data.ActiveFreezes = make([]activeFreezeCard, 0, len(freezes))
	for _, view := range freezes {
		data.ActiveFreezes = append(data.ActiveFreezes, activeFreezeCard{
			freezeView: view,
			CSRFToken:  data.CSRFToken,
			CSRFField:  data.CSRFField,
			CanFreeze:  currentUser.CanFreeze,
		})
	}
	s.renderPage(w, "layouts/freezes", data)
}
