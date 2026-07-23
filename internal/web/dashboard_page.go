package web

import (
	"context"
	"fmt"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

const (
	// dashboardActiveFreezePreviewLimit caps the active-freezes panel; the
	// "View all N →" link carries the real total when rows are cut off.
	dashboardActiveFreezePreviewLimit = 5
	dashboardScheduledPreviewLimit    = 3
	dashboardActivityPreviewLimit     = 6
)

type dashboardPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	RepositoryCount      int
	EnforcingCount       int
	SetupIncompleteCount int
	ActiveFreezeCount    int
	ScheduledFreezeCount int
	ActiveThawCount      int

	ActiveFreezes    []freezeView
	ScheduledFreezes []scheduledFreezeView
	RecentActivity   []activityEventView
	CanStartFreeze   bool
	CanReviewThaws   bool
}

// dashboardPageData assembles the read-only overview: real counts for every
// stat, the first rows of each owning page as panel previews, and the newest
// audit events through the same curated view mapping /activity uses. Optional
// stores (audit, thaw exceptions) degrade to empty panels and zero stats.
func (s *Server) dashboardPageData(ctx context.Context, session sessionState) (dashboardPageData, error) {
	scope := session.Grants.RepositoryReadScope()
	repositories, err := s.repositories(ctx, scope)
	if err != nil {
		return dashboardPageData{}, err
	}
	freezes, err := s.activeFreezes(ctx, scope)
	if err != nil {
		return dashboardPageData{}, err
	}
	var scheduled []domain.BranchFreeze
	scheduledTotal := 0
	if s.cfg.ScheduledFreezeStore != nil {
		scheduled, scheduledTotal, err = s.cfg.ScheduledFreezeStore.ListScheduledPageForScope(ctx, scope, domain.BranchFreezeStatusScheduled, 0, dashboardScheduledPreviewLimit)
		if err != nil {
			return dashboardPageData{}, err
		}
	}
	var users []auth.User
	if s.cfg.AuthService != nil {
		users, err = s.cfg.AuthService.ListUsers(ctx)
		if err != nil {
			return dashboardPageData{}, fmt.Errorf("list users for dashboard attribution: %w", err)
		}
	}
	var events []audit.Event
	if s.cfg.AuditStore != nil {
		events, err = s.cfg.AuditStore.ListForScope(ctx, scope, dashboardActivityPreviewLimit)
		if err != nil {
			return dashboardPageData{}, err
		}
	}
	activeThawCount := 0
	if s.cfg.ThawExceptionStore != nil {
		activeThawCount, err = s.cfg.ThawExceptionStore.CountActiveForScope(ctx, scope)
		if err != nil {
			return dashboardPageData{}, err
		}
	}

	enforcingCount := 0
	canStartFreeze, canReviewThaws := false, false
	for _, repo := range repositories {
		if repo.EnforcementActive() {
			enforcingCount++
			canStartFreeze = canStartFreeze || session.Grants.CanFreezeRepository(repo.ID)
			canReviewThaws = canReviewThaws || session.Grants.CanThawRepository(repo.ID)
		}
	}

	usersByID := make(map[int64]auth.User, len(users))
	for _, user := range users {
		usersByID[user.ID] = user
	}
	freezeViews := s.freezeViews(repositories, freezes, usersByID)
	if len(freezeViews) > dashboardActiveFreezePreviewLimit {
		freezeViews = freezeViews[:dashboardActiveFreezePreviewLimit]
	}
	scheduledViews := scheduledFreezeViews(repositories, scheduled, scheduledFreezePageState{})
	if len(scheduledViews) > dashboardScheduledPreviewLimit {
		scheduledViews = scheduledViews[:dashboardScheduledPreviewLimit]
	}

	currentUser := currentUserFromSession(session)
	currentUser.CanFreeze = canStartFreeze
	currentUser.CanThaw = canReviewThaws
	return dashboardPageData{
		AppName:              s.cfg.AppName,
		PageTitle:            "Dashboard",
		ActivePage:           "dashboard",
		CurrentUser:          currentUser,
		CSRFToken:            session.CSRFToken,
		CSRFField:            csrfFormField,
		RepositoryCount:      len(repositories),
		EnforcingCount:       enforcingCount,
		SetupIncompleteCount: len(repositories) - enforcingCount,
		ActiveFreezeCount:    len(freezes),
		ScheduledFreezeCount: scheduledTotal,
		ActiveThawCount:      activeThawCount,
		ActiveFreezes:        freezeViews,
		ScheduledFreezes:     scheduledViews,
		RecentActivity:       activityEventViews(repositories, users, events),
		CanStartFreeze:       canStartFreeze,
		CanReviewThaws:       canReviewThaws,
	}, nil
}
