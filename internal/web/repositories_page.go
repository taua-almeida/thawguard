package web

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type repositoryView struct {
	Repository           domain.Repository
	SetupChecks          []setupcheck.Check
	RepositoryChecks     []setupcheck.Check
	Branches             []repositoryBranchView
	LastCheckedAt        string
	EnforcementLabel     string
	EnforcementTone      string
	StatusPostVerifiedAt string
	IsSetupIncomplete    bool
	IsReady              bool
	IsUnhealthy          bool
	// EnforcementFailedAt and FailureRemediation present the stored sanitized
	// enforcement failure (timestamp formatted, remediation mapped from the
	// stable reason category) for the unhealthy state.
	EnforcementFailedAt string
	FailureRemediation  string
	RecoveryInProgress  bool
	RecoveryAttempts    int
	NextRecoveryAt      string
	// VerifyAvailable is true when the latest recorded readiness run has
	// every mandatory read-only check OK; the POST re-runs readiness, so this
	// only controls whether the action is offered.
	VerifyAvailable      bool
	VerifyBlockedReason  string
	ActiveFreezeCount    int
	PendingScheduleCount int
	// Lifecycle renders the Setup → Ready → Active rail; the Active node is
	// marked broken while enforcement is unhealthy.
	Lifecycle []lifecycleNode
}

// Compact reports whether the card collapses to a summary row. States that
// need no operator attention (ready, active) collapse so large installs stay
// scannable; unhealthy and setup-incomplete repositories always render the
// full card.
func (v repositoryView) Compact() bool {
	state := v.Repository.EnforcementState
	return state == domain.EnforcementReady || state == domain.EnforcementActive
}

// lifecycleNode is one step of the enforcement lifecycle rail. State is one
// of the ui/lifecycle primitive states: done, current, todo, or blocked.
type lifecycleNode struct {
	Label string
	State string
}

// repositoryListFilter narrows the repositories page by full-name substring
// and lifecycle state. POST error re-renders always show the unfiltered list.
type repositoryListFilter struct {
	Query string
	State string
}

func (f repositoryListFilter) Active() bool { return f.Query != "" || f.State != "" }

// repositoryStateChip is one lifecycle-state filter link with its total count.
type repositoryStateChip struct {
	Label    string
	URL      string
	Count    int
	Selected bool
}

type repositoryBranchView struct {
	Name          string
	IsDefault     bool
	SetupLabel    string
	SetupTone     string
	LastCheckedAt string
	Checks        []setupcheck.Check
}

type repositoryOverview struct {
	RepositoryCount            int
	WebhookConfiguredCount     int
	StatusTokenConfiguredCount int
	EnforcementActiveCount     int
}

// repositoryCard is the complete rendering context for one repository card:
// the prepared repository view plus the page-shared values its forms and
// admin copy need.
type repositoryCard struct {
	repositoryView
	CSRFToken   string
	CSRFField   string
	CurrentUser currentUserView
	// ActionError carries a per-card validation message for htmx fragment
	// re-renders; the full-page fallback uses repositoriesPageData.FormError.
	ActionError string
	// Expanded forces a compact-tier card to render its disclosure open. Set
	// only on htmx fragment responses: the user just acted inside the card,
	// so the swap must not collapse it.
	Expanded                          bool
	RequiredContext                   string
	SetupStatusContext                string
	WebhookSecretEncryptionConfigured bool
}

// toastView is one transient success/notice message rendered by ui/toast.
type toastView struct {
	Message     string
	Tone        string
	DismissHref string
}

// repositoryCardFragment is the htmx response payload for a repository
// mutation: the refreshed card plus an optional out-of-band success toast.
type repositoryCardFragment struct {
	Card  repositoryCard
	Toast *toastView
}

// repositoriesPageData is the explicit, fully prepared model for the
// Repositories page. Every field the templates read is declared here; all
// domain and permission decisions happen before rendering.
type repositoriesPageData struct {
	AppName                           string
	PageTitle                         string
	Theme                             string
	ActivePage                        string
	Overview                          repositoryOverview
	RepositoryViews                   []repositoryCard
	Filter                            repositoryListFilter
	StateChips                        []repositoryStateChip
	TotalCount                        int
	VisibleCount                      int
	FormError                         string
	Toasts                            []toastView
	CSRFToken                         string
	CSRFField                         string
	CurrentUser                       currentUserView
	RequiredContext                   string
	SetupStatusContext                string
	WebhookSecretEncryptionConfigured bool
}

func (s *Server) repositoryViews(ctx context.Context, scope repositoryscope.ReadScope, repositories []domain.Repository) ([]repositoryView, error) {
	jobsByRepository := make(map[int64]jobs.Job)
	activeFreezesByRepository := make(map[int64]int)
	pendingSchedulesByRepository := make(map[int64]int)
	if s.cfg.ReconciliationJobStore != nil {
		pending, err := s.cfg.ReconciliationJobStore.ListReconciliationsForScope(ctx, scope)
		if err != nil {
			return nil, err
		}
		for _, job := range pending {
			jobsByRepository[job.RepositoryID] = job
		}
	}
	activeFreezes, err := s.activeFreezes(ctx, scope)
	if err != nil {
		return nil, err
	}
	for _, activeFreeze := range activeFreezes {
		activeFreezesByRepository[activeFreeze.RepositoryID]++
	}
	if s.cfg.ScheduledFreezeStore != nil {
		pendingSchedulesByRepository, err = s.cfg.ScheduledFreezeStore.PendingScheduledCountsForScope(ctx, scope)
		if err != nil {
			return nil, err
		}
	}
	views := make([]repositoryView, 0, len(repositories))
	for _, repo := range repositories {
		view := repositoryView{Repository: repo}
		view.ActiveFreezeCount = activeFreezesByRepository[repo.ID]
		view.PendingScheduleCount = pendingSchedulesByRepository[repo.ID]
		view.EnforcementLabel, view.EnforcementTone = enforcementView(repo.EnforcementState)
		view.Lifecycle = lifecycleRail(repo.EnforcementState)
		view.IsSetupIncomplete = repo.EnforcementState == domain.EnforcementSetupIncomplete
		view.IsReady = repo.EnforcementState == domain.EnforcementReady
		view.IsUnhealthy = repo.EnforcementState == domain.EnforcementUnhealthy
		if repo.StatusPostVerifiedAt != nil {
			view.StatusPostVerifiedAt = formatReadinessTime(*repo.StatusPostVerifiedAt)
		}
		if repo.EnforcementFailedAt != nil {
			view.EnforcementFailedAt = formatReadinessTime(*repo.EnforcementFailedAt)
		}
		if view.IsUnhealthy {
			view.FailureRemediation = enforcementFailureRemediation(repo.EnforcementFailureReason)
			if job, ok := jobsByRepository[repo.ID]; ok {
				view.RecoveryAttempts = job.Attempts
				view.RecoveryInProgress = job.LeaseActive(time.Now().UTC())
				if !view.RecoveryInProgress {
					view.NextRecoveryAt = formatReadinessTime(job.RunAt)
				}
			}
		}
		if s.cfg.SetupCheckStore != nil {
			checks, err := s.cfg.SetupCheckStore.ListByRepository(ctx, repo.ID)
			if err != nil {
				return nil, err
			}
			view.SetupChecks = latestSetupChecks(checks)
			if len(view.SetupChecks) > 0 {
				view.LastCheckedAt = formatReadinessTime(view.SetupChecks[0].CheckedAt)
			}
		}
		branches, err := s.managedBranches(ctx, repo.ID)
		if err != nil {
			return nil, err
		}
		view.RepositoryChecks, view.Branches = groupReadinessChecks(repo, branches, view.SetupChecks)
		if view.IsSetupIncomplete {
			view.VerifyAvailable, view.VerifyBlockedReason = verifyActionAvailability(view.SetupChecks)
		}
		views = append(views, view)
	}
	return views, nil
}

// verifyActionAvailability decides whether the Verify status posting action
// is offered based on the latest recorded readiness run. Every mandatory
// read-only check must be OK; the expected status-posting-untested warning is
// the only allowed non-OK result.
func verifyActionAvailability(latest []setupcheck.Check) (bool, string) {
	if len(latest) == 0 {
		return false, "Run the read-only readiness checks first. Verification is offered once every mandatory check passes."
	}
	for _, check := range latest {
		if check.Result.Status == setupcheck.StatusOK {
			continue
		}
		if check.Result.Name == setupcheck.CheckStatusPostingUntested && check.Result.Status == setupcheck.StatusWarning {
			continue
		}
		return false, "Fix the failing readiness checks and rerun them. Verification is offered once every mandatory read-only check passes."
	}
	return true, ""
}

func groupReadinessChecks(repo domain.Repository, branches []domain.RepositoryBranch, checks []setupcheck.Check) ([]setupcheck.Check, []repositoryBranchView) {
	repositoryChecks := make([]setupcheck.Check, 0)
	checksByBranch := make(map[string][]setupcheck.Check)
	for _, check := range checks {
		if check.Branch == "" {
			repositoryChecks = append(repositoryChecks, check)
			continue
		}
		checksByBranch[check.Branch] = append(checksByBranch[check.Branch], check)
	}
	views := make([]repositoryBranchView, 0, len(branches))
	for _, branch := range branches {
		branchChecks := checksByBranch[branch.Name]
		label, tone := readinessStatus(branchChecks)
		lastCheckedAt := ""
		if branch.LastCheckedAt != nil {
			lastCheckedAt = formatReadinessTime(*branch.LastCheckedAt)
		}
		views = append(views, repositoryBranchView{
			Name:          branch.Name,
			IsDefault:     branch.Name == repo.DefaultBranch,
			SetupLabel:    label,
			SetupTone:     tone,
			LastCheckedAt: lastCheckedAt,
			Checks:        branchChecks,
		})
	}
	return repositoryChecks, views
}

// readinessStatus summarizes a branch's latest checks as a badge label and
// ui/badge tone.
func readinessStatus(checks []setupcheck.Check) (string, string) {
	if len(checks) == 0 {
		return "not checked", "warning"
	}
	status := setupcheck.StatusOK
	for _, check := range checks {
		if check.Result.Status == setupcheck.StatusFailed {
			return "failed", "danger"
		}
		if check.Result.Status == setupcheck.StatusWarning {
			status = setupcheck.StatusWarning
		}
	}
	if status == setupcheck.StatusWarning {
		return "warning", "warning"
	}
	return "passed", "success"
}

// enforcementFailureRemediation maps the stable stored failure categories to
// concrete operator guidance shown next to the unhealthy state.
func enforcementFailureRemediation(reason string) string {
	switch reason {
	case domain.EnforcementFailureReadinessChecks:
		return "Fix the failing read-only readiness checks below (branch protection, required context, webhook evidence, token access), rerun them, then retry enforcement recovery."
	case domain.EnforcementFailureSetupStatusPost:
		return "The stored status token could not post a commit status. Fix the token permissions or forge setup, then retry enforcement recovery."
	case domain.EnforcementFailureOpenPRSync:
		return "Open pull requests could not be listed from the forge. Check forge availability and token read access, then retry enforcement recovery."
	case domain.EnforcementFailureEvaluation:
		return "The current freeze policy could not be evaluated. Review activity for the failed run, then retry enforcement recovery."
	case domain.EnforcementFailurePublication:
		return "One or more " + domain.RequiredStatusContext + " statuses could not be posted. Check forge availability and token permissions, then retry enforcement recovery."
	case domain.EnforcementFailureRuntime:
		return "Runtime convergence bookkeeping did not complete. Automatic recovery will rerun the complete current repository policy."
	default:
		return "Review the sanitized failure in activity, fix the forge setup or credentials, then retry enforcement recovery."
	}
}

// enforcementView maps the enforcement state to a badge label and ui/badge
// tone.
func enforcementView(state domain.EnforcementState) (string, string) {
	switch state {
	case domain.EnforcementActive:
		return "enforcement active", "success"
	case domain.EnforcementUnhealthy:
		return "unhealthy", "danger"
	case domain.EnforcementReady:
		return "ready", "info"
	default:
		return "setup incomplete", "warning"
	}
}

func lifecycleRail(state domain.EnforcementState) []lifecycleNode {
	switch state {
	case domain.EnforcementReady:
		return []lifecycleNode{{"Setup", "done"}, {"Ready", "current"}, {"Active", "todo"}}
	case domain.EnforcementActive:
		return []lifecycleNode{{"Setup", "done"}, {"Ready", "done"}, {"Active", "current"}}
	case domain.EnforcementUnhealthy:
		return []lifecycleNode{{"Setup", "done"}, {"Ready", "done"}, {"Active", "blocked"}}
	default:
		return []lifecycleNode{{"Setup", "current"}, {"Ready", "todo"}, {"Active", "todo"}}
	}
}

// repositoryStateFilters maps URL-safe filter values to lifecycle states, in
// attention-first display order.
var repositoryStateFilters = []struct {
	Value string
	Label string
	State domain.EnforcementState
}{
	{"unhealthy", "Unhealthy", domain.EnforcementUnhealthy},
	{"setup-incomplete", "Setup incomplete", domain.EnforcementSetupIncomplete},
	{"ready", "Ready", domain.EnforcementReady},
	{"active", "Active", domain.EnforcementActive},
}

func parseRepositoryListFilter(query url.Values) repositoryListFilter {
	filter := repositoryListFilter{Query: strings.TrimSpace(query.Get("q"))}
	state := strings.TrimSpace(query.Get("state"))
	for _, option := range repositoryStateFilters {
		if option.Value == state {
			filter.State = state
			break
		}
	}
	return filter
}

func (f repositoryListFilter) matches(view repositoryView) bool {
	if f.Query != "" && !strings.Contains(strings.ToLower(view.Repository.FullName()), strings.ToLower(f.Query)) {
		return false
	}
	if f.State != "" {
		for _, option := range repositoryStateFilters {
			if option.Value == f.State {
				return view.Repository.EnforcementState == option.State
			}
		}
		return false
	}
	return true
}

func filterRepositoryViews(views []repositoryView, filter repositoryListFilter) []repositoryView {
	if !filter.Active() {
		return views
	}
	visible := make([]repositoryView, 0, len(views))
	for _, view := range views {
		if filter.matches(view) {
			visible = append(visible, view)
		}
	}
	return visible
}

// sortRepositoryViewsByAttention orders the list so states needing operator
// action come first: unhealthy, setup incomplete, ready, then active.
func sortRepositoryViewsByAttention(views []repositoryView) {
	rank := func(state domain.EnforcementState) int {
		switch state {
		case domain.EnforcementUnhealthy:
			return 0
		case domain.EnforcementSetupIncomplete:
			return 1
		case domain.EnforcementReady:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(views, func(i, j int) bool {
		ri, rj := rank(views[i].Repository.EnforcementState), rank(views[j].Repository.EnforcementState)
		if ri != rj {
			return ri < rj
		}
		return views[i].Repository.FullName() < views[j].Repository.FullName()
	})
}

func repositoryListURL(query, state string) string {
	values := url.Values{}
	if query != "" {
		values.Set("q", query)
	}
	if state != "" {
		values.Set("state", state)
	}
	if len(values) == 0 {
		return "/repositories"
	}
	return "/repositories?" + values.Encode()
}

func repositoryStateChips(views []repositoryView, filter repositoryListFilter) []repositoryStateChip {
	queryOnly := filter
	queryOnly.State = ""
	matchingQuery := filterRepositoryViews(views, queryOnly)
	counts := make(map[domain.EnforcementState]int)
	for _, view := range matchingQuery {
		counts[view.Repository.EnforcementState]++
	}
	chips := []repositoryStateChip{{Label: "All", URL: repositoryListURL(filter.Query, ""), Count: len(matchingQuery), Selected: filter.State == ""}}
	for _, option := range repositoryStateFilters {
		chips = append(chips, repositoryStateChip{
			Label:    option.Label,
			URL:      repositoryListURL(filter.Query, option.Value),
			Count:    counts[option.State],
			Selected: filter.State == option.Value,
		})
	}
	return chips
}

func formatReadinessTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func latestSetupChecks(checks []setupcheck.Check) []setupcheck.Check {
	if len(checks) == 0 {
		return nil
	}
	checkedAt := checks[0].CheckedAt
	latest := make([]setupcheck.Check, 0, len(checks))
	for _, check := range checks {
		if !check.CheckedAt.Equal(checkedAt) {
			break
		}
		latest = append(latest, check)
	}
	return latest
}

func (s *Server) renderRepositories(w http.ResponseWriter, views []repositoryView, formError string, session sessionState) {
	s.renderRepositoriesPage(w, views, formError, "", session, repositoryListFilter{})
}

func (s *Server) renderRepositoriesPage(w http.ResponseWriter, views []repositoryView, formError, notice string, session sessionState, filter repositoryListFilter) {
	data := s.repositoriesPageData(views, formError, notice, session.CSRFToken, currentUserFromSession(session), filter)
	s.renderPage(w, "layouts/repositories", data)
}

// repositoriesPageData assembles the full page model from prepared views; it
// is shared by the live renderer and the dev-only preview fixtures.
func (s *Server) repositoriesPageData(views []repositoryView, formError, notice, csrfToken string, currentUser currentUserView, filter repositoryListFilter) repositoriesPageData {
	overview := repositoryOverview{RepositoryCount: len(views)}
	for _, view := range views {
		if view.Repository.HasWebhookSecret {
			overview.WebhookConfiguredCount++
		}
		if view.Repository.HasStatusToken {
			overview.StatusTokenConfiguredCount++
		}
		if view.Repository.EnforcementActive() {
			overview.EnforcementActiveCount++
		}
	}
	sortRepositoryViewsByAttention(views)
	visible := filterRepositoryViews(views, filter)
	data := repositoriesPageData{
		AppName:                           s.cfg.AppName,
		PageTitle:                         "Repositories",
		ActivePage:                        "repositories",
		Overview:                          overview,
		Filter:                            filter,
		StateChips:                        repositoryStateChips(views, filter),
		TotalCount:                        len(views),
		VisibleCount:                      len(visible),
		FormError:                         formError,
		CSRFToken:                         csrfToken,
		CSRFField:                         csrfFormField,
		CurrentUser:                       currentUser,
		RequiredContext:                   domain.RequiredStatusContext,
		SetupStatusContext:                domain.SetupStatusContext,
		WebhookSecretEncryptionConfigured: s.cfg.RepositorySecretEncryptionConfigured,
	}
	if notice != "" {
		data.Toasts = []toastView{{Message: notice, Tone: "success", DismissHref: "/repositories"}}
	}
	data.RepositoryViews = make([]repositoryCard, 0, len(visible))
	for _, view := range visible {
		data.RepositoryViews = append(data.RepositoryViews, repositoryCard{
			repositoryView:                    view,
			CSRFToken:                         data.CSRFToken,
			CSRFField:                         data.CSRFField,
			CurrentUser:                       data.CurrentUser,
			RequiredContext:                   data.RequiredContext,
			SetupStatusContext:                data.SetupStatusContext,
			WebhookSecretEncryptionConfigured: data.WebhookSecretEncryptionConfigured,
		})
	}
	return data
}

// repositoryCardByID rebuilds the current repository views and returns the
// fully prepared card for one repository, for htmx fragment responses.
func (s *Server) repositoryCardByID(ctx context.Context, repositoryID int64, session sessionState) (repositoryCard, bool, error) {
	scope := session.Grants.RepositoryReadScope()
	repositories, err := s.repositories(ctx, scope)
	if err != nil {
		return repositoryCard{}, false, err
	}
	views, err := s.repositoryViews(ctx, scope, repositories)
	if err != nil {
		return repositoryCard{}, false, err
	}
	for _, view := range views {
		if view.Repository.ID != repositoryID {
			continue
		}
		return repositoryCard{
			repositoryView:                    view,
			CSRFToken:                         session.CSRFToken,
			CSRFField:                         csrfFormField,
			CurrentUser:                       currentUserFromSession(session),
			Expanded:                          true,
			RequiredContext:                   domain.RequiredStatusContext,
			SetupStatusContext:                domain.SetupStatusContext,
			WebhookSecretEncryptionConfigured: s.cfg.RepositorySecretEncryptionConfigured,
		}, true, nil
	}
	return repositoryCard{}, false, nil
}
