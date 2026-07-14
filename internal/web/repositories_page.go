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
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type repositoryView struct {
	Repository           domain.Repository
	SetupChecks          []setupcheck.Check
	RepositoryChecks     []setupcheck.Check
	Branches             []repositoryBranchView
	LastCheckedAt        string
	EnforcementLabel     string
	EnforcementClass     string
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

// lifecycleNode is one step of the enforcement lifecycle rail.
type lifecycleNode struct {
	Label string
	Class string
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
	SetupClass    string
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
	CSRFToken                         string
	CSRFField                         string
	CurrentUser                       currentUserView
	RequiredContext                   string
	SetupStatusContext                string
	WebhookSecretEncryptionConfigured bool
}

// repositoriesPageData is the explicit, fully prepared model for the
// Repositories page. Every field the templates read is declared here; all
// domain and permission decisions happen before rendering.
type repositoriesPageData struct {
	AppName                           string
	ActivePage                        string
	Overview                          repositoryOverview
	RepositoryViews                   []repositoryCard
	Filter                            repositoryListFilter
	StateChips                        []repositoryStateChip
	TotalCount                        int
	VisibleCount                      int
	FormError                         string
	Notice                            string
	CSRFToken                         string
	CSRFField                         string
	CurrentUser                       currentUserView
	RequiredContext                   string
	SetupStatusContext                string
	WebhookSecretEncryptionConfigured bool
}

func (s *Server) repositoryViews(ctx context.Context, repositories []domain.Repository) ([]repositoryView, error) {
	jobsByRepository := make(map[int64]jobs.Job)
	activeFreezesByRepository := make(map[int64]int)
	pendingSchedulesByRepository := make(map[int64]int)
	if s.cfg.ReconciliationJobStore != nil {
		pending, err := s.cfg.ReconciliationJobStore.ListReconciliations(ctx)
		if err != nil {
			return nil, err
		}
		for _, job := range pending {
			jobsByRepository[job.RepositoryID] = job
		}
	}
	activeFreezes, err := s.activeFreezes(ctx)
	if err != nil {
		return nil, err
	}
	for _, activeFreeze := range activeFreezes {
		activeFreezesByRepository[activeFreeze.RepositoryID]++
	}
	scheduled, err := s.scheduledFreezes(ctx, 500)
	if err != nil {
		return nil, err
	}
	for _, scheduledFreeze := range scheduled {
		if scheduledFreeze.Status == domain.BranchFreezeStatusScheduled {
			pendingSchedulesByRepository[scheduledFreeze.RepositoryID]++
		}
	}
	views := make([]repositoryView, 0, len(repositories))
	for _, repo := range repositories {
		view := repositoryView{Repository: repo}
		view.ActiveFreezeCount = activeFreezesByRepository[repo.ID]
		view.PendingScheduleCount = pendingSchedulesByRepository[repo.ID]
		view.EnforcementLabel, view.EnforcementClass = enforcementView(repo.EnforcementState)
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
		label, class := readinessStatus(branchChecks)
		lastCheckedAt := ""
		if branch.LastCheckedAt != nil {
			lastCheckedAt = formatReadinessTime(*branch.LastCheckedAt)
		}
		views = append(views, repositoryBranchView{
			Name:          branch.Name,
			IsDefault:     branch.Name == repo.DefaultBranch,
			SetupLabel:    label,
			SetupClass:    class,
			LastCheckedAt: lastCheckedAt,
			Checks:        branchChecks,
		})
	}
	return repositoryChecks, views
}

func readinessStatus(checks []setupcheck.Check) (string, string) {
	if len(checks) == 0 {
		return "not checked", "status-warning"
	}
	status := setupcheck.StatusOK
	for _, check := range checks {
		if check.Result.Status == setupcheck.StatusFailed {
			return "failed", "status-failed"
		}
		if check.Result.Status == setupcheck.StatusWarning {
			status = setupcheck.StatusWarning
		}
	}
	if status == setupcheck.StatusWarning {
		return "warning", "status-warning"
	}
	return "passed", "status-ok"
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

func enforcementView(state domain.EnforcementState) (string, string) {
	switch state {
	case domain.EnforcementActive:
		return "enforcement active", "status-ok"
	case domain.EnforcementUnhealthy:
		return "unhealthy", "status-failed"
	case domain.EnforcementReady:
		return "ready", "status-warning"
	default:
		return "setup incomplete", "status-warning"
	}
}

func lifecycleRail(state domain.EnforcementState) []lifecycleNode {
	switch state {
	case domain.EnforcementReady:
		return []lifecycleNode{{"Setup", "is-done"}, {"Ready", "is-current"}, {"Active", "is-pending"}}
	case domain.EnforcementActive:
		return []lifecycleNode{{"Setup", "is-done"}, {"Ready", "is-done"}, {"Active", "is-current"}}
	case domain.EnforcementUnhealthy:
		return []lifecycleNode{{"Setup", "is-done"}, {"Ready", "is-done"}, {"Active", "is-broken"}}
	default:
		return []lifecycleNode{{"Setup", "is-current"}, {"Ready", "is-pending"}, {"Active", "is-pending"}}
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
		ActivePage:                        "repositories",
		Overview:                          overview,
		Filter:                            filter,
		StateChips:                        repositoryStateChips(views, filter),
		TotalCount:                        len(views),
		VisibleCount:                      len(visible),
		FormError:                         formError,
		Notice:                            notice,
		CSRFToken:                         session.CSRFToken,
		CSRFField:                         csrfFormField,
		CurrentUser:                       currentUserFromSession(session),
		RequiredContext:                   domain.RequiredStatusContext,
		SetupStatusContext:                domain.SetupStatusContext,
		WebhookSecretEncryptionConfigured: s.cfg.RepositorySecretEncryptionConfigured,
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
	s.renderPage(w, "layouts/repositories", data)
}
