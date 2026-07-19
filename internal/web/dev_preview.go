package web

import (
	"html/template"
	"net/http"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

// Dev-only component gallery (GET /dev/preview, GET /dev/preview/auth).
// Registered only when Config.DevMode is true; every handler re-checks the
// flag and 404s otherwise so the pages can never leak into production even
// if route registration changes. All data below is fictional.

type devPreviewToast struct {
	Message     string
	Tone        string
	DismissHref string
}

type devPreviewOption struct {
	Value    string
	Label    string
	Selected bool
}

type devPreviewStep struct {
	Label string
	State string
}

type devPreviewNode struct {
	Label string
	State string
}

type devPreviewView struct {
	AppName      string
	PageTitle    string
	Theme        string
	ActivePage   string
	CurrentUser  currentUserView
	CSRFField    string
	CSRFToken    string
	Toasts       []devPreviewToast
	SelectOpts   []devPreviewOption
	Steps        []devPreviewStep
	Nodes        []devPreviewNode
	TableHeaders []string
	TableRows    [][]string
	FieldControl template.HTML
}

type devPreviewAuthView struct {
	AppName   string
	PageTitle string
	Theme     string
}

func devPreviewTheme(r *http.Request) string {
	switch r.URL.Query().Get("theme") {
	case "dark":
		return "dark"
	case "light":
		return "light"
	}
	return ""
}

func (s *Server) handleDevPreview(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	view := devPreviewView{
		AppName:    s.cfg.AppName,
		PageTitle:  "Component gallery",
		Theme:      devPreviewTheme(r),
		ActivePage: "dashboard",
		CurrentUser: currentUserView{
			Email:                 "mira.frost@example.test",
			DisplayName:           "Mira Frost",
			RoleLabel:             "Admin",
			CanChangePassword:     true,
			IsAdmin:               true,
			CanManageRepositories: true,
			CanFreeze:             true,
			CanThaw:               true,
		},
		CSRFField: csrfFormField,
		CSRFToken: "dev-preview-fictional-token",
		Toasts: []devPreviewToast{
			{Message: "Freeze started for aurora/ice-station.", Tone: "success", DismissHref: "/dev/preview"},
			{Message: "Webhook secret for glacier/perma-lab has not been verified yet.", Tone: "warning", DismissHref: "/dev/preview"},
		},
		SelectOpts: []devPreviewOption{
			{Value: "aurora/ice-station", Label: "aurora/ice-station", Selected: true},
			{Value: "glacier/perma-lab", Label: "glacier/perma-lab"},
			{Value: "tundra/snowmelt", Label: "tundra/snowmelt"},
		},
		Steps: []devPreviewStep{
			{Label: "Connect repository", State: "done"},
			{Label: "Set webhook secret", State: "done"},
			{Label: "Verify status posting", State: "current"},
			{Label: "Activate enforcement", State: "todo"},
		},
		Nodes: []devPreviewNode{
			{Label: "Scheduled", State: "done"},
			{Label: "Active", State: "current"},
			{Label: "Thaw requested", State: "todo"},
			{Label: "Blocked", State: "blocked"},
		},
		TableHeaders: []string{"Repository", "Branch", "State", "Since"},
		TableRows: [][]string{
			{"aurora/ice-station", "main", "Frozen", "2026-07-12"},
			{"glacier/perma-lab", "release/2.4", "Thawed", "2026-07-09"},
			{"tundra/snowmelt", "main", "Scheduled", "2026-07-20"},
		},
		FieldControl: template.HTML(`<textarea id="gallery-notes" name="notes" rows="3" class="w-full rounded-control border border-border-input bg-surface px-3 py-2 text-sm text-text">Extend the freeze through the aurora launch window.</textarea>`),
	}
	s.renderPage(w, "layouts/dev-preview", view)
}

// handleDevPreviewAuth renders the auth shell demo and the real auth screens
// from fictional fixtures (GET /dev/preview/auth). Query knobs:
// ?screen=login|setup|account-password|error (default: shell demo),
// ?state=error|expired|forced, ?code=403|404|500|503, ?signed-out=1,
// ?theme=dark|light. Always answers 200 — the real handlers own status codes.
func (s *Server) handleDevPreviewAuth(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	theme := devPreviewTheme(r)
	state := r.URL.Query().Get("state")
	switch r.URL.Query().Get("screen") {
	case "login":
		data := authLoginData{
			AppName:   s.cfg.AppName,
			PageTitle: "Sign in",
			Theme:     theme,
			CSRFField: csrfFormField,
			CSRFToken: "dev-preview-fictional-token",
		}
		switch state {
		case "error":
			data.FormError = "invalid email or password"
			data.Email = "mira.frost@example.test"
		case "expired":
			data.FormError = "Your sign-in form expired. Please try again."
			data.Email = "mira.frost@example.test"
		}
		s.renderPage(w, "layouts/login", data)
	case "setup":
		data := authSetupData{
			AppName:   s.cfg.AppName,
			PageTitle: "Set up",
			Theme:     theme,
			CSRFField: csrfFormField,
			CSRFToken: "dev-preview-fictional-token",
		}
		if state == "error" {
			data.FormError = "password must be at least 12 characters"
			data.Email = "mira.frost@example.test"
			data.DisplayName = "Mira Frost"
		}
		s.renderPage(w, "layouts/setup", data)
	case "account-password":
		data := authAccountPasswordData{
			AppName:            s.cfg.AppName,
			PageTitle:          "Change password",
			Theme:              theme,
			CSRFField:          csrfFormField,
			CSRFToken:          "dev-preview-fictional-token",
			MustChangePassword: state == "forced",
		}
		if state == "error" {
			data.FormError = "new passwords do not match"
		}
		s.renderPage(w, "layouts/account-password", data)
	case "error":
		status := http.StatusInternalServerError
		switch r.URL.Query().Get("code") {
		case "403":
			status = http.StatusForbidden
		case "404":
			status = http.StatusNotFound
		case "503":
			status = http.StatusServiceUnavailable
		}
		heading, message := errorPageContent(status)
		data := authErrorData{
			AppName:     s.cfg.AppName,
			PageTitle:   heading,
			Theme:       theme,
			Status:      status,
			Heading:     heading,
			Message:     message,
			ActionHref:  "/",
			ActionLabel: "Back to dashboard",
		}
		if r.URL.Query().Get("signed-out") == "1" {
			data.ActionHref = "/login"
			data.ActionLabel = "Sign in"
		}
		s.renderPage(w, "layouts/error", data)
	default:
		s.renderPage(w, "layouts/dev-preview-auth", devPreviewAuthView{
			AppName:   s.cfg.AppName,
			PageTitle: "Auth layout preview",
			Theme:     theme,
		})
	}
}

// handleDevPreviewRepositories renders the repositories page from fictional
// fixtures covering the full state matrix (GET /dev/preview/repositories).
// Query knobs: ?role=viewer, ?variant=empty|no-match|no-encryption,
// ?theme=dark|light.
func (s *Server) handleDevPreviewRepositories(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	user := currentUserView{
		Email:                 "mira.frost@example.test",
		DisplayName:           "Mira Frost",
		RoleLabel:             "Admin",
		CanChangePassword:     true,
		IsAdmin:               true,
		CanManageRepositories: true,
		CanFreeze:             true,
		CanThaw:               true,
	}
	if r.URL.Query().Get("role") == "viewer" {
		user = currentUserView{
			Email:             "sten.hale@example.test",
			DisplayName:       "Sten Hale",
			RoleLabel:         "Viewer",
			CanChangePassword: true,
		}
	}
	views := devPreviewRepositoryViews()
	filter := repositoryListFilter{}
	variant := r.URL.Query().Get("variant")
	switch variant {
	case "empty":
		views = nil
	case "no-match":
		filter.Query = "yeti"
	}
	data := s.repositoriesPageData(views, "", "", "dev-preview-fictional-token", user, filter)
	data.Theme = devPreviewTheme(r)
	// The preview must not depend on whether this dev machine has a real
	// THAWGUARD_SECRET_KEY: encryption is on unless the variant turns it off.
	encryptionConfigured := variant != "no-encryption"
	data.WebhookSecretEncryptionConfigured = encryptionConfigured
	for i := range data.RepositoryViews {
		data.RepositoryViews[i].WebhookSecretEncryptionConfigured = encryptionConfigured
	}
	s.renderPage(w, "layouts/repositories", data)
}

// handleDevPreviewDashboard renders the dashboard from fictional fixtures
// (GET /dev/preview/dashboard). Query knobs: ?role=viewer, ?variant=empty,
// ?theme=dark|light. The default variant is a populated admin view; "empty"
// is a fresh install with zero repositories and no recorded data.
func (s *Server) handleDevPreviewDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	user := currentUserView{
		Email:                 "mira.frost@example.test",
		DisplayName:           "Mira Frost",
		RoleLabel:             "Admin",
		CanChangePassword:     true,
		IsAdmin:               true,
		CanManageRepositories: true,
		CanFreeze:             true,
		CanThaw:               true,
	}
	if r.URL.Query().Get("role") == "viewer" {
		user = currentUserView{
			Email:             "sten.hale@example.test",
			DisplayName:       "Sten Hale",
			RoleLabel:         "Viewer",
			CanChangePassword: true,
		}
	}
	data := dashboardPageData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Dashboard",
		Theme:       devPreviewTheme(r),
		ActivePage:  "dashboard",
		CurrentUser: user,
		CSRFToken:   "dev-preview-fictional-token",
		CSRFField:   csrfFormField,
	}
	if r.URL.Query().Get("variant") == "empty" {
		s.renderPage(w, "layouts/dashboard", data)
		return
	}
	auroraIceStation := domain.Repository{ID: 46, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "aurora", Name: "ice-station", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	borealisFrostAPI := domain.Repository{ID: 47, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "borealis", Name: "frost-api", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	data.RepositoryCount = 4
	data.EnforcingCount = 3
	data.SetupIncompleteCount = 1
	data.ActiveFreezeCount = 6
	data.ScheduledFreezeCount = 2
	data.ActiveThawCount = 1
	data.ActiveFreezes = []freezeView{
		{
			Freeze:         domain.BranchFreeze{ID: 301, RepositoryID: 46, Branch: "main", Reason: "Release cut 2026-07 — QA verification in progress"},
			Repository:     auroraIceStation,
			StartedLabel:   "2026-07-16",
			StartedTitle:   "2026-07-16T14:05:00Z",
			CreatedByLabel: "rana.kall@example.test",
		},
		{
			Freeze:         domain.BranchFreeze{ID: 302, RepositoryID: 47, Branch: "main", Reason: "Incident 4821 — hold deploys until the postmortem lands"},
			Repository:     borealisFrostAPI,
			StartedLabel:   "2026-07-15",
			StartedTitle:   "2026-07-15T22:41:00Z",
			CreatedByLabel: "bootstrap admin",
		},
		{
			Freeze:         domain.BranchFreeze{ID: 304, RepositoryID: 46, Branch: "release/1.8", Reason: "Recurring release-week freeze"},
			Repository:     auroraIceStation,
			StartedLabel:   "2026-07-14",
			StartedTitle:   "2026-07-14T06:00:00Z",
			CreatedByLabel: "via schedule",
		},
		{
			Freeze:         domain.BranchFreeze{ID: 305, RepositoryID: 47, Branch: "main", Reason: "Offboarding hold — access review in progress"},
			Repository:     borealisFrostAPI,
			StartedLabel:   "2026-07-12",
			StartedTitle:   "2026-07-12T11:30:00Z",
			CreatedByLabel: "a removed user",
		},
		{
			// Deleted repository: the zero-value Repository exercises the
			// "Repository #17" fallback; no StartedLabel (pre-backfill row).
			Freeze: domain.BranchFreeze{ID: 303, RepositoryID: 17, Branch: "release/0.9", Reason: "Repository disconnected mid-freeze — evidence retained"},
		},
	}
	data.ScheduledFreezes = []scheduledFreezeView{
		{
			Freeze:           domain.BranchFreeze{ID: 401, RepositoryID: 46, Branch: "main", Reason: "Aurora launch window"},
			Repository:       auroraIceStation,
			StartsAt:         "2026-07-20 06:00 UTC",
			StartsAtUTC:      "2026-07-20T06:00:00Z",
			PlannedEndsAt:    "2026-07-22 18:00 UTC",
			PlannedEndsAtUTC: "2026-07-22T18:00:00Z",
			StatusLabel:      "Pending",
			StateClass:       "pending",
		},
		{
			Freeze:      domain.BranchFreeze{ID: 402, RepositoryID: 47, Branch: "main", Reason: "Quarterly audit hold"},
			Repository:  borealisFrostAPI,
			StartsAt:    "2026-07-28 00:00 UTC",
			StartsAtUTC: "2026-07-28T00:00:00Z",
			StatusLabel: "Pending",
			StateClass:  "pending",
		},
	}
	data.RecentActivity = []activityEventView{
		{CreatedAt: "2026-07-17 11:20 UTC", Actor: "rana.kall@example.test", ActionLabel: "Freeze started", Target: "aurora/ice-station main", Outcome: "Enforced", OutcomeClass: "frozen"},
		{CreatedAt: "2026-07-17 09:02 UTC", Actor: "mira.frost@example.test", ActionLabel: "Thaw approved", Target: "borealis/frost-api pull 241", Outcome: "Granted", OutcomeClass: "ok"},
		{CreatedAt: "2026-07-16 21:40 UTC", ActionLabel: "Status publication", Target: "glacier/perma-lab main", Outcome: "Failed", OutcomeClass: "failed"},
		{CreatedAt: "2026-07-16 18:00 UTC", Actor: "via schedule", ActionLabel: "Scheduled freeze started", Target: "aurora/ice-station release/1.8", Outcome: "Enforced", OutcomeClass: "frozen"},
		{CreatedAt: "2026-07-16 09:12 UTC", Actor: "mira.frost@example.test", ActionLabel: "Setup check", Target: "cirrus/ice-docs main", Outcome: "Warning", OutcomeClass: "warning"},
		{CreatedAt: "2026-07-15 22:41 UTC", Actor: "sten.hale@example.test", ActionLabel: "Repository connected", Target: "borealis/frost-api"},
	}
	s.renderPage(w, "layouts/dashboard", data)
}

func devPreviewCheck(branch, name string, status setupcheck.Status, description, remediation string) setupcheck.Check {
	return setupcheck.Check{
		Branch: branch,
		Result: setupcheck.Result{Name: name, Status: status, Description: description, Remediation: remediation},
	}
}

// devPreviewRepositoryView builds one fictional view with the derived badge,
// tone, and lifecycle fields filled in by the real helpers.
func devPreviewRepositoryView(repo domain.Repository) repositoryView {
	view := repositoryView{Repository: repo}
	view.EnforcementLabel, view.EnforcementTone = enforcementView(repo.EnforcementState)
	view.Lifecycle = lifecycleRail(repo.EnforcementState)
	view.IsSetupIncomplete = repo.EnforcementState == domain.EnforcementSetupIncomplete
	view.IsReady = repo.EnforcementState == domain.EnforcementReady
	view.IsUnhealthy = repo.EnforcementState == domain.EnforcementUnhealthy
	return view
}

func devPreviewBranch(name string, isDefault bool, lastCheckedAt string, checks ...setupcheck.Check) repositoryBranchView {
	label, tone := readinessStatus(checks)
	return repositoryBranchView{Name: name, IsDefault: isDefault, SetupLabel: label, SetupTone: tone, LastCheckedAt: lastCheckedAt, Checks: checks}
}

// devPreviewRepositoryViews covers every card state: unhealthy with recovery
// pending and in progress, setup incomplete with verification blocked and
// available, ready, and active with each deactivation-blocker combination.
// All names, times, and evidence are fictional.
func devPreviewRepositoryViews() []repositoryView {
	protectionOK := devPreviewCheck("", "Branch protection readable", setupcheck.StatusOK, "Branch protection settings could be read for every managed branch.", "")
	webhookOK := devPreviewCheck("", "Webhook evidence recorded", setupcheck.StatusOK, "A signed pull_request webhook delivery has been verified.", "")

	unhealthyPending := devPreviewRepositoryView(domain.Repository{
		ID: 41, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "glacier", Name: "perma-lab",
		DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true,
		EnforcementState: domain.EnforcementUnhealthy, EnforcementFailureReason: domain.EnforcementFailurePublication,
	})
	unhealthyPending.EnforcementFailedAt = "2026-07-16 21:40 UTC"
	unhealthyPending.FailureRemediation = enforcementFailureRemediation(domain.EnforcementFailurePublication)
	unhealthyPending.RecoveryAttempts = 3
	unhealthyPending.NextRecoveryAt = "2026-07-17 06:15 UTC"
	unhealthyPending.LastCheckedAt = "2026-07-16 21:38 UTC"
	unhealthyPending.RepositoryChecks = []setupcheck.Check{
		protectionOK,
		devPreviewCheck("", "Status posting", setupcheck.StatusFailed, "The stored status token was rejected while posting a commit status.", "Rotate the status token, then retry enforcement recovery."),
	}
	unhealthyPending.Branches = []repositoryBranchView{
		devPreviewBranch("main", true, "2026-07-16 21:38 UTC", devPreviewCheck("main", "Required context enforced", setupcheck.StatusOK, "Branch protection requires the merge-gating context.", "")),
		devPreviewBranch("release/2.4", false, "2026-07-16 21:38 UTC", devPreviewCheck("release/2.4", "Required context enforced", setupcheck.StatusFailed, "Branch protection does not require the merge-gating context.", "Add the required context to branch protection.")),
	}

	unhealthyRunning := devPreviewRepositoryView(domain.Repository{
		ID: 42, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "tundra", Name: "snowmelt",
		DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true,
		EnforcementState: domain.EnforcementUnhealthy, EnforcementFailureReason: domain.EnforcementFailureOpenPRSync,
	})
	unhealthyRunning.EnforcementFailedAt = "2026-07-17 02:05 UTC"
	unhealthyRunning.FailureRemediation = enforcementFailureRemediation(domain.EnforcementFailureOpenPRSync)
	unhealthyRunning.RecoveryInProgress = true
	unhealthyRunning.RecoveryAttempts = 1
	unhealthyRunning.LastCheckedAt = "2026-07-17 02:04 UTC"
	unhealthyRunning.RepositoryChecks = []setupcheck.Check{protectionOK, webhookOK}
	unhealthyRunning.Branches = []repositoryBranchView{devPreviewBranch("main", true, "2026-07-17 02:04 UTC")}

	setupBlocked := devPreviewRepositoryView(domain.Repository{
		ID: 43, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "sleet", Name: "queue-runner",
		DefaultBranch: "main", EnforcementState: domain.EnforcementSetupIncomplete,
	})
	setupBlocked.VerifyAvailable, setupBlocked.VerifyBlockedReason = verifyActionAvailability(nil)

	setupVerifiable := devPreviewRepositoryView(domain.Repository{
		ID: 44, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "cirrus", Name: "ice-docs",
		DefaultBranch: "main", HasStatusToken: true,
		EnforcementState: domain.EnforcementSetupIncomplete,
	})
	setupVerifiable.LastCheckedAt = "2026-07-17 09:12 UTC"
	untested := devPreviewCheck("", setupcheck.CheckStatusPostingUntested, setupcheck.StatusWarning, "The status token has not posted a controlled test status yet.", "Run Verify status posting.")
	setupVerifiable.SetupChecks = []setupcheck.Check{protectionOK, untested}
	setupVerifiable.RepositoryChecks = []setupcheck.Check{protectionOK, untested}
	setupVerifiable.Branches = []repositoryBranchView{devPreviewBranch("main", true, "2026-07-17 09:12 UTC", devPreviewCheck("main", "Required context enforced", setupcheck.StatusOK, "Branch protection requires the merge-gating context.", ""))}
	setupVerifiable.VerifyAvailable, setupVerifiable.VerifyBlockedReason = verifyActionAvailability(setupVerifiable.SetupChecks)

	ready := devPreviewRepositoryView(domain.Repository{
		ID: 45, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "rime", Name: "dock-tools",
		DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true,
		EnforcementState: domain.EnforcementReady,
	})
	ready.StatusPostVerifiedAt = "2026-07-17 10:02 UTC"
	ready.LastCheckedAt = "2026-07-17 10:01 UTC"
	ready.RepositoryChecks = []setupcheck.Check{protectionOK, webhookOK}
	ready.Branches = []repositoryBranchView{devPreviewBranch("main", true, "2026-07-17 10:01 UTC", devPreviewCheck("main", "Required context enforced", setupcheck.StatusOK, "Branch protection requires the merge-gating context.", ""))}

	activeFrozen := devPreviewRepositoryView(domain.Repository{
		ID: 46, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "aurora", Name: "ice-station",
		DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true,
		EnforcementState: domain.EnforcementActive,
	})
	activeFrozen.ActiveFreezeCount = 2
	activeFrozen.StatusPostVerifiedAt = "2026-07-12 08:30 UTC"
	activeFrozen.LastCheckedAt = "2026-07-17 11:20 UTC"
	activeFrozen.RepositoryChecks = []setupcheck.Check{protectionOK, webhookOK}
	activeFrozen.Branches = []repositoryBranchView{
		devPreviewBranch("main", true, "2026-07-17 11:20 UTC", devPreviewCheck("main", "Required context enforced", setupcheck.StatusOK, "Branch protection requires the merge-gating context.", "")),
		devPreviewBranch("release/1.8", false, "2026-07-17 11:20 UTC", devPreviewCheck("release/1.8", "Required context enforced", setupcheck.StatusOK, "Branch protection requires the merge-gating context.", "")),
	}

	activeScheduled := devPreviewRepositoryView(domain.Repository{
		ID: 47, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "borealis", Name: "frost-api",
		DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true,
		EnforcementState: domain.EnforcementActive,
	})
	activeScheduled.PendingScheduleCount = 1
	activeScheduled.StatusPostVerifiedAt = "2026-07-10 15:45 UTC"
	activeScheduled.LastCheckedAt = "2026-07-16 18:00 UTC"
	activeScheduled.RepositoryChecks = []setupcheck.Check{protectionOK, webhookOK}
	activeScheduled.Branches = []repositoryBranchView{devPreviewBranch("main", true, "2026-07-16 18:00 UTC")}

	activeIdle := devPreviewRepositoryView(domain.Repository{
		ID: 48, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "polar", Name: "night-watch",
		DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true,
		EnforcementState: domain.EnforcementActive,
	})
	activeIdle.StatusPostVerifiedAt = "2026-07-11 07:19 UTC"
	activeIdle.LastCheckedAt = "2026-07-15 22:41 UTC"
	activeIdle.RepositoryChecks = []setupcheck.Check{protectionOK, webhookOK}
	activeIdle.Branches = []repositoryBranchView{devPreviewBranch("main", true, "2026-07-15 22:41 UTC")}

	return []repositoryView{unhealthyPending, unhealthyRunning, setupBlocked, setupVerifiable, ready, activeFrozen, activeScheduled, activeIdle}
}

// handleDevPreviewFreezes renders the freezes page from fictional fixtures
// covering the full state matrix (GET /dev/preview/freezes). Query knobs:
// ?role=viewer, ?variant=empty|no-repos|form-error|impact-empty|impact-many,
// ?theme=dark|light.
func (s *Server) handleDevPreviewFreezes(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	user := currentUserView{
		Email:             "rana.kall@example.test",
		DisplayName:       "Rana Kall",
		RoleLabel:         "Freezer",
		CanChangePassword: true,
		CanFreeze:         true,
	}
	if r.URL.Query().Get("role") == "viewer" {
		user = currentUserView{
			Email:             "sten.hale@example.test",
			DisplayName:       "Sten Hale",
			RoleLabel:         "Viewer",
			CanChangePassword: true,
		}
	}
	repositories := []domain.Repository{
		{ID: 46, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "aurora", Name: "ice-station", DefaultBranch: "main", EnforcementState: domain.EnforcementActive},
		{ID: 47, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "borealis", Name: "frost-api", DefaultBranch: "main", EnforcementState: domain.EnforcementActive},
	}
	branchOptions := []managedBranchOption{
		{RepositoryID: 46, Name: "main"},
		{RepositoryID: 46, Name: "release/1.8"},
		{RepositoryID: 47, Name: "main"},
	}
	// Created-by fixtures cover all five label variants: user email,
	// bootstrap admin, via schedule, removed user, and the pre-backfill
	// blank (no "by …" part at all).
	freezes := []freezeView{
		{
			Freeze:          domain.BranchFreeze{ID: 301, RepositoryID: 46, Branch: "main", Reason: "Release cut 2026-07 — QA verification in progress"},
			Repository:      repositories[0],
			PlannedEndsAt:   "2026-07-21 09:00 UTC",
			HasPlannedEndAt: true,
			StartedLabel:    "2026-07-16",
			StartedTitle:    "2026-07-16T14:05:00Z",
			CreatedByLabel:  "rana.kall@example.test",
		},
		{
			Freeze:         domain.BranchFreeze{ID: 302, RepositoryID: 47, Branch: "main", Reason: "Incident 4821 — hold deploys until the postmortem lands"},
			Repository:     repositories[1],
			StartedLabel:   "2026-07-15",
			StartedTitle:   "2026-07-15T22:41:00Z",
			CreatedByLabel: "bootstrap admin",
		},
		{
			Freeze:         domain.BranchFreeze{ID: 304, RepositoryID: 46, Branch: "release/1.8", Reason: "Recurring release-week freeze"},
			Repository:     repositories[0],
			StartedLabel:   "2026-07-14",
			StartedTitle:   "2026-07-14T06:00:00Z",
			CreatedByLabel: "via schedule",
		},
		{
			Freeze:         domain.BranchFreeze{ID: 305, RepositoryID: 47, Branch: "main", Reason: "Offboarding hold — access review in progress"},
			Repository:     repositories[1],
			StartedLabel:   "2026-07-12",
			StartedTitle:   "2026-07-12T11:30:00Z",
			CreatedByLabel: "a removed user",
		},
		{
			// Deleted repository: the zero-value Repository makes the page
			// fall back to "Repository #17" while keeping the row liftable.
			// No StartedLabel: pre-backfill row, attribution line omitted.
			Freeze: domain.BranchFreeze{ID: 303, RepositoryID: 17, Branch: "release/0.9", Reason: "Repository disconnected mid-freeze — evidence retained"},
		},
	}
	impact := &impactView{
		Repository:      "aurora/ice-station",
		Branch:          "main",
		Total:           3,
		RequiredContext: domain.RequiredStatusContext,
		Visible: []impactPRView{
			{Index: 241, Title: "Fix retry backoff for status publication", URL: "https://forge.example.test/aurora/ice-station/pulls/241"},
			{Index: 238, Title: "Bump forge client to 1.24 and regenerate fixtures", URL: "https://forge.example.test/aurora/ice-station/pulls/238"},
			{Index: 229, Title: "Docs: webhook rotation runbook", URL: "https://forge.example.test/aurora/ice-station/pulls/229"},
		},
	}
	state := freezesPageState{}
	switch r.URL.Query().Get("variant") {
	case "empty":
		freezes = nil
	case "no-repos":
		repositories = nil
		branchOptions = nil
		freezes = nil
		impact = nil
	case "form-error":
		state.FormError = "planned unfreeze must be in the future"
		state.FreezeForm = freezeFormState{
			Submitted:     true,
			RepositoryID:  46,
			Branch:        "release/1.8",
			Reason:        "Release cut 2026-07 — QA verification in progress",
			PlannedEndsAt: "2026-07-01T09:00",
		}
		impact.Branch = "release/1.8"
		impact.Total = 1
		impact.Visible = []impactPRView{
			{Index: 187, Title: "Backport: clamp planned unfreeze to UTC", URL: "https://forge.example.test/aurora/ice-station/pulls/187"},
		}
	case "impact-empty":
		impact.Total = 0
		impact.Visible = nil
	case "impact-many":
		impact.Total = 8
		impact.Overflow = []impactPRView{
			{Index: 224, Title: "Refactor decision evaluation into pure funcs", URL: "https://forge.example.test/aurora/ice-station/pulls/224"},
			{Index: 219, Title: "Add health-check probe for webhook latency", URL: "https://forge.example.test/aurora/ice-station/pulls/219"},
			{Index: 214, Title: "Chore: tidy module graph", URL: "https://forge.example.test/aurora/ice-station/pulls/214"},
		}
		impact.Visible = append(impact.Visible,
			impactPRView{Index: 236, Title: "Support release/* branch conventions in setup checks with a very long title that truncates", URL: "https://forge.example.test/aurora/ice-station/pulls/236"},
			impactPRView{Index: 231, Title: "Harden webhook signature comparison", URL: "https://forge.example.test/aurora/ice-station/pulls/231"},
		)
	}
	if !user.CanFreeze {
		impact = nil
	}
	data := s.freezesPageData(repositories, freezes, branchOptions, state, "dev-preview-fictional-token", user)
	data.Impact = impact
	data.Theme = devPreviewTheme(r)
	s.renderPage(w, "layouts/freezes", data)
}

// handleDevPreviewDecisions renders the thaw requests page from fictional
// fixtures covering the full state matrix (GET /dev/preview/decisions).
// Query knobs: ?role=viewer, ?variant=empty|no-repos|form-error|
// eligibility-found|eligibility-unfrozen|eligibility-missing|shared-head|
// stale, ?theme=dark|light. The default variant is the approve form with the
// eligibility prompt and one table row per badge tone (plus a deleted-repo
// fallback row).
func (s *Server) handleDevPreviewDecisions(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	user := currentUserView{
		Email:             "mira.frost@example.test",
		DisplayName:       "Mira Frost",
		RoleLabel:         "Admin",
		CanChangePassword: true,
		IsAdmin:           true,
		CanFreeze:         true,
		CanThaw:           true,
	}
	if r.URL.Query().Get("role") == "viewer" {
		user = currentUserView{
			Email:             "sten.hale@example.test",
			DisplayName:       "Sten Hale",
			RoleLabel:         "Viewer",
			CanChangePassword: true,
		}
	}
	repositories := []domain.Repository{
		{ID: 46, Forge: "forgejo", BaseURL: "https://forge.example.test", Owner: "aurora", Name: "ice-station", DefaultBranch: "main", EnforcementState: domain.EnforcementActive},
		{ID: 47, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "borealis", Name: "frost-api", DefaultBranch: "main", EnforcementState: domain.EnforcementActive},
	}
	branchOptions := []managedBranchOption{
		{RepositoryID: 46, Name: "main"},
		{RepositoryID: 46, Name: "release/1.8"},
		{RepositoryID: 47, Name: "main"},
	}
	sharedHead := "f00dfeed00c0ffee1122334455667788990011aa"
	// One row per badge tone plus a deleted-repository fallback row.
	results := []statusresult.Result{
		{ID: 501, RepositoryID: 46, PullRequestIndex: 241, TargetBranch: "main", HeadSHA: sharedHead, Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "PR is explicitly thawed during an active freeze", CreatedAt: time.Date(2026, 7, 17, 9, 2, 0, 0, time.UTC)},
		{ID: 502, RepositoryID: 46, PullRequestIndex: 238, TargetBranch: "main", HeadSHA: "aa11bb22cc33dd44ee55ff667788990011223344", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", CreatedAt: time.Date(2026, 7, 16, 21, 40, 0, 0, time.UTC)},
		{ID: 503, RepositoryID: 47, PullRequestIndex: 229, TargetBranch: "main", HeadSHA: "bb22cc33dd44ee55ff6677889900112233445566", Context: domain.RequiredStatusContext, State: domain.CommitStatusPending, Description: "Thawguard is evaluating this pull request", CreatedAt: time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)},
		{ID: 504, RepositoryID: 47, PullRequestIndex: 214, TargetBranch: "main", HeadSHA: "cc33dd44ee55ff667788990011223344556677aa", Context: domain.RequiredStatusContext, State: domain.CommitStatusError, Error: "status publication failed: the forge rejected the status token", CreatedAt: time.Date(2026, 7, 16, 9, 12, 0, 0, time.UTC)},
		{ID: 505, RepositoryID: 17, PullRequestIndex: 77, TargetBranch: "release/0.9", HeadSHA: "dd44ee55ff667788990011223344556677aabb00", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard", CreatedAt: time.Date(2026, 7, 12, 11, 30, 0, 0, time.UTC)},
	}
	eligibilityFound := &thawEligibilityView{
		State:            "found",
		RepositoryLabel:  "aurora/ice-station",
		PullRequestIndex: 241,
		Title:            "Fix retry backoff for status publication",
		URL:              "https://forge.example.test/aurora/ice-station/pulls/241",
		TargetBranch:     "main",
		TargetFrozen:     true,
		ShortHeadSHA:     shortHeadSHA(sharedHead),
		Companions: []thawEligibilityCompanionView{
			{Index: 238, Title: "Backport retry backoff fix to release/1.8", URL: "https://forge.example.test/aurora/ice-station/pulls/238"},
		},
	}
	confirmation := &sharedHeadConfirmationView{
		RepositoryID:      46,
		PullRequestIndex:  241,
		TargetBranch:      "main",
		Reason:            "Production fix needed during release freeze",
		HeadSHA:           sharedHead,
		ShortHeadSHA:      shortHeadSHA(sharedHead),
		AffectedSignature: "9c1f2b7e4d8a5c3e6f0b1d2a4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70",
		AffectedCount:     3,
		AffectedPullRequests: []sharedHeadAffectedPullRequestView{
			{Index: 241, Title: "Fix retry backoff for status publication", TargetBranch: "main", ShortHeadSHA: shortHeadSHA(sharedHead), URL: "https://forge.example.test/aurora/ice-station/pulls/241"},
			{Index: 238, Title: "Backport retry backoff fix to release/1.8", TargetBranch: "release/1.8", ShortHeadSHA: shortHeadSHA(sharedHead), URL: "https://forge.example.test/aurora/ice-station/pulls/238"},
			{Index: 229, Title: "Docs: webhook rotation runbook", TargetBranch: "main", ShortHeadSHA: shortHeadSHA(sharedHead), URL: "https://forge.example.test/aurora/ice-station/pulls/229"},
		},
	}
	state := decisionsPageState{Query: decisionsQuery{State: "all", Page: 1}}
	var eligibility *thawEligibilityView
	switch r.URL.Query().Get("variant") {
	case "empty":
		results = nil
	case "no-repos":
		repositories = nil
		branchOptions = nil
		results = nil
	case "form-error":
		state.FormError = "target branch is invalid"
		state.DecisionForm = decisionFormState{
			Submitted:        true,
			RepositoryID:     46,
			TargetBranch:     "release/1.8",
			PullRequestIndex: "241",
			Reason:           "Production fix needed during release freeze",
		}
		eligibility = eligibilityFound
	case "eligibility-found":
		state.DecisionForm = decisionFormState{Submitted: true, RepositoryID: 46, TargetBranch: "main", PullRequestIndex: "241"}
		eligibility = eligibilityFound
	case "eligibility-unfrozen":
		state.DecisionForm = decisionFormState{Submitted: true, RepositoryID: 46, TargetBranch: "main", PullRequestIndex: "241"}
		unfrozen := *eligibilityFound
		unfrozen.TargetFrozen = false
		unfrozen.Companions = nil
		eligibility = &unfrozen
	case "eligibility-missing":
		state.DecisionForm = decisionFormState{Submitted: true, RepositoryID: 46, TargetBranch: "main", PullRequestIndex: "977"}
		eligibility = &thawEligibilityView{State: "missing", RepositoryLabel: "aurora/ice-station", PullRequestIndex: 977}
	case "shared-head":
		state.Confirmation = confirmation
	case "stale":
		stale := *confirmation
		stale.Stale = true
		state.Confirmation = &stale
	}
	data := s.decisionsPageData(repositories, results, branchOptions, len(results), state, eligibility, "dev-preview-fictional-token", user)
	data.Theme = devPreviewTheme(r)
	s.renderPage(w, "layouts/decisions", data)
}

// devPreviewActivityRow builds one fictional activity-table row, deriving the
// badge and machine-readable timestamp the same way the real page does. A zero
// createdAt exercises the "Time unavailable" path without a <time> element.
func devPreviewActivityRow(createdAt time.Time, actor, label, outcome, outcomeClass, target, detail string) activityRowView {
	row := activityRowView{activityEventView: activityEventView{
		CreatedAt:    activityCreatedAt(createdAt),
		Actor:        actor,
		ActionLabel:  label,
		Outcome:      outcome,
		OutcomeClass: outcomeClass,
		Target:       target,
		Detail:       detail,
	}}
	if !createdAt.IsZero() {
		row.CreatedAtUTC = createdAt.UTC().Format(time.RFC3339)
	}
	row.BadgeTone, row.BadgeIcon = activityOutcomeBadge(outcome, outcomeClass)
	return row
}

// handleDevPreviewActivity renders the activity page from fictional fixtures
// covering the table state matrix (GET /dev/preview/activity). Query knobs:
// ?role=viewer, ?variant=empty|filtered|filtered-empty, ?theme=dark|light.
// The default variant is the last page (2 of 28 events) with one row per
// badge tone plus the safe fallback row; label/outcome pairs mirror real
// entries in activityActionDefinitions.
func (s *Server) handleDevPreviewActivity(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	user := currentUserView{
		Email:             "mira.frost@example.test",
		DisplayName:       "Mira Frost",
		RoleLabel:         "Admin",
		CanChangePassword: true,
		IsAdmin:           true,
		CanFreeze:         true,
		CanThaw:           true,
	}
	if r.URL.Query().Get("role") == "viewer" {
		user = currentUserView{
			Email:             "sten.hale@example.test",
			DisplayName:       "Sten Hale",
			RoleLabel:         "Viewer",
			CanChangePassword: true,
		}
	}
	rows := []activityRowView{
		devPreviewActivityRow(time.Date(2026, 7, 17, 9, 2, 0, 0, time.UTC), "Mira Frost", "Single-PR thaw", "Approved", "ok", "aurora/ice-station → PR #241", "Production fix needed during release freeze."),
		devPreviewActivityRow(time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC), "Scheduler", "Scheduled freeze", "Started", "frozen", "aurora/ice-station main", "Release freeze window opened on schedule."),
		devPreviewActivityRow(time.Date(2026, 7, 16, 21, 40, 0, 0, time.UTC), "Mira Frost", "Freeze schedule", "Changed", "frozen", "aurora/ice-station main", "Freeze window now ends 2026-07-21 06:00 UTC."),
		devPreviewActivityRow(time.Date(2026, 7, 16, 18, 25, 0, 0, time.UTC), "Runtime process", "Status-post verification", "Failed", "failed", "borealis/frost-api → PR #214", "The forge rejected the posted commit status."),
		devPreviewActivityRow(time.Date(2026, 7, 16, 9, 12, 0, 0, time.UTC), "Reconciliation runner", "Setup drift", "Detected", "warning", "borealis/frost-api", "Branch protection no longer requires the Thawguard status context."),
		devPreviewActivityRow(time.Date(2026, 7, 15, 16, 44, 0, 0, time.UTC), "Mira Frost", "Freeze schedule", "Scheduled", "pending", "borealis/frost-api release/1.8", "Freeze window scheduled for 2026-07-19 06:00 to 2026-07-21 06:00 UTC."),
		devPreviewActivityRow(time.Date(2026, 7, 15, 11, 3, 0, 0, time.UTC), "Mira Frost", "User roles", "Changed", "frozen", "Sten Hale", "Roles set to viewer."),
		devPreviewActivityRow(time.Time{}, "Unknown system actor", "Unrecognized activity", "Unknown", "warning", "Repository #12", "Stored audit details could not be displayed safely."),
	}
	query := activityQuery{Filter: "all", Page: 2}
	total := 28
	switch r.URL.Query().Get("variant") {
	case "empty":
		rows = nil
		total = 0
		query.Page = 1
	case "filtered":
		query = activityQuery{Filter: "failures", Page: 1}
		rows = []activityRowView{
			devPreviewActivityRow(time.Date(2026, 7, 16, 18, 25, 0, 0, time.UTC), "Runtime process", "Status-post verification", "Failed", "failed", "borealis/frost-api → PR #214", "The forge rejected the posted commit status."),
			devPreviewActivityRow(time.Date(2026, 7, 14, 7, 50, 0, 0, time.UTC), "Runtime process", "Enforcement activation", "Failed", "failed", "borealis/frost-api", "Could not reach the forge API to require the status context."),
		}
		total = len(rows)
	case "filtered-empty":
		query = activityQuery{Filter: "users", Page: 1}
		rows = nil
		total = 0
	}
	data := activityPageData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Activity",
		Theme:       devPreviewTheme(r),
		ActivePage:  "activity",
		CurrentUser: user,
		Rows:        rows,
		Total:       total,
		Filter:      query.Filter,
		Query:       query,
		CSRFToken:   "dev-preview-fictional-token",
		CSRFField:   csrfFormField,
	}
	data.Chips = filterChips(query.Filter, activityFilterOptions, func(value string) string {
		return activityURL(activityQuery{Filter: value, Page: 1})
	})
	data.Pagination = paginateTable(total, query.Page, activityPageSize, func(page int) string {
		return activityURL(activityQuery{Filter: query.Filter, Page: page})
	})
	s.renderPage(w, "layouts/activity", data)
}
