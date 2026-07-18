package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestRepositoriesLayoutTemplateExecutesWithTypedData(t *testing.T) {
	view := repositoryView{
		Repository: domain.Repository{
			ID:               7,
			Owner:            "taua-almeida",
			Name:             "thawguard",
			Forge:            "forgejo",
			DefaultBranch:    "main",
			HasWebhookSecret: true,
			HasStatusToken:   true,
		},
		EnforcementLabel:    "setup incomplete",
		EnforcementTone:     "warning",
		IsSetupIncomplete:   true,
		VerifyBlockedReason: "Run readiness checks first.",
		Lifecycle:           []lifecycleNode{{Label: "Setup", State: "current"}},
	}
	data := repositoriesPageData{
		AppName:    "Thawguard",
		PageTitle:  "Repositories",
		ActivePage: "repositories",
		Toasts:     []toastView{{Message: "Repository enforcement is inactive.", Tone: "success", DismissHref: "/repositories"}},
		RepositoryViews: []repositoryCard{{
			repositoryView:                    view,
			CSRFToken:                         "test-token",
			CSRFField:                         csrfFormField,
			CurrentUser:                       currentUserView{Email: "taua@example.com", DisplayName: "Taua", RoleLabel: "Admin", IsAdmin: true, CanManageRepositories: true},
			RequiredContext:                   domain.RequiredStatusContext,
			SetupStatusContext:                domain.SetupStatusContext,
			WebhookSecretEncryptionConfigured: true,
		}},
		TotalCount:                        1,
		VisibleCount:                      1,
		CSRFToken:                         "test-token",
		CSRFField:                         csrfFormField,
		CurrentUser:                       currentUserView{Email: "taua@example.com", DisplayName: "Taua", RoleLabel: "Admin", IsAdmin: true, CanManageRepositories: true},
		RequiredContext:                   domain.RequiredStatusContext,
		SetupStatusContext:                domain.SetupStatusContext,
		WebhookSecretEncryptionConfigured: true,
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/repositories", data); err != nil {
		t.Fatalf("expected layout to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"/static/app.css",
		`id="repo-7"`,
		"taua-almeida/thawguard",
		`name="` + csrfFormField + `" value="test-token"`,
		domain.RequiredStatusContext,
		`<dialog id="connect-repository"`,
		"Run readiness checks first.",
		`id="toasts"`,
		"Repository enforcement is inactive.",
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered layout to contain %q", want)
		}
	}
	if strings.Contains(body, "/static/thawguard.css") {
		t.Fatalf("expected repositories layout to use app.css, not the legacy stylesheet")
	}
}

func TestRepositoryCardFragmentRendersCardAndOOBToast(t *testing.T) {
	card := repositoryCard{
		repositoryView: repositoryView{
			Repository:       domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"},
			EnforcementLabel: "setup incomplete",
			EnforcementTone:  "warning",
			Lifecycle:        []lifecycleNode{{Label: "Setup", State: "current"}},
		},
		CSRFToken:       "test-token",
		CSRFField:       csrfFormField,
		CurrentUser:     currentUserView{Email: "taua@example.com", DisplayName: "Taua", RoleLabel: "Admin", IsAdmin: true, CanManageRepositories: true},
		RequiredContext: domain.RequiredStatusContext,
		ActionError:     "branch name is invalid",
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "components/repository-card-fragment", repositoryCardFragment{
		Card:  card,
		Toast: &toastView{Message: "Managed branch added.", Tone: "success"},
	}); err != nil {
		t.Fatalf("expected card fragment to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		`id="repo-7"`,
		"branch name is invalid",
		`id="toasts" hx-swap-oob="true"`,
		"Managed branch added.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered fragment to contain %q", want)
		}
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected fragment to render without the page shell")
	}
}

func TestFreezesLayoutTemplateExecutesWithTypedData(t *testing.T) {
	repo := domain.Repository{
		ID:               7,
		Owner:            "taua-almeida",
		Name:             "thawguard",
		DefaultBranch:    "main",
		EnforcementState: domain.EnforcementActive,
	}
	view := freezeView{
		Freeze: domain.BranchFreeze{
			ID:           11,
			RepositoryID: repo.ID,
			Branch:       "main",
			Status:       domain.BranchFreezeStatusActive,
			Reason:       "release <cut>",
		},
		Repository: repo,
	}
	data := freezesPageData{
		AppName:                 "Thawguard",
		ActivePage:              "freezes",
		CurrentUser:             currentUserView{Email: "taua@example.com", DisplayName: "Taua", RoleLabel: "Freezer", CanFreeze: true},
		EnforceableRepositories: []domain.Repository{repo},
		BranchOptions:           []managedBranchOption{{RepositoryID: repo.ID, Name: "main"}},
		ActiveFreezes: []activeFreezeCard{{
			freezeView: view,
			CSRFToken:  "test-token",
			CSRFField:  csrfFormField,
			CanFreeze:  true,
		}},
		CSRFToken:       "test-token",
		CSRFField:       csrfFormField,
		RequiredContext: domain.RequiredStatusContext,
		Impact: &impactView{
			Repository:      "taua-almeida/thawguard",
			Branch:          "main",
			RequiredContext: domain.RequiredStatusContext,
		},
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/freezes", data); err != nil {
		t.Fatalf("expected freezes layout to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"Start a freeze",
		"Freeze impact",
		`id="freeze-impact"`,
		"How freezes work",
		"No known open pull requests target this branch right now.",
		"From webhook sync, not a live forge lookup.",
		`hx-get="/freezes/impact"`,
		"data-local-datetime disabled",
		"Planned unfreeze is unavailable without JavaScript",
		`name="` + csrfFormField + `" value="test-token"`,
		`action="/freezes/end"`,
		`action="/freezes/cancel"`,
		domain.RequiredStatusContext,
		"release &lt;cut&gt;",
		`<dialog id="lift-freeze-11"`,
		`<dialog id="cancel-freeze-11"`,
		`data-timezone-offset-minutes`,
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered freezes layout to contain %q", want)
		}
	}
	for _, unwanted := range []string{"3 open PRs", "#248", "Live preview of PRs"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected rendered freezes layout not to contain fictional data %q", unwanted)
		}
	}
}

func TestFreezesLayoutKeepsReadOnlyStateMutationFree(t *testing.T) {
	repo := domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard", EnforcementState: domain.EnforcementActive}
	data := freezesPageData{
		AppName:                 "Thawguard",
		ActivePage:              "freezes",
		CurrentUser:             currentUserView{Email: "viewer@example.com", DisplayName: "Viewer", RoleLabel: "Viewer"},
		EnforceableRepositories: []domain.Repository{repo},
		ActiveFreezes: []activeFreezeCard{{
			freezeView: freezeView{
				Freeze:     domain.BranchFreeze{ID: 11, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusActive},
				Repository: repo,
			},
			CSRFToken: "test-token",
			CSRFField: csrfFormField,
		}},
		CSRFToken:       "test-token",
		CSRFField:       csrfFormField,
		RequiredContext: domain.RequiredStatusContext,
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/freezes", data); err != nil {
		t.Fatalf("expected read-only freezes layout to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"Read-only freeze access", "How freezes work", "Read only"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected read-only freezes layout to contain %q", want)
		}
	}
	for _, mutation := range []string{`action="/freezes"`, `action="/freezes/end"`, `action="/freezes/cancel"`, "Evaluated on submit", "Freeze impact", `id="freeze-impact"`} {
		if strings.Contains(body, mutation) {
			t.Fatalf("expected read-only freezes layout not to contain mutation marker %q", mutation)
		}
	}
}

func TestDashboardLayoutTemplateExecutesWithTypedData(t *testing.T) {
	repo := domain.Repository{
		ID:               7,
		Owner:            "taua-almeida",
		Name:             "thawguard",
		DefaultBranch:    "main",
		EnforcementState: domain.EnforcementActive,
	}
	data := dashboardPageData{
		AppName:              "Thawguard",
		PageTitle:            "Dashboard",
		ActivePage:           "dashboard",
		CurrentUser:          currentUserView{Email: "taua@example.com", DisplayName: "Taua", RoleLabel: "Admin", IsAdmin: true, CanFreeze: true, CanThaw: true},
		CSRFToken:            "test-token",
		CSRFField:            csrfFormField,
		RepositoryCount:      4,
		EnforcingCount:       3,
		SetupIncompleteCount: 1,
		ActiveFreezeCount:    6,
		ScheduledFreezeCount: 1,
		ActiveThawCount:      2,
		ActiveFreezes: []freezeView{
			{
				Freeze:         domain.BranchFreeze{ID: 11, RepositoryID: repo.ID, Branch: "main", Status: domain.BranchFreezeStatusActive, Reason: "release <cut>"},
				Repository:     repo,
				StartedLabel:   "2026-07-17",
				StartedTitle:   "2026-07-17T09:00:00Z",
				CreatedByLabel: "Taua",
			},
			{
				Freeze: domain.BranchFreeze{ID: 12, RepositoryID: 9, Branch: "main", Status: domain.BranchFreezeStatusActive, Reason: "incident hold"},
			},
		},
		ScheduledFreezes: []scheduledFreezeView{{
			Freeze:      domain.BranchFreeze{ID: 21, RepositoryID: repo.ID, Branch: "main"},
			Repository:  repo,
			StartsAt:    "2026-07-20 08:00",
			StartsAtUTC: "2026-07-20T08:00:00Z",
			StatusLabel: "upcoming",
			StateClass:  "pending",
		}},
		RecentActivity: []activityEventView{{
			CreatedAt:    "2026-07-18 10:00 UTC",
			Actor:        "Taua",
			ActionLabel:  "Freeze started",
			Target:       "taua-almeida/thawguard → main",
			Outcome:      "Frozen",
			OutcomeClass: "frozen",
		}},
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/dashboard", data); err != nil {
		t.Fatalf("expected dashboard layout to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"Dashboard",
		"What is frozen, what is scheduled, and what changed — at a glance.",
		"Start freeze",
		"Review thaws",
		"3 of 4",
		`href="/scheduled-freezes"`,
		`href="/decisions"`,
		"Approved exceptions in effect",
		"1 of 4 repositories can't enforce freezes yet.",
		"Freezes on those repositories are recorded but not enforced until setup completes.",
		"View setup",
		"View all 6 →",
		"taua-almeida/thawguard",
		"release &lt;cut&gt;",
		"Started",
		"by Taua",
		"Repository #9",
		"Scheduled next",
		"upcoming",
		"2026-07-20 08:00",
		"Recent activity",
		"Freeze started",
		"Frozen",
		"bg-frozen",
		"2026-07-18 10:00 UTC",
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered dashboard layout to contain %q", want)
		}
	}
	for _, unwanted := range []string{"aurora/ice-station", "borealis/frost-api", "rana.kall"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected rendered dashboard layout not to contain fictional data %q", unwanted)
		}
	}
}

func TestDashboardLayoutKeepsViewerReadOnlyAndEmptyStates(t *testing.T) {
	data := dashboardPageData{
		AppName:         "Thawguard",
		PageTitle:       "Dashboard",
		ActivePage:      "dashboard",
		CurrentUser:     currentUserView{Email: "viewer@example.com", DisplayName: "Viewer", RoleLabel: "Viewer"},
		CSRFToken:       "test-token",
		CSRFField:       csrfFormField,
		RepositoryCount: 2,
		EnforcingCount:  2,
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/dashboard", data); err != nil {
		t.Fatalf("expected viewer dashboard layout to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		`text-success">2 of 2`,
		"0 active",
		"No active freezes",
		"Start one from the Freezes page.",
		"No scheduled windows yet.",
		"No recorded activity yet.",
		"Recent activity",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected viewer dashboard layout to contain %q", want)
		}
	}
	for _, unwanted := range []string{"Start freeze", "Review thaws", "can't enforce freezes yet", "View setup"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("expected viewer dashboard layout not to contain %q", unwanted)
		}
	}
}

// A fresh install has zero repositories; "0 of 0" enforcing must render in
// the neutral tone — success green would misread as "everything is healthy".
func TestDashboardEnforcingStatIsNeutralWithZeroRepositories(t *testing.T) {
	data := dashboardPageData{
		AppName:     "Thawguard",
		PageTitle:   "Dashboard",
		ActivePage:  "dashboard",
		CurrentUser: currentUserView{Email: "admin@example.com", DisplayName: "Admin", RoleLabel: "Admin", IsAdmin: true},
		CSRFToken:   "test-token",
		CSRFField:   csrfFormField,
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/dashboard", data); err != nil {
		t.Fatalf("expected empty dashboard layout to execute, got error: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, `text-text">0 of 0`) {
		t.Fatalf("expected 0-of-0 enforcing stat to render in the neutral tone")
	}
	if strings.Contains(body, `text-success">0 of 0`) || strings.Contains(body, `text-warning">0 of 0`) {
		t.Fatalf("expected 0-of-0 enforcing stat not to render in success or warning tone")
	}
}

func TestStaticAssetsServedFromEmbeddedFS(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	cases := []struct {
		path string
		want string
	}{
		{"/static/thawguard.css", "@import"},
		{"/static/css/tokens.css", ":root"},
		{"/static/css/legacy.css", ".tg-sidebar"},
		{"/static/css/pages/freezes.css", ".tg-freezes-page"},
	}
	for _, tc := range cases {
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status 200 for %s, got %d", tc.path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), tc.want) {
			t.Fatalf("expected %s to contain %q", tc.path, tc.want)
		}
	}
}
