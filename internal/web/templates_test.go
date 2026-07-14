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
		EnforcementClass:    "status-warning",
		IsSetupIncomplete:   true,
		VerifyBlockedReason: "Run readiness checks first.",
		Lifecycle:           []lifecycleNode{{Label: "Setup", Class: "is-current"}},
	}
	data := repositoriesPageData{
		AppName:    "Thawguard",
		ActivePage: "repositories",
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
		"/static/thawguard.css",
		"tg-repo-card",
		"taua-almeida/thawguard",
		`name="` + csrfFormField + `" value="test-token"`,
		domain.RequiredStatusContext,
		"data-alert-dialog",
		"data-confirm-submit",
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered layout to contain %q", want)
		}
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
	}

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "layouts/freezes", data); err != nil {
		t.Fatalf("expected freezes layout to execute, got error: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"Branch Freezes",
		"Freeze effect",
		"Active freeze mobile cards",
		"data-local-datetime disabled",
		"Planned unfreeze is unavailable without JavaScript",
		`name="` + csrfFormField + `" value="test-token"`,
		`action="/freezes/end"`,
		`action="/freezes/cancel"`,
		domain.RequiredStatusContext,
		"release &lt;cut&gt;",
		"data-alert-dialog",
		`tabindex="-1"`,
		"previouslyFocused",
		"plannedEndsAt.addEventListener('change', updateTimezoneOffset)",
		"form.addEventListener('submit', updateTimezoneOffset)",
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
	for _, want := range []string{"Read-only freeze access", "Policy summary", "Read only"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected read-only freezes layout to contain %q", want)
		}
	}
	for _, mutation := range []string{`action="/freezes"`, `action="/freezes/end"`, `action="/freezes/cancel"`, "Evaluated on submit"} {
		if strings.Contains(body, mutation) {
			t.Fatalf("expected read-only freezes layout not to contain mutation marker %q", mutation)
		}
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
		{"/static/css/pages/repositories.css", ".tg-repo-grid"},
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
