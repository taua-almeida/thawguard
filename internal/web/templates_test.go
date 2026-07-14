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

func TestStaticAssetsServedFromEmbeddedFS(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	cases := []struct {
		path string
		want string
	}{
		{"/static/thawguard.css", "@import"},
		{"/static/css/tokens.css", ":root"},
		{"/static/css/legacy.css", ".tg-sidebar"},
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
