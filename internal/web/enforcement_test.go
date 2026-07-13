package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type fakeEnforcementService struct {
	verified    []int64
	activated   []int64
	actors      []domain.Actor
	verifyErr   error
	activateErr error
}

func (s *fakeEnforcementService) VerifyStatusPosting(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if s.verifyErr != nil {
		return domain.Repository{}, s.verifyErr
	}
	s.verified = append(s.verified, repositoryID)
	s.actors = append(s.actors, actor)
	return domain.Repository{ID: repositoryID, EnforcementState: domain.EnforcementReady}, nil
}

func (s *fakeEnforcementService) ActivateEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if s.activateErr != nil {
		return domain.Repository{}, s.activateErr
	}
	s.activated = append(s.activated, repositoryID)
	s.actors = append(s.actors, actor)
	return domain.Repository{ID: repositoryID, EnforcementState: domain.EnforcementActive}, nil
}

func enforcementTestRepository(state domain.EnforcementState) domain.Repository {
	repo := domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", HasWebhookSecret: true, HasStatusToken: true, EnforcementState: state}
	if state == domain.EnforcementReady || state == domain.EnforcementActive {
		verifiedAt := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
		repo.StatusPostVerifiedAt = &verifiedAt
	}
	return repo
}

func passingReadinessChecks(checkedAt time.Time) []setupcheck.Check {
	return []setupcheck.Check{
		{RepositoryID: 7, Result: setupcheck.Result{Name: setupcheck.CheckStatusTokenConfigured, Status: setupcheck.StatusOK, Description: "ok"}, CheckedAt: checkedAt},
		{RepositoryID: 7, Result: setupcheck.Result{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "untested"}, CheckedAt: checkedAt},
		{RepositoryID: 7, Branch: "main", Result: setupcheck.Result{Name: setupcheck.CheckBranchProtectionEnabled, Status: setupcheck.StatusOK, Description: "ok"}, CheckedAt: checkedAt},
	}
}

func newEnforcementTestServer(repo domain.Repository, checks []setupcheck.Check, service EnforcementService) *Server {
	return NewServer(Config{
		AppName:                              "Thawguard",
		RepositoryStore:                      &fakeRepositoryStore{repositories: []domain.Repository{repo}},
		RepositorySecretEncryptionConfigured: true,
		SetupCheckStore:                      &fakeSetupCheckStore{checks: map[int64][]setupcheck.Check{7: checks}},
		EnforcementService:                   service,
	})
}

func TestRepositoriesPageOffersVerifyActionWhenReadinessPasses(t *testing.T) {
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementSetupIncomplete), passingReadinessChecks(time.Now().UTC()), &fakeEnforcementService{})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	body := recorder.Body.String()
	if !strings.Contains(body, `action="/repositories/status-verification"`) || !strings.Contains(body, "Verify status posting") {
		t.Fatalf("expected verify action to be offered, got %q", body)
	}
	if !strings.Contains(body, domain.SetupStatusContext) {
		t.Fatalf("expected setup context explanation, got %q", body)
	}
	if strings.Contains(body, `action="/repositories/activate"`) {
		t.Fatalf("expected no activate action for setup-incomplete repository, got %q", body)
	}
}

func TestRepositoriesPageDisablesVerifyActionWhenReadinessIncomplete(t *testing.T) {
	checkedAt := time.Now().UTC()
	failing := append(passingReadinessChecks(checkedAt), setupcheck.Check{RepositoryID: 7, Branch: "main", Result: setupcheck.Result{Name: setupcheck.CheckRequiredStatusChecksEnabled, Status: setupcheck.StatusFailed, Description: "missing"}, CheckedAt: checkedAt})
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementSetupIncomplete), failing, &fakeEnforcementService{})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	body := recorder.Body.String()
	if strings.Contains(body, `action="/repositories/status-verification"`) {
		t.Fatalf("expected no verify form when readiness fails, got %q", body)
	}
	if !strings.Contains(body, "Fix the failing readiness checks") {
		t.Fatalf("expected verify remediation copy, got %q", body)
	}

	server = newEnforcementTestServer(enforcementTestRepository(domain.EnforcementSetupIncomplete), nil, &fakeEnforcementService{})
	recorder = httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	if !strings.Contains(recorder.Body.String(), "Run the read-only readiness checks first") {
		t.Fatalf("expected no-evidence remediation copy, got %q", recorder.Body.String())
	}
}

func TestRepositoriesPageShowsActivateActionOnlyWhenReady(t *testing.T) {
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementReady), passingReadinessChecks(time.Now().UTC()), &fakeEnforcementService{})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	body := recorder.Body.String()
	if !strings.Contains(body, `action="/repositories/activate"`) || !strings.Contains(body, "Activate enforcement") {
		t.Fatalf("expected activate action for ready repository, got %q", body)
	}
	if !strings.Contains(body, `data-confirm-title="Activate enforcement?"`) || !strings.Contains(body, "synchronizes current open pull requests") {
		t.Fatalf("expected custom confirmation metadata explaining activation, got %q", body)
	}
	if !strings.Contains(body, "Status posting verified") || !strings.Contains(body, "2026-07-12 09:00 UTC") {
		t.Fatalf("expected verification evidence with time, got %q", body)
	}
	if strings.Contains(body, `action="/repositories/status-verification"`) {
		t.Fatalf("expected no verify form for ready repository, got %q", body)
	}
}

func TestRepositoriesPageHidesEnforcementActionsForActiveAndUnhealthy(t *testing.T) {
	for _, state := range []domain.EnforcementState{domain.EnforcementActive, domain.EnforcementUnhealthy} {
		server := newEnforcementTestServer(enforcementTestRepository(state), passingReadinessChecks(time.Now().UTC()), &fakeEnforcementService{})
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

		body := recorder.Body.String()
		if strings.Contains(body, `action="/repositories/status-verification"`) || strings.Contains(body, `action="/repositories/activate"`) {
			t.Fatalf("expected no enforcement actions for %s repository, got %q", state, body)
		}
		if state == domain.EnforcementUnhealthy && !strings.Contains(body, "Enforcement is unhealthy") {
			t.Fatalf("expected unhealthy remediation copy, got %q", body)
		}
	}
}

func TestVerifyStatusPostingHandlerRedirectsAfterSuccess(t *testing.T) {
	service := &fakeEnforcementService{}
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementSetupIncomplete), passingReadinessChecks(time.Now().UTC()), service)
	cookie, csrfToken := getRepositoryForm(t, server)

	form := url.Values{"repository_id": {"7"}, csrfFormField: {csrfToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/status-verification", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/repositories" {
		t.Fatalf("expected PRG redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(service.verified) != 1 || service.verified[0] != 7 {
		t.Fatalf("expected verification call for repository 7, got %+v", service.verified)
	}
}

func TestActivateEnforcementHandlerRedirectsAfterSuccess(t *testing.T) {
	service := &fakeEnforcementService{}
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementReady), passingReadinessChecks(time.Now().UTC()), service)
	cookie, csrfToken := getRepositoryForm(t, server)

	form := url.Values{"repository_id": {"7"}, csrfFormField: {csrfToken}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/activate", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/repositories" {
		t.Fatalf("expected PRG redirect, status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if len(service.activated) != 1 || service.activated[0] != 7 {
		t.Fatalf("expected activation call for repository 7, got %+v", service.activated)
	}
}

func TestEnforcementHandlersRenderTypedValidationErrorsSafely(t *testing.T) {
	service := &fakeEnforcementService{
		verifyErr:   repository.ValidationError{Message: "Status-post verification failed: the controlled thawguard/setup status could not be posted with the stored token. <script>"},
		activateErr: repository.ValidationError{Message: "Repository enforcement can only be activated from the ready state."},
	}
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementSetupIncomplete), passingReadinessChecks(time.Now().UTC()), service)
	cookie, csrfToken := getRepositoryForm(t, server)

	for _, path := range []string{"/repositories/status-verification", "/repositories/activate"} {
		form := url.Values{"repository_id": {"7"}, csrfFormField: {csrfToken}}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		server.Routes().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected validation re-render for %s, got %d", path, recorder.Code)
		}
	}
	body := httptest.NewRecorder()
	form := url.Values{"repository_id": {"7"}, csrfFormField: {csrfToken}}
	request := httptest.NewRequest(http.MethodPost, "/repositories/status-verification", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(body, request)
	if !strings.Contains(body.Body.String(), "Status-post verification failed") {
		t.Fatalf("expected operator-facing failure message, got %q", body.Body.String())
	}
	if !strings.Contains(body.Body.String(), "&lt;script&gt;") {
		t.Fatalf("expected error message to be HTML-escaped, got %q", body.Body.String())
	}
}

func TestEnforcementHandlersRejectInvalidCSRF(t *testing.T) {
	service := &fakeEnforcementService{}
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementReady), nil, service)
	cookie, _ := getRepositoryForm(t, server)

	for _, path := range []string{"/repositories/status-verification", "/repositories/activate"} {
		form := url.Values{"repository_id": {"7"}, csrfFormField: {"not-the-session-token"}}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		server.Routes().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected CSRF rejection for %s, got %d", path, recorder.Code)
		}
	}
	if len(service.verified) != 0 || len(service.activated) != 0 {
		t.Fatalf("expected no service calls after CSRF rejection, got %+v %+v", service.verified, service.activated)
	}
}

func TestEnforcementActionsForbiddenForNonAdmin(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	if _, err := authService.CreateFirstAdmin(ctx, auth.CreateFirstAdminParams{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authService.CreateUser(ctx, auth.CreateUserParams{Email: "viewer@example.test", DisplayName: "Viewer", Password: "correct horse battery staple", Roles: []auth.Role{auth.RoleViewer}}); err != nil {
		t.Fatal(err)
	}
	viewerSession, err := authService.Login(ctx, auth.LoginParams{Email: "viewer@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	service := &fakeEnforcementService{}
	server := NewServer(Config{
		AppName:            "Thawguard",
		AuthService:        authService,
		RepositoryStore:    &fakeRepositoryStore{repositories: []domain.Repository{enforcementTestRepository(domain.EnforcementReady)}},
		SetupCheckStore:    &fakeSetupCheckStore{checks: map[int64][]setupcheck.Check{7: passingReadinessChecks(time.Now().UTC())}},
		EnforcementService: service,
	})
	viewerCookie := &http.Cookie{Name: sessionCookieName, Value: viewerSession.ID}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	request.AddCookie(viewerCookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected viewer to read repository state, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Status posting verified") {
		t.Fatalf("expected viewer to see enforcement state evidence, got %q", body)
	}
	if strings.Contains(body, `action="/repositories/status-verification"`) || strings.Contains(body, `action="/repositories/activate"`) {
		t.Fatalf("expected no actionable enforcement forms for viewer, got %q", body)
	}

	for _, path := range []string{"/repositories/status-verification", "/repositories/activate"} {
		form := url.Values{"repository_id": {"7"}, csrfFormField: {viewerSession.CSRFToken}}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(viewerCookie)
		server.Routes().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected viewer %s to be forbidden, got %d", path, recorder.Code)
		}
	}
	if len(service.verified) != 0 || len(service.activated) != 0 {
		t.Fatalf("expected no service calls for viewer, got %+v %+v", service.verified, service.activated)
	}
}
