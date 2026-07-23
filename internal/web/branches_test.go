package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
)

func newBranchTestRepositoryStore(state domain.EnforcementState) *fakeRepositoryStore {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: state}
	return &fakeRepositoryStore{
		repositories: []domain.Repository{repo},
		branches: map[int64][]domain.RepositoryBranch{
			1: {
				{ID: 1, RepositoryID: 1, Name: "main", SetupStatus: "unknown"},
				{ID: 2, RepositoryID: 1, Name: "release/1.4", SetupStatus: "unknown"},
			},
		},
	}
}

func branchForm(branch string) url.Values {
	return url.Values{"repository_id": {"1"}, "branch": {branch}}
}

func TestRepositoriesPageShowsManagedBranches(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})

	recorder := getPageWithRoles(t, server, "/repositories", auth.RoleSet{auth.RoleAdmin})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Managed branches", "exact names only", "release/1.4", ">default<", "not checked", `action="/repositories/branches"`, `action="/repositories/branches/remove"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected repositories page to contain %q, got %q", want, body)
		}
	}
	// The default branch has no remove form: exactly one removal input (release/1.4).
	if got := strings.Count(body, `name="branch" value=`); got != 1 {
		t.Fatalf("expected one branch removal input, got %d", got)
	}
	if !strings.Contains(body, `name="branch" value="release/1.4"`) {
		t.Fatalf("expected removal form for the non-default branch, got %q", body)
	}
}

func TestRepositoriesPageLocksBranchEditingWhileEnforcementActive(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementActive)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})

	recorder := getPageWithRoles(t, server, "/repositories", auth.RoleSet{auth.RoleAdmin})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Branch editing is disabled while enforcement is active") {
		t.Fatalf("expected disabled branch editing explanation, got %q", body)
	}
	if strings.Contains(body, `action="/repositories/branches"`) || strings.Contains(body, `action="/repositories/branches/remove"`) {
		t.Fatalf("expected no branch mutation forms for enforcement-active repository, got %q", body)
	}
}

func TestAddRepositoryBranchPostsToStore(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := branchForm("release/2.0")
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/branches", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(store.branchAdds) != 1 || store.branchAdds[0].repositoryID != 1 || store.branchAdds[0].branch != "release/2.0" {
		t.Fatalf("unexpected branch adds: %+v", store.branchAdds)
	}
	if len(store.branchActors) != 1 || store.branchActors[0].Kind != domain.ActorKindBootstrapAdmin {
		t.Fatalf("unexpected branch actors: %+v", store.branchActors)
	}
}

func TestRemoveRepositoryBranchPostsToStore(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := branchForm("release/1.4")
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/branches/remove", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(store.branchRemovals) != 1 || store.branchRemovals[0].repositoryID != 1 || store.branchRemovals[0].branch != "release/1.4" {
		t.Fatalf("unexpected branch removals: %+v", store.branchRemovals)
	}
}

func TestBranchMutationsRejectMissingCSRFSession(t *testing.T) {
	for _, path := range []string{"/repositories/branches", "/repositories/branches/remove"} {
		store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
		server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(branchForm("release/2.0").Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.Routes().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden status for %s, got %d", path, recorder.Code)
		}
		if len(store.branchAdds) != 0 || len(store.branchRemovals) != 0 {
			t.Fatalf("expected no branch mutation for %s, got adds=%+v removals=%+v", path, store.branchAdds, store.branchRemovals)
		}
	}
}

func TestBranchMutationsRejectInvalidCSRFToken(t *testing.T) {
	for _, path := range []string{"/repositories/branches", "/repositories/branches/remove"} {
		store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
		server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
		form := branchForm("release/2.0")
		cookie, _ := getRepositoryForm(t, server)
		form.Set(csrfFormField, "not-the-session-token")

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		server.Routes().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden status for %s, got %d", path, recorder.Code)
		}
		if len(store.branchAdds) != 0 || len(store.branchRemovals) != 0 {
			t.Fatalf("expected no branch mutation for %s, got adds=%+v removals=%+v", path, store.branchAdds, store.branchRemovals)
		}
	}
}

func TestBranchMutationsForbiddenForNonAdminRoles(t *testing.T) {
	ctx := context.Background()
	database := newWebTestDB(t, ctx)
	authService := auth.NewService(database)
	mustSetupWebAdmin(t, ctx, authService)
	mustCreateWebUser(t, ctx, authService, "freezer@example.test", false)
	freezerSession, err := authService.Login(ctx, auth.LoginParams{Email: "freezer@example.test", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	server := NewServer(Config{AppName: "Thawguard", AuthService: authService, RepositoryStore: store})
	cookie := &http.Cookie{Name: sessionCookieName, Value: freezerSession.ID}

	for _, path := range []string{"/repositories/branches", "/repositories/branches/remove"} {
		form := branchForm("release/2.0")
		form.Set(csrfFormField, freezerSession.CSRFToken)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		server.Routes().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden status for %s, got %d", path, recorder.Code)
		}
	}
	if len(store.branchAdds) != 0 || len(store.branchRemovals) != 0 {
		t.Fatalf("expected no branch mutation, got adds=%+v removals=%+v", store.branchAdds, store.branchRemovals)
	}
}

func TestAddRepositoryBranchEscapesValidationError(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	store.branchErr = repositorysetup.ValidationError{Message: `branch <script>alert("x")</script> is invalid`}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := branchForm(`<script>alert("x")</script>`)
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/branches", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request status, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, `<script>alert("x")</script>`) {
		t.Fatalf("expected validation error to be escaped, got %q", body)
	}
	if !strings.Contains(body, "is invalid") {
		t.Fatalf("expected validation message in body, got %q", body)
	}
}

func TestAddRepositoryBranchHidesInternalErrorDetails(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	store.branchErr = errors.New("database failed with secret-database-detail")
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := branchForm("release/2.0")
	cookie, csrfToken := getRepositoryForm(t, server)
	form.Set(csrfFormField, csrfToken)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/branches", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected internal server error status, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret-database-detail") {
		t.Fatalf("expected generic internal error body, got %q", recorder.Body.String())
	}
}

func TestFreezeFormsUseManagedBranchOptions(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementActive)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store, FreezeStore: &fakeFreezeStore{}, ScheduledFreezeStore: &fakeFreezeStore{}})

	for _, path := range []string{"/freezes", "/scheduled-freezes"} {
		recorder := getPageWithRoles(t, server, path, auth.RoleSet{auth.RoleFreezer})
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status 200 for %s, got %d", path, recorder.Code)
		}
		body := recorder.Body.String()
		for _, want := range []string{`<option value="main" data-repository="1">main</option>`, `<option value="release/1.4" data-repository="1">release/1.4</option>`} {
			if !strings.Contains(body, want) {
				t.Fatalf("expected %s to offer managed branch option %q, got %q", path, want, body)
			}
		}
		if strings.Contains(body, `<input name="branch"`) {
			t.Fatalf("expected %s to use a managed branch select instead of free text, got %q", path, body)
		}
	}
}
