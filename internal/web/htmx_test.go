package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
)

func postHXForm(t *testing.T, server *Server, path string, form map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	cookie, csrfToken := getRepositoryForm(t, server)
	values := make([]string, 0, len(form)+1)
	values = append(values, csrfFormField+"="+csrfToken)
	for name, value := range form {
		values = append(values, name+"="+value)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.Join(values, "&")))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func TestAddRepositoryBranchHXRequestReturnsCardFragmentWithToast(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})

	recorder := postHXForm(t, server, "/repositories/branches", map[string]string{"repository_id": "1", "branch": "release/2.0"})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 fragment for HX branch add, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if vary := recorder.Header().Values("Vary"); !containsString(vary, "HX-Request") {
		t.Fatalf("expected Vary: HX-Request on HX response, got %v", vary)
	}
	if len(store.branchAdds) != 1 || store.branchAdds[0].branch != "release/2.0" {
		t.Fatalf("unexpected branch adds: %+v", store.branchAdds)
	}
	body := recorder.Body.String()
	for _, want := range []string{`id="repo-1"`, `id="toasts" hx-swap-oob="true"`, "Managed branch added."} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected HX fragment to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected HX response to be a fragment without the page shell, got %q", body)
	}
}

func TestAddRepositoryBranchHXValidationErrorReturns200Fragment(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	store.branchErr = repositorysetup.ValidationError{Message: "branch name is invalid"}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})

	recorder := postHXForm(t, server, "/repositories/branches", map[string]string{"repository_id": "1", "branch": "bad"})

	// main.js only swaps 2xx and 5xx responses, so HX validation errors must
	// come back as 200 fragments to re-render the card with the error.
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 fragment for HX validation error, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{`id="repo-1"`, "branch name is invalid", `role="alert"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected HX validation fragment to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected HX validation response to be a fragment, got %q", body)
	}
	if strings.Contains(body, `id="toasts"`) {
		t.Fatalf("expected no success toast on validation error, got %q", body)
	}
}

func TestAddRepositoryBranchWithoutHXKeepsRedirectAndFullPageError(t *testing.T) {
	store := newBranchTestRepositoryStore(domain.EnforcementSetupIncomplete)
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	cookie, csrfToken := getRepositoryForm(t, server)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories/branches", strings.NewReader(csrfFormField+"="+csrfToken+"&repository_id=1&branch=release/2.0"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected non-HX branch add to keep the PRG redirect, got %d", recorder.Code)
	}

	store.branchErr = repositorysetup.ValidationError{Message: "branch name is invalid"}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/repositories/branches", strings.NewReader(csrfFormField+"="+csrfToken+"&repository_id=1&branch=bad"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected non-HX validation error to stay a 400 full page, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "branch name is invalid") {
		t.Fatalf("expected full-page validation error, got %q", body)
	}
}

func TestEnforcementTransitionHXRequestReturnsCardFragment(t *testing.T) {
	service := &fakeEnforcementService{}
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementActive), passingReadinessChecks(time.Now().UTC()), service)

	recorder := postHXForm(t, server, "/repositories/reconcile", map[string]string{"repository_id": "7"})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 fragment for HX reconcile, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(service.reconciled) != 1 || service.reconciled[0] != 7 {
		t.Fatalf("unexpected reconcile calls: %+v", service.reconciled)
	}
	body := recorder.Body.String()
	for _, want := range []string{`id="repo-7"`, `id="toasts" hx-swap-oob="true"`, "Reconciliation completed."} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected HX reconcile fragment to contain %q, got %q", want, body)
		}
	}
	// Active repositories render as compact disclosure rows; the fragment
	// swap must come back expanded so acting inside the card never
	// collapses it.
	if !strings.Contains(body, `class="group" open`) {
		t.Fatalf("expected HX fragment for a compact-tier card to render its disclosure open, got %q", body)
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected HX reconcile response to be a fragment, got %q", body)
	}
}

func TestRepositoryMutationHXRedirectsWhenRepositoryDisappears(t *testing.T) {
	service := &fakeEnforcementService{}
	server := newEnforcementTestServer(enforcementTestRepository(domain.EnforcementActive), passingReadinessChecks(time.Now().UTC()), service)

	// The fake service accepts any ID; the card rebuild then misses ID 999,
	// which must turn into a client-side redirect instead of a broken swap.
	recorder := postHXForm(t, server, "/repositories/reconcile", map[string]string{"repository_id": "999"})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 with HX-Redirect, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("HX-Redirect"); got != "/repositories" {
		t.Fatalf("expected HX-Redirect to /repositories, got %q", got)
	}
}

func postHXFreezeForm(t *testing.T, server *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	cookie, csrfToken := getFreezeForm(t, server)
	form.Set(csrfFormField, csrfToken)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	request.AddCookie(cookie)
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func freezeHXTestServer(store *fakeFreezeStore) *Server {
	repo := domain.Repository{ID: 1, Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main", EnforcementState: domain.EnforcementActive}
	return NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{repo}}, FreezeStore: store})
}

func TestCreateFreezeHXRequestReturnsLiveFragmentWithToast(t *testing.T) {
	store := &fakeFreezeStore{}
	server := freezeHXTestServer(store)

	recorder := postHXFreezeForm(t, server, "/freezes", freezeCreateForm())

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 fragment for HX freeze create, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if vary := recorder.Header().Values("Vary"); !containsString(vary, "HX-Request") {
		t.Fatalf("expected Vary: HX-Request on HX response, got %v", vary)
	}
	if len(store.created) != 1 || store.created[0].Branch != "main" {
		t.Fatalf("unexpected freeze creations: %+v", store.created)
	}
	body := recorder.Body.String()
	for _, want := range []string{`id="freezes-live"`, `id="active-freezes"`, `id="toasts" hx-swap-oob="true"`, "Freeze started."} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected HX fragment to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected HX response to be a fragment without the page shell, got %q", body)
	}
}

func TestCreateFreezeHXValidationErrorReturns200FragmentWithPreservedValues(t *testing.T) {
	store := &fakeFreezeStore{err: freeze.ValidationError{Message: "branch is already frozen"}}
	server := freezeHXTestServer(store)

	recorder := postHXFreezeForm(t, server, "/freezes", freezeCreateForm())

	// main.js only swaps 2xx and 5xx responses, so HX validation errors must
	// come back as 200 fragments to re-render the workbench with the error.
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 fragment for HX validation error, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{`id="freezes-live"`, `role="alert"`, "branch is already frozen", `value="release window"`, `<option value="main" data-repository="1" selected>main</option>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected HX validation fragment to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `id="toasts"`) {
		t.Fatalf("expected no success toast on validation error, got %q", body)
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Fatalf("expected HX validation response to be a fragment, got %q", body)
	}
}

func TestEndAndCancelFreezeHXRequestsReturnActiveFreezesFragmentWithToast(t *testing.T) {
	for path, toast := range map[string]string{
		"/freezes/end":    "Freeze lifted.",
		"/freezes/cancel": "Freeze cancelled.",
	} {
		store := &fakeFreezeStore{freezes: []domain.BranchFreeze{{ID: 9, RepositoryID: 1, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true, Reason: "release"}}}
		server := freezeHXTestServer(store)

		recorder := postHXFreezeForm(t, server, path, freezeCloseForm(9))

		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: expected 200 fragment, got %d body=%q", path, recorder.Code, recorder.Body.String())
		}
		if vary := recorder.Header().Values("Vary"); !containsString(vary, "HX-Request") {
			t.Fatalf("%s: expected Vary: HX-Request, got %v", path, vary)
		}
		body := recorder.Body.String()
		for _, want := range []string{`id="active-freezes"`, `id="toasts" hx-swap-oob="true"`, toast} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s: expected HX fragment to contain %q, got %q", path, want, body)
			}
		}
		if strings.Contains(body, `id="freezes-live"`) {
			t.Fatalf("%s: expected lift/cancel to swap only the active-freezes region, got %q", path, body)
		}
		if strings.Contains(body, "<!doctype html>") {
			t.Fatalf("%s: expected HX response to be a fragment, got %q", path, body)
		}
	}
}

func TestCloseFreezeHXValidationErrorReturnsActiveFreezesFragment(t *testing.T) {
	store := &fakeFreezeStore{err: freeze.ValidationError{Message: "freeze is not active"}}
	server := freezeHXTestServer(store)

	recorder := postHXFreezeForm(t, server, "/freezes/end", freezeCloseForm(9))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 fragment for HX close validation error, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{`id="active-freezes"`, `role="alert"`, "freeze is not active"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected HX close validation fragment to contain %q, got %q", want, body)
		}
	}
	if strings.Contains(body, `id="toasts"`) {
		t.Fatalf("expected no success toast on close validation error, got %q", body)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}
