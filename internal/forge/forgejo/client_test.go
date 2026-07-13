package forgejo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
)

func TestClientPostsCommitStatus(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotBody commitStatusRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("expected JSON content type, got %q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client := New(server.URL, "secret-token")

	err := client.PostCommitStatus(context.Background(), "taua-almeida", "thawguard", forge.CommitStatus{SHA: "ABC123", State: domain.CommitStatusFailure, Context: domain.RequiredStatusContext, Description: "Branch is frozen; merge is blocked by Thawguard", TargetURL: "https://example.test/status/1"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/repos/taua-almeida/thawguard/statuses/abc123" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if gotAuth != "token secret-token" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if gotBody.State != "failure" || gotBody.Context != domain.RequiredStatusContext || gotBody.Description == "" || gotBody.TargetURL == "" {
		t.Fatalf("unexpected request body %+v", gotBody)
	}
}

func TestClientRejectsInvalidCommitStatus(t *testing.T) {
	client := New("https://codeberg.org", "token")
	if err := client.PostCommitStatus(context.Background(), "", "repo", forge.CommitStatus{SHA: "abc123", State: domain.CommitStatusFailure, Context: domain.RequiredStatusContext}); err == nil {
		t.Fatal("expected missing owner error")
	}
	if err := client.PostCommitStatus(context.Background(), "owner", "repo", forge.CommitStatus{SHA: "abc123", State: "invalid", Context: domain.RequiredStatusContext}); err == nil {
		t.Fatal("expected invalid state error")
	}
}

func TestClientGetsPullRequest(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/repos/taua-almeida/thawguard/pulls/42" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(newPullRequestResponse(42, "Release fix", "open", "main", "ABCDEF123456", "https://codeberg.org/taua-almeida/thawguard/pulls/42"))
	}))
	defer server.Close()
	client := New(server.URL, "read-token")

	pr, err := client.GetPullRequest(context.Background(), "taua-almeida", "thawguard", 42)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "token read-token" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if pr.Index != 42 || pr.Title != "Release fix" || pr.State != "open" || pr.TargetBranch != "main" || pr.HeadSHA != "abcdef123456" || pr.URL == "" {
		t.Fatalf("unexpected pull request %+v", pr)
	}
}

func TestClientRejectsInvalidPullRequestGet(t *testing.T) {
	client := New("https://codeberg.org", "token")
	if _, err := client.GetPullRequest(context.Background(), "", "repo", 1); err == nil {
		t.Fatal("expected missing owner error")
	}
	if _, err := client.GetPullRequest(context.Background(), "owner", "repo", 0); err == nil {
		t.Fatal("expected missing pull request error")
	}
}

func TestClientListsOpenPullRequests(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/repos/taua-almeida/thawguard/pulls" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("state") != "open" || query.Get("base") != "main" || query.Get("page") != "1" || query.Get("limit") != "50" {
			t.Fatalf("unexpected query %s", r.URL.RawQuery)
		}
		gotAuth = r.Header.Get("Authorization")
		writePullRequests(t, w, []pullRequestResponse{
			newPullRequestResponse(12, "Release fix", "open", "main", "ABCDEF123456", "https://codeberg.org/taua-almeida/thawguard/pulls/12"),
			newPullRequestResponse(13, "Other branch", "open", "develop", "123456ABCDEF", "https://codeberg.org/taua-almeida/thawguard/pulls/13"),
		})
	}))
	defer server.Close()
	client := New(server.URL, "read-token")

	prs, err := client.ListOpenPullRequests(context.Background(), "taua-almeida", "thawguard", "main")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "token read-token" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if len(prs) != 1 {
		t.Fatalf("expected one pull request for target branch, got %+v", prs)
	}
	pr := prs[0]
	if pr.Index != 12 || pr.Title != "Release fix" || pr.State != "open" || pr.TargetBranch != "main" || pr.HeadSHA != "abcdef123456" || pr.URL == "" {
		t.Fatalf("unexpected pull request %+v", pr)
	}
}

func TestClientListOpenPullRequestsPaginatesBeforeClientSideBranchFilter(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil {
			t.Fatalf("page query is not an integer: %v", err)
		}
		switch page {
		case 1:
			payload := make([]pullRequestResponse, 50)
			for i := range payload {
				payload[i] = newPullRequestResponse(i+1, "Non-target", "open", "develop", "abcdef123456", "")
			}
			writePullRequests(t, w, payload)
		case 2:
			writePullRequests(t, w, []pullRequestResponse{newPullRequestResponse(51, "Target", "open", "main", "bbbbbb123456", "")})
		default:
			t.Fatalf("unexpected page %d", page)
		}
	}))
	defer server.Close()
	client := New(server.URL, "")

	prs, err := client.ListOpenPullRequests(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("expected two page requests, got %d", requests)
	}
	if len(prs) != 1 || prs[0].Index != 51 {
		t.Fatalf("expected target PR from second page, got %+v", prs)
	}
}

func TestClientListOpenPullRequestsAllowsRepositoryWideListing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("base"); got != "" {
			t.Fatalf("expected no base filter, got %q", got)
		}
		writePullRequests(t, w, []pullRequestResponse{
			newPullRequestResponse(1, "Main", "open", "main", "abc123", ""),
			newPullRequestResponse(2, "Release", "open", "release", "abc123", ""),
		})
	}))
	defer server.Close()
	client := New(server.URL, "token")

	prs, err := client.ListOpenPullRequests(context.Background(), "owner", "repo", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].TargetBranch != "main" || prs[1].TargetBranch != "release" {
		t.Fatalf("expected all open branches, got %+v", prs)
	}
}

func TestClientRejectsInvalidPullRequestList(t *testing.T) {
	client := New("https://codeberg.org", "token")
	if _, err := client.ListOpenPullRequests(context.Background(), "", "repo", "main"); err == nil {
		t.Fatal("expected missing owner error")
	}
}

func TestClientReadsBranchProtection(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if got := r.URL.EscapedPath(); got != "/api/v1/repos/team%20name/repo%20name/branch_protections/release%2F1.0" {
			t.Fatalf("unexpected escaped path %q", got)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(branchProtectionResponse{
			BranchName:          "release/1.0",
			EnableStatusCheck:   true,
			StatusCheckContexts: []string{domain.RequiredStatusContext, "ci/test"},
		})
	}))
	defer server.Close()
	client := New(server.URL, "read-token")

	protection, err := client.ReadBranchProtection(context.Background(), "team name", "repo name", "release/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "token read-token" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if !protection.Protected || !protection.RequiresStatusCheck || protection.Branch != "release/1.0" {
		t.Fatalf("unexpected protection %+v", protection)
	}
	if len(protection.RequiredContexts) != 2 || protection.RequiredContexts[0] != domain.RequiredStatusContext {
		t.Fatalf("unexpected contexts %+v", protection.RequiredContexts)
	}
}

func TestClientReadsBranchProtectionWithStatusChecksDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(branchProtectionResponse{BranchName: "main"})
	}))
	defer server.Close()

	protection, err := New(server.URL, "token").ReadBranchProtection(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatal(err)
	}
	if !protection.Protected || protection.RequiresStatusCheck || len(protection.RequiredContexts) != 0 {
		t.Fatalf("unexpected protection %+v", protection)
	}
}

func TestClientTreatsMissingBranchProtectionAsUnprotected(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	protection, err := New(server.URL, "token").ReadBranchProtection(context.Background(), "owner", "repo", "main")
	if !errors.Is(err, forge.ErrBranchProtectionNotFound) {
		t.Fatalf("expected not-found evidence, got protection=%+v err=%v", protection, err)
	}
	if protection.Protected || protection.Branch != "main" {
		t.Fatalf("unexpected missing protection evidence %+v", protection)
	}
}

func TestClientRejectsMalformedBranchProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"branch_name":`))
	}))
	defer server.Close()

	if _, err := New(server.URL, "token").ReadBranchProtection(context.Background(), "owner", "repo", "main"); err == nil || !strings.Contains(err.Error(), "decode branch protection response") {
		t.Fatalf("expected malformed JSON error, got %v", err)
	}
}

func TestClientBoundsAndRedactsBranchProtectionErrors(t *testing.T) {
	const token = "secret-read-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(token + strings.Repeat("x", 1024)))
	}))
	defer server.Close()

	_, err := New(server.URL, token).ReadBranchProtection(context.Background(), "owner", "repo", "main")
	if err == nil {
		t.Fatal("expected forge error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("expected token redaction, got %v", err)
	}
	if len(err.Error()) > 700 {
		t.Fatalf("expected bounded error, got %d bytes", len(err.Error()))
	}
}

func TestClientEmptyPullRequestListProvesReadableResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]pullRequestResponse{})
	}))
	defer server.Close()

	prs, err := New(server.URL, "token").ListOpenPullRequests(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 0 {
		t.Fatalf("expected empty readable list, got %+v", prs)
	}
}

func TestClientReturnsForgeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no token", http.StatusUnauthorized)
	}))
	defer server.Close()
	client := New(server.URL, "")

	err := client.PostCommitStatus(context.Background(), "owner", "repo", forge.CommitStatus{SHA: "abc123", State: domain.CommitStatusSuccess, Context: domain.RequiredStatusContext})
	if err == nil {
		t.Fatal("expected forge error")
	}
}

func newPullRequestResponse(number int, title string, state string, baseRef string, headSHA string, htmlURL string) pullRequestResponse {
	var pr pullRequestResponse
	pr.Number = number
	pr.Title = title
	pr.State = state
	pr.HTMLURL = htmlURL
	pr.Base.Ref = baseRef
	pr.Head.SHA = headSHA
	return pr
}

func writePullRequests(t *testing.T, w http.ResponseWriter, payload []pullRequestResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatal(err)
	}
}
