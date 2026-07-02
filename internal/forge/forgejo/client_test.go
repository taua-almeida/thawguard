package forgejo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
