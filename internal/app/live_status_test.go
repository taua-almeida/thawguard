package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/secrets"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

func TestStatusPublisherFromConfigPostsWithDecryptedRepositoryToken(t *testing.T) {
	ctx := context.Background()
	var authHeader string
	var statusPath string
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		statusPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer forge.Close()

	database := newAppTestDB(t, ctx)
	secretStore := newAppTestSecretStore(t)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forge.URL, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	result, err := statusresult.NewStore(database).Create(ctx, statusresult.CreateParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "ABC123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	publications := statuspublication.NewStore(database)
	publisher, err := statusPublisherFromConfig(config.Config{LiveStatusRepos: "taua-almeida/thawguard"}, statuspublication.DeliveryModeForgejoStatus, publications, repository.NewStore(database), repositorySetup)
	if err != nil {
		t.Fatal(err)
	}

	publication, err := publisher.Publish(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if publication.DeliveryMode != statuspublication.DeliveryModeForgejoStatus {
		t.Fatalf("expected forgejo_status publication, got %+v", publication)
	}
	if authHeader != "token live-status-token-123" {
		t.Fatalf("expected decrypted status token authorization header, got %q", authHeader)
	}
	if statusPath != "/api/v1/repos/taua-almeida/thawguard/statuses/abc123" {
		t.Fatalf("unexpected status path %q", statusPath)
	}
	attempts, err := publications.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].Mode != statuspublication.AttemptModeForgejoStatus || attempts[0].Result != statuspublication.AttemptResultPosted || attempts[0].Error != "" {
		t.Fatalf("expected posted forgejo status attempt, got %+v", attempts)
	}
}

func TestThawApprovalApprovesAndPublishesCurrentPullRequestHead(t *testing.T) {
	ctx := context.Background()
	var postedStatus map[string]string
	var statusPath string
	var authHeaders []string
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/pulls/42":
			_ = json.NewEncoder(w).Encode(newAppPullRequestResponse(42, "open", "main", "ABC123"))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/pulls":
			_ = json.NewEncoder(w).Encode([]forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "ABC123"), newAppPullRequestResponse(43, "open", "main", "DEF456")})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/statuses/abc123":
			statusPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&postedStatus); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected forge request %s %s", r.Method, r.URL.String())
		}
	}))
	defer forge.Close()

	database := newAppTestDB(t, ctx)
	secretStore := newAppTestSecretStore(t)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forge.URL, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(database).CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	pullRequests := pullrequest.NewStore(database)
	thaws := thawexception.NewStore(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freeze.NewService(database), thaws, pullRequests)
	publications := statuspublication.NewStore(database)
	publisher, err := statusPublisherFromConfig(config.Config{LiveStatusRepos: "taua-almeida/thawguard"}, statuspublication.DeliveryModeForgejoStatus, publications, repository.NewStore(database), repositorySetup)
	if err != nil {
		t.Fatal(err)
	}
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, []string{"taua-almeida/thawguard"}, forgejoPullRequestClientForRepository)
	approvals := newThawApprovalService(repository.NewStore(database), repositorySetup, pullRequests, thaws, statuses, publisher, syncer, []string{"taua-almeida/thawguard"}, forgejoThawApprovalClientForRepository)

	result, err := approvals.ApproveThaw(ctx, statusresult.ThawApprovalParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusSuccess || result.HeadSHA != "abc123" || result.PullRequestIndex != 42 {
		t.Fatalf("expected thaw success for current head, got %+v", result)
	}
	if statusPath != "/api/v1/repos/taua-almeida/thawguard/statuses/abc123" {
		t.Fatalf("unexpected posted status path %q", statusPath)
	}
	if postedStatus["context"] != domain.RequiredStatusContext || postedStatus["state"] != string(domain.CommitStatusSuccess) {
		t.Fatalf("unexpected posted status %+v", postedStatus)
	}
	for _, auth := range authHeaders {
		if auth != "token live-status-token-123" {
			t.Fatalf("unexpected auth header %q", auth)
		}
	}
}

func TestThawApprovalPublishesFailureWhenDuplicateOpenHeadExists(t *testing.T) {
	ctx := context.Background()
	var postedStatus map[string]string
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/pulls/42":
			_ = json.NewEncoder(w).Encode(newAppPullRequestResponse(42, "open", "main", "ABC123"))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/pulls":
			_ = json.NewEncoder(w).Encode([]forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "ABC123"), newAppPullRequestResponse(43, "open", "main", "ABC123")})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/statuses/abc123":
			if err := json.NewDecoder(r.Body).Decode(&postedStatus); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected forge request %s %s", r.Method, r.URL.String())
		}
	}))
	defer forge.Close()

	database := newAppTestDB(t, ctx)
	secretStore := newAppTestSecretStore(t)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forge.URL, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(database).CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	pullRequests := pullrequest.NewStore(database)
	thaws := thawexception.NewStore(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freeze.NewService(database), thaws, pullRequests)
	publications := statuspublication.NewStore(database)
	publisher, err := statusPublisherFromConfig(config.Config{LiveStatusRepos: "taua-almeida/thawguard"}, statuspublication.DeliveryModeForgejoStatus, publications, repository.NewStore(database), repositorySetup)
	if err != nil {
		t.Fatal(err)
	}
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, []string{"taua-almeida/thawguard"}, forgejoPullRequestClientForRepository)
	approvals := newThawApprovalService(repository.NewStore(database), repositorySetup, pullRequests, thaws, statuses, publisher, syncer, []string{"taua-almeida/thawguard"}, forgejoThawApprovalClientForRepository)

	result, err := approvals.ApproveThaw(ctx, statusresult.ThawApprovalParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.Description != "Thaw blocked because another open PR shares this head SHA" {
		t.Fatalf("expected duplicate-head failure, got %+v", result)
	}
	if postedStatus["context"] != domain.RequiredStatusContext || postedStatus["state"] != string(domain.CommitStatusFailure) {
		t.Fatalf("unexpected posted status %+v", postedStatus)
	}
}

type forgejoPullRequestResponse struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	Base    struct {
		Ref string `json:"ref"`
	} `json:"base"`
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func newAppPullRequestResponse(number int, state string, baseRef string, headSHA string) forgejoPullRequestResponse {
	var pr forgejoPullRequestResponse
	pr.Number = number
	pr.Title = "Release fix"
	pr.State = state
	pr.HTMLURL = "https://codeberg.org/taua-almeida/thawguard/pulls/42"
	pr.Base.Ref = baseRef
	pr.Head.SHA = headSHA
	return pr
}

func newAppTestSecretStore(t *testing.T) secrets.Store {
	t.Helper()
	store, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newAppTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := db.LoadMigrations(appTestMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return database
}

func appTestMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
