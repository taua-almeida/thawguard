package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
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

func TestRuntimeStatusPublisherPostsWithDecryptedRepositoryToken(t *testing.T) {
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
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}

	result, err := statusresult.NewStore(database).Create(ctx, statusresult.CreateParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "ABC123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)

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

// Legacy mode environment variables must not re-enable publishing or select a
// dry-run publisher; enforcement state is the only gate.
func TestRemovedModeEnvVarsDoNotAffectPublishing(t *testing.T) {
	ctx := context.Background()
	t.Setenv("THAWGUARD_STATUS_PUBLISHER", "dry_run")
	t.Setenv("THAWGUARD_LIVE_STATUS_POSTING", "enabled")
	t.Setenv("THAWGUARD_LIVE_STATUS_REPOSITORIES", "taua-almeida/thawguard")

	database := newAppTestDB(t, ctx)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, newAppTestSecretStore(t))
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	result, err := statusresult.NewStore(database).Create(ctx, statusresult.CreateParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)

	if _, err := publisher.Publish(ctx, result); !errors.Is(err, domain.ErrEnforcementNotActive) {
		t.Fatalf("expected setup-incomplete repository to stay unpublished despite legacy env vars, got %v", err)
	}
	attempts, err := publications.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected no publication attempts, got %+v", attempts)
	}
}

// Matrix row: active repository with a missing token fails closed and leaves a
// sanitized operator-visible failed attempt.
func TestActiveRepositoryMissingTokenFailsClosedWithSanitizedAttempt(t *testing.T) {
	ctx := context.Background()
	database := newAppTestDB(t, ctx)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, newAppTestSecretStore(t))
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	result, err := statusresult.NewStore(database).Create(ctx, statusresult.CreateParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"})
	if err != nil {
		t.Fatal(err)
	}
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)

	if _, err := publisher.Publish(ctx, result); err == nil {
		t.Fatal("expected missing-token publish to fail closed")
	}
	attempts, err := publications.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].Result != statuspublication.AttemptResultFailed || attempts[0].Error == "" {
		t.Fatalf("expected sanitized failed attempt for missing token, got %+v", attempts)
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
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(database).CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	pullRequests := pullrequest.NewStore(database)
	thaws := thawexception.NewService(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freeze.NewService(database), thaws, pullRequests)
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, forgejoPullRequestClientForRepository)
	approvals := newThawApprovalService(repository.NewStore(database), repositorySetup, pullRequests, thaws, freeze.NewService(database), statuses, publisher, syncer, forgejoThawApprovalClientForRepository)

	outcome, err := approvals.ApproveThaw(ctx, statusresult.ThawApprovalParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result == nil || outcome.ConfirmationRequired {
		t.Fatalf("expected immediate unique-head approval, got %+v", outcome)
	}
	result := *outcome.Result
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

func TestThawApprovalRequiresThenAppliesSharedHeadConfirmation(t *testing.T) {
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
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(database).CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	pullRequests := pullrequest.NewStore(database)
	thaws := thawexception.NewService(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freeze.NewService(database), thaws, pullRequests)
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, forgejoPullRequestClientForRepository)
	approvals := newThawApprovalService(repository.NewStore(database), repositorySetup, pullRequests, thaws, freeze.NewService(database), statuses, publisher, syncer, forgejoThawApprovalClientForRepository)

	outcome, err := approvals.ApproveThaw(ctx, statusresult.ThawApprovalParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.ConfirmationRequired || outcome.Result != nil || len(outcome.AffectedPullRequests) != 2 {
		t.Fatalf("expected shared-head confirmation requirement, got %+v", outcome)
	}
	for i, wantIndex := range []int{42, 43} {
		affected := outcome.AffectedPullRequests[i]
		if affected.Index != wantIndex || affected.Title == "" || affected.TargetBranch != "main" || affected.URL == "" || affected.HeadSHA != "abc123" {
			t.Fatalf("unexpected sanitized affected PR: %+v", affected)
		}
	}
	assertAppTableCount(t, database, "thaw_exceptions", 0)
	assertNoThawApprovalAuditEvents(t, ctx, database)
	if len(postedStatus) != 0 {
		t.Fatalf("expected no status publication before confirmation, got %+v", postedStatus)
	}

	confirmed, err := approvals.ApproveThaw(ctx, statusresult.ThawApprovalParams{
		RepositoryID:     repo.ID,
		PullRequestIndex: 42,
		TargetBranch:     "main",
		Reason:           "production fix",
		Confirmation:     outcome.Confirmation,
	}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Result == nil || confirmed.ConfirmationRequired || confirmed.Result.State != domain.CommitStatusSuccess {
		t.Fatalf("expected confirmed shared-head success, got %+v", confirmed)
	}
	assertAppTableCount(t, database, "thaw_exceptions", 2)
	events, err := audit.NewStore(database).List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	sharedApprovals := 0
	for _, event := range events {
		if event.Action == audit.ActionThawExceptionApproved {
			t.Fatalf("shared approval must not record a unique approval event: %+v", event)
		}
		if event.Action == audit.ActionThawExceptionSharedHeadApproved {
			sharedApprovals++
			if !strings.Contains(event.DetailsJSON, `"affected_pull_request_indexes":"42,43"`) || strings.Contains(event.DetailsJSON, "live-status-token-123") {
				t.Fatalf("unexpected shared approval audit details: %s", event.DetailsJSON)
			}
		}
	}
	if sharedApprovals != 1 {
		t.Fatalf("expected one shared approval audit event, got %d", sharedApprovals)
	}
	if postedStatus["context"] != domain.RequiredStatusContext || postedStatus["state"] != string(domain.CommitStatusSuccess) {
		t.Fatalf("unexpected posted status %+v", postedStatus)
	}
}

func assertAppTableCount(t *testing.T, database *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("expected %d rows in %s, got %d", want, table, got)
	}
}

func assertNoThawApprovalAuditEvents(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == audit.ActionThawExceptionApproved || event.Action == audit.ActionThawExceptionSharedHeadApproved {
			t.Fatalf("expected no thaw approval audit event, got %+v", event)
		}
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
