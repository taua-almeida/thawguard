package app

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/secrets"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
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
