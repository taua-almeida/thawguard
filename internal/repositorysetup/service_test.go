package repositorysetup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

func TestServiceCreatesRepositoryAndAuditEventAtomically(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewService(database)

	repo, err := service.Create(ctx, repository.CreateParams{
		Forge:         "forgejo",
		BaseURL:       "https://token:secret@codeberg.org?access_token=secret#fragment",
		Owner:         "taua-almeida",
		Name:          "thawguard",
		DefaultBranch: "main",
	}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.ID == 0 {
		t.Fatal("expected repository id")
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	event := events[0]
	if event.Action != audit.ActionRepositoryCreated {
		t.Fatalf("unexpected action: %q", event.Action)
	}
	if event.SubjectType != audit.SubjectTypeRepository || event.SubjectID != "1" {
		t.Fatalf("unexpected subject: %s/%s", event.SubjectType, event.SubjectID)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" {
		t.Fatalf("unexpected actor details: %s", event.DetailsJSON)
	}
	if details["base_url"] != "https://codeberg.org" {
		t.Fatalf("expected redacted base URL, got %q", details["base_url"])
	}
}

func TestServiceRollsBackRepositoryWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewService(database)
	missingUserID := int64(999)

	_, err := service.Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard"}, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	repositories, listErr := service.List(ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(repositories) != 0 {
		t.Fatalf("expected rollback to leave no repositories, got %d", len(repositories))
	}
	events, listErr := audit.NewStore(database).List(ctx, 10)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(events) != 0 {
		t.Fatalf("expected rollback to leave no audit events, got %d", len(events))
	}
}

func TestServiceSetsEncryptedWebhookSecretAndAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	secretStore := newTestSecretStore(t)
	service := NewServiceWithSecrets(database, secretStore)
	repo, err := service.Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := service.SetWebhookSecret(ctx, repo.ID, "first-webhook-secret", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.HasWebhookSecret {
		t.Fatal("expected repository to report configured webhook secret")
	}

	var ciphertext []byte
	if err := database.QueryRowContext(ctx, `SELECT ciphertext FROM repository_webhook_secrets WHERE repository_id = ?`, repo.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte("first-webhook-secret")) {
		t.Fatalf("expected encrypted webhook secret, got %q", ciphertext)
	}
	decrypted, found, err := service.WebhookSecret(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || decrypted != "first-webhook-secret" {
		t.Fatalf("expected decrypted webhook secret, found=%v value=%q", found, decrypted)
	}

	if _, err := service.SetWebhookSecret(ctx, repo.ID, "second-webhook-secret", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	rotated, found, err := service.WebhookSecret(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || rotated != "second-webhook-secret" {
		t.Fatalf("expected rotated webhook secret, found=%v value=%q", found, rotated)
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("expected repository create plus two webhook secret audit events, got %d", len(events))
	}
	latest := events[0]
	if latest.Action != audit.ActionRepositoryWebhookSecretConfigured {
		t.Fatalf("unexpected latest action: %q", latest.Action)
	}
	if bytes.Contains([]byte(latest.DetailsJSON), []byte("second-webhook-secret")) || bytes.Contains([]byte(latest.DetailsJSON), []byte("first-webhook-secret")) {
		t.Fatalf("expected audit details not to contain webhook secrets, got %s", latest.DetailsJSON)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(latest.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["webhook_secret_was_configured"] != "true" {
		t.Fatalf("expected rotation audit flag, got %s", latest.DetailsJSON)
	}
}

func TestServiceRejectsWebhookSecretWithoutEncryptionStore(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewService(database)
	repo, err := service.Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.SetWebhookSecret(ctx, repo.ID, "first-webhook-secret", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); !IsConfigurationError(err) {
		t.Fatalf("expected configuration error, got %v", err)
	}
	if _, found, err := service.WebhookSecret(ctx, repo.ID); !IsConfigurationError(err) || found {
		t.Fatalf("expected configuration error and no secret, found=%v err=%v", found, err)
	}
}

func TestServiceRejectsInvalidWebhookSecretParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewServiceWithSecrets(database, newTestSecretStore(t))
	repo, err := service.Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name         string
		repositoryID int64
		secret       string
	}{
		{name: "missing repository", repositoryID: 0, secret: "first-webhook-secret"},
		{name: "short secret", repositoryID: repo.ID, secret: "short"},
		{name: "leading whitespace", repositoryID: repo.ID, secret: " first-webhook-secret"},
		{name: "trailing whitespace", repositoryID: repo.ID, secret: "first-webhook-secret "},
		{name: "control character", repositoryID: repo.ID, secret: "first\nwebhook-secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.SetWebhookSecret(ctx, test.repositoryID, test.secret, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}

func TestRedactURLUserInfoFailsClosedOnInvalidURL(t *testing.T) {
	if got := redactURLUserInfo("https://%zz.example.test?access_token=secret"); got != "[invalid URL]" {
		t.Fatalf("expected invalid URL placeholder, got %q", got)
	}
	if got := redactURLUserInfo("https:token:secret@codeberg.org?access_token=secret#fragment"); got != "[invalid URL]" {
		t.Fatalf("expected opaque URL placeholder, got %q", got)
	}
}

func newTestSecretStore(t *testing.T) secrets.Store {
	t.Helper()
	store, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	migrations, err := db.LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return database
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
