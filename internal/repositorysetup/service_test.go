package repositorysetup

import (
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

func TestRedactURLUserInfoFailsClosedOnInvalidURL(t *testing.T) {
	if got := redactURLUserInfo("https://%zz.example.test?access_token=secret"); got != "[invalid URL]" {
		t.Fatalf("expected invalid URL placeholder, got %q", got)
	}
	if got := redactURLUserInfo("https:token:secret@codeberg.org?access_token=secret#fragment"); got != "[invalid URL]" {
		t.Fatalf("expected opaque URL placeholder, got %q", got)
	}
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
