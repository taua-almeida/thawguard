package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/db"
)

func TestStoreRecordsAndListsAuditEvents(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return createdAt }
	actorUserID := int64(42)
	createdAtText := createdAt.Format(time.RFC3339Nano)
	_, err := store.db.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, password_hash, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, actorUserID, "admin@example.test", "Admin", "hash", "admin", createdAtText, createdAtText)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Record(ctx, Event{
		ActorUserID: &actorUserID,
		Action:      ActionRepositoryCreated,
		SubjectType: SubjectTypeRepository,
		SubjectID:   "7",
		DetailsJSON: `{"forge":"forgejo","full_name":"taua-almeida/thawguard"}`,
		CreatedAt:   createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	event := events[0]
	if event.ID == 0 {
		t.Fatal("expected audit event id")
	}
	if event.ActorUserID == nil || *event.ActorUserID != actorUserID {
		t.Fatalf("unexpected actor user id: %+v", event.ActorUserID)
	}
	if event.Action != ActionRepositoryCreated {
		t.Fatalf("unexpected action: %q", event.Action)
	}
	if event.SubjectType != SubjectTypeRepository || event.SubjectID != "7" {
		t.Fatalf("unexpected subject: %s/%s", event.SubjectType, event.SubjectID)
	}
	if !event.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected created_at %s, got %s", createdAt, event.CreatedAt)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["full_name"] != "taua-almeida/thawguard" {
		t.Fatalf("unexpected details JSON: %s", event.DetailsJSON)
	}
}

func TestStoreDefaultsDetailsAndCreatedAt(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return createdAt }

	err := store.Record(ctx, Event{
		Action:      "test.action",
		SubjectType: "test_subject",
		SubjectID:   "123",
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].DetailsJSON != "{}" {
		t.Fatalf("expected default details JSON, got %q", events[0].DetailsJSON)
	}
	if !events[0].CreatedAt.Equal(createdAt) {
		t.Fatalf("expected authoritative created_at %s, got %s", createdAt, events[0].CreatedAt)
	}
	if events[0].ActorUserID != nil {
		t.Fatalf("expected nil actor user id, got %+v", events[0].ActorUserID)
	}
}

func TestStoreListsAuditEventsBySubjectType(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return createdAt }

	if err := store.Record(ctx, Event{Action: ActionBranchFreezeCreated, SubjectType: SubjectTypeBranchFreeze, SubjectID: "freeze-1"}); err != nil {
		t.Fatal(err)
	}
	for i := range 60 {
		if err := store.Record(ctx, Event{Action: ActionRepositoryCreated, SubjectType: SubjectTypeRepository, SubjectID: strconv.Itoa(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := store.ListBySubjectType(ctx, SubjectTypeBranchFreeze, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 branch-freeze audit event, got %d", len(events))
	}
	if events[0].SubjectType != SubjectTypeBranchFreeze || events[0].SubjectID != "freeze-1" {
		t.Fatalf("unexpected audit event: %+v", events[0])
	}
}

func TestStoreRejectsMissingSubjectTypeFilter(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	if _, err := store.ListBySubjectType(ctx, "", 10); err == nil {
		t.Fatal("expected missing subject type error")
	}
}

func TestStoreRejectsInvalidAuditEvents(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)

	cases := []struct {
		name  string
		event Event
	}{
		{name: "missing action", event: Event{SubjectType: "repository", SubjectID: "1"}},
		{name: "missing subject type", event: Event{Action: "repository.created", SubjectID: "1"}},
		{name: "missing subject id", event: Event{Action: "repository.created", SubjectType: "repository"}},
		{name: "invalid JSON", event: Event{Action: "repository.created", SubjectType: "repository", SubjectID: "1", DetailsJSON: "not-json"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Record(ctx, tc.event); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func newTestStore(t *testing.T, ctx context.Context) *Store {
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
	return NewStore(database)
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
