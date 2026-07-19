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

func TestStoreListsNewestFirstWithStableIDOrdering(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	older := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	newer := older.Add(time.Second)

	insertStoredEvent(t, ctx, store, "older", older)
	insertStoredEvent(t, ctx, store, "newer-first", newer)
	insertStoredEvent(t, ctx, store, "newer-second", newer)

	events, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"newer-second", "newer-first", "older"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i := range want {
		if events[i].SubjectID != want[i] {
			t.Fatalf("event %d: expected subject %q, got %q", i, want[i], events[i].SubjectID)
		}
	}
}

func TestStoreListHonorsBoundedLimit(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		insertStoredEvent(t, ctx, store, strconv.Itoa(i+1), createdAt.Add(time.Duration(i)*time.Second))
	}

	events, err := store.List(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].SubjectID != "5" || events[1].SubjectID != "4" {
		t.Fatalf("expected newest two events, got %+v", events)
	}
}

func TestStoreListPageFiltersByExactActionNames(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

	insertStoredActionEvent(t, ctx, store, ActionRepositoryCreated, "repo-1", base)
	insertStoredActionEvent(t, ctx, store, ActionBranchFreezeCreated, "freeze-1", base.Add(time.Second))
	insertStoredActionEvent(t, ctx, store, ActionUserRolesUpdated, "user-1", base.Add(2*time.Second))
	insertStoredActionEvent(t, ctx, store, ActionBranchFreezeEnded, "freeze-2", base.Add(3*time.Second))
	// A prefix-sharing action must not match an exact IN-list filter.
	insertStoredActionEvent(t, ctx, store, ActionBranchFreezeCreated+".extra", "freeze-3", base.Add(4*time.Second))

	events, total, err := store.ListPage(ctx, []string{ActionBranchFreezeCreated, ActionBranchFreezeEnded}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	want := []string{"freeze-2", "freeze-1"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i := range want {
		if events[i].SubjectID != want[i] {
			t.Fatalf("event %d: expected subject %q, got %q", i, want[i], events[i].SubjectID)
		}
	}
}

func TestStoreListPageWithoutActionsReturnsAll(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

	insertStoredActionEvent(t, ctx, store, ActionRepositoryCreated, "repo-1", base)
	insertStoredActionEvent(t, ctx, store, ActionUserDisabled, "user-1", base.Add(time.Second))

	events, total, err := store.ListPage(ctx, nil, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(events) != 2 {
		t.Fatalf("expected all 2 events, got %d of total %d", len(events), total)
	}
	if events[0].SubjectID != "user-1" || events[1].SubjectID != "repo-1" {
		t.Fatalf("expected newest-first ordering, got %+v", events)
	}
}

func TestStoreListPagePaginatesWithStableTotal(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		insertStoredEvent(t, ctx, store, strconv.Itoa(i+1), base.Add(time.Duration(i)*time.Second))
	}

	events, total, err := store.ListPage(ctx, nil, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(events) != 2 || events[0].SubjectID != "3" || events[1].SubjectID != "2" {
		t.Fatalf("expected middle page (3, 2), got %+v", events)
	}
}

func TestStoreListPageClampsOffsetAndLimit(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i := range 3 {
		insertStoredEvent(t, ctx, store, strconv.Itoa(i+1), base.Add(time.Duration(i)*time.Second))
	}

	events, total, err := store.ListPage(ctx, nil, -5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(events) != 3 {
		t.Fatalf("expected clamped query to return all 3 events, got %d of total %d", len(events), total)
	}
	if events[0].SubjectID != "3" {
		t.Fatalf("expected newest event first, got %+v", events)
	}
}

func TestStoreListPageReturnsSafeScanFailure(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO audit_events(action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?)`, ActionRepositoryCreated, SubjectTypeRepository, "1", `{}`, "not-a-time"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.ListPage(ctx, nil, 0, 10); err == nil {
		t.Fatal("expected invalid stored timestamp to fail safely")
	}
}

func TestStoreListReturnsSafeScanFailure(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO audit_events(action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?)`, ActionRepositoryCreated, SubjectTypeRepository, "1", `{}`, "not-a-time"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.List(ctx, 10); err == nil {
		t.Fatal("expected invalid stored timestamp to fail safely")
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

func insertStoredEvent(t *testing.T, ctx context.Context, store *Store, subjectID string, createdAt time.Time) {
	t.Helper()
	insertStoredActionEvent(t, ctx, store, ActionRepositoryCreated, subjectID, createdAt)
}

func insertStoredActionEvent(t *testing.T, ctx context.Context, store *Store, action, subjectID string, createdAt time.Time) {
	t.Helper()
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO audit_events(action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?)`, action, SubjectTypeRepository, subjectID, `{}`, createdAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
