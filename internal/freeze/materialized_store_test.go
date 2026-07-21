package freeze

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// insertTestSchedule creates a minimal schedules row directly: the freeze
// package cannot import internal/schedule (schedule imports freeze), and the
// store only needs a valid foreign-key target for schedule_id.
func insertTestSchedule(t *testing.T, ctx context.Context, database *sql.DB, repositoryID int64) int64 {
	t.Helper()
	now := time.Now().UTC().Format(sqliteTimestampFormat)
	result, err := database.ExecContext(ctx, `
INSERT INTO schedules (repository_id, branch, name, kind, timezone, active, created_at, updated_at)
VALUES (?, 'main', 'Nightly release lock', 'weekly', 'UTC', 1, ?, ?)`, repositoryID, now, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStoreLinksFreezeToScheduleAndQueriesMaterializedRows(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	scheduleID := insertTestSchedule(t, ctx, database, repo.ID)
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{
		RepositoryID:  repo.ID,
		Branch:        "main",
		Reason:        "Release window",
		PlannedEndsAt: timePointer(time.Now().UTC().Add(4 * time.Hour)),
		ScheduleID:    &scheduleID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ScheduleID == nil || *created.ScheduleID != scheduleID {
		t.Fatalf("expected freeze linked to schedule %d, got %+v", scheduleID, created.ScheduleID)
	}

	loaded, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ScheduleID == nil || *loaded.ScheduleID != scheduleID {
		t.Fatalf("expected schedule_id to round-trip through Get, got %+v", loaded.ScheduleID)
	}

	live, found, err := store.GetActiveForBranch(ctx, repo.ID, "main")
	if err != nil {
		t.Fatal(err)
	}
	if !found || live.ID != created.ID {
		t.Fatalf("expected live freeze %d for branch, got found=%v %+v", created.ID, found, live)
	}

	linked, found, err := store.ActiveForSchedule(ctx, scheduleID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || linked.ID != created.ID {
		t.Fatalf("expected live freeze %d for schedule, got found=%v %+v", created.ID, found, linked)
	}

	materialized, err := store.ListActiveMaterialized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized) != 1 || materialized[0].ID != created.ID {
		t.Fatalf("expected exactly the linked freeze in materialized list, got %+v", materialized)
	}

	if _, err := store.End(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err = store.GetActiveForBranch(ctx, repo.ID, "main"); err != nil || found {
		t.Fatalf("expected no live freeze after end, found=%v err=%v", found, err)
	}
	if _, found, err = store.ActiveForSchedule(ctx, scheduleID); err != nil || found {
		t.Fatalf("expected no live schedule freeze after end, found=%v err=%v", found, err)
	}
	if materialized, err = store.ListActiveMaterialized(ctx); err != nil || len(materialized) != 0 {
		t.Fatalf("expected empty materialized list after end, got %+v err=%v", materialized, err)
	}
}

func TestStoreExcludesManualFreezesFromMaterializedQueries(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	manual, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "Manual freeze"})
	if err != nil {
		t.Fatal(err)
	}
	if manual.ScheduleID != nil {
		t.Fatalf("expected manual freeze without schedule link, got %+v", manual.ScheduleID)
	}

	// The manual row is still the branch's live freeze…
	live, found, err := store.GetActiveForBranch(ctx, repo.ID, "main")
	if err != nil || !found || live.ID != manual.ID {
		t.Fatalf("expected manual freeze as live branch freeze, got found=%v %+v err=%v", found, live, err)
	}
	// …but never a materialized one.
	materialized, err := store.ListActiveMaterialized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized) != 0 {
		t.Fatalf("expected no materialized rows for manual freezes, got %+v", materialized)
	}
}

func TestScheduleDeletionUnlinksHistoricalFreezeRow(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	scheduleID := insertTestSchedule(t, ctx, database, repo.ID)
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", ScheduleID: &scheduleID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(ctx, created.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, scheduleID); err != nil {
		t.Fatal(err)
	}
	unlinked, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unlinked.ScheduleID != nil {
		t.Fatalf("expected ON DELETE SET NULL to unlink the historical freeze, got %+v", unlinked.ScheduleID)
	}
}
