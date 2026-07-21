package freeze

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

// insertTestSchedule creates a minimal schedules row directly: the freeze
// package cannot import internal/schedule (schedule imports freeze), and the
// store only needs a valid foreign-key target for schedule_id.
func insertTestSchedule(t *testing.T, ctx context.Context, database *sql.DB, repositoryID int64, name string) int64 {
	t.Helper()
	now := time.Now().UTC().Format(sqliteTimestampFormat)
	result, err := database.ExecContext(ctx, `
INSERT INTO schedules (repository_id, branch, name, kind, timezone, active, created_at, updated_at)
VALUES (?, 'main', ?, 'weekly', 'UTC', 1, ?, ?)`, repositoryID, name, now, now)
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
	scheduleID := insertTestSchedule(t, ctx, database, repo.ID, "Nightly release lock")
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

func TestStoreSnapshotsScheduleNameThroughScheduleDeletion(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	scheduleID := insertTestSchedule(t, ctx, database, repo.ID, "Nightly release lock")
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{
		RepositoryID: repo.ID,
		Branch:       "main",
		ScheduleID:   &scheduleID,
		ScheduleName: "Nightly release lock",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ScheduleName != "Nightly release lock" {
		t.Fatalf("expected schedule name to round-trip, got %q", created.ScheduleName)
	}

	// The snapshot is the whole point: a hard schedule delete mid-window must
	// not blank the name on the live freeze row.
	if _, err := database.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, scheduleID); err != nil {
		t.Fatal(err)
	}
	survivor, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if survivor.ScheduleID != nil {
		t.Fatalf("expected schedule link cleared by ON DELETE SET NULL, got %+v", survivor.ScheduleID)
	}
	if survivor.ScheduleName != "Nightly release lock" {
		t.Fatalf("expected schedule name to survive schedule deletion, got %q", survivor.ScheduleName)
	}
}

func TestStoreUpdatesMaterializedAttributionInPlace(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	weeklyID := insertTestSchedule(t, ctx, database, repo.ID, "Work week lock")
	datedID := insertTestSchedule(t, ctx, database, repo.ID, "Christmas maintenance")
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{
		RepositoryID:  repo.ID,
		Branch:        "main",
		Reason:        "Work week",
		PlannedEndsAt: timePointer(time.Now().UTC().Add(4 * time.Hour)),
		ScheduleID:    &weeklyID,
		ScheduleName:  "Work week lock",
	})
	if err != nil {
		t.Fatal(err)
	}

	newEnd := time.Now().UTC().Add(9 * 24 * time.Hour).Truncate(time.Second)
	updated, err := store.UpdateMaterializedAttribution(ctx, UpdateAttributionParams{
		FreezeID:      created.ID,
		ScheduleID:    datedID,
		ScheduleName:  "Christmas maintenance",
		Reason:        "Holiday change stop",
		PlannedEndsAt: &newEnd,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ScheduleID == nil || *updated.ScheduleID != datedID {
		t.Fatalf("expected freeze relinked to schedule %d, got %+v", datedID, updated.ScheduleID)
	}
	if updated.ScheduleName != "Christmas maintenance" || updated.Reason != "Holiday change stop" {
		t.Fatalf("expected relabeled attribution, got %+v", updated)
	}
	if updated.PlannedEndsAt == nil || !updated.PlannedEndsAt.Equal(newEnd) {
		t.Fatalf("expected planned end %v, got %v", newEnd, updated.PlannedEndsAt)
	}
	// Identity and lifecycle are untouched: same row, still active, same start.
	if updated.ID != created.ID || updated.Status != domain.BranchFreezeStatusActive {
		t.Fatalf("expected the same live row, got %+v", updated)
	}
	if updated.StartsAt == nil || created.StartsAt == nil || !updated.StartsAt.Equal(*created.StartsAt) {
		t.Fatalf("expected start to stay %v, got %v", created.StartsAt, updated.StartsAt)
	}
}

func TestStoreRejectsAttributionUpdateForEndedOrManualFreezes(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	scheduleID := insertTestSchedule(t, ctx, database, repo.ID, "Nightly release lock")
	store := NewStore(database)

	ended, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", ScheduleID: &scheduleID, ScheduleName: "Work week lock"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(ctx, ended.ID); err != nil {
		t.Fatal(err)
	}
	manual, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "dev", Reason: "Manual freeze"})
	if err != nil {
		t.Fatal(err)
	}

	for name, freezeID := range map[string]int64{"ended freeze": ended.ID, "manual freeze": manual.ID} {
		params := UpdateAttributionParams{FreezeID: freezeID, ScheduleID: scheduleID, ScheduleName: "Work week lock"}
		if _, err := store.UpdateMaterializedAttribution(ctx, params); !errors.As(err, &ValidationError{}) {
			t.Fatalf("expected ValidationError relabeling %s, got %v", name, err)
		}
	}
}

func TestScheduleDeletionUnlinksHistoricalFreezeRow(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	scheduleID := insertTestSchedule(t, ctx, database, repo.ID, "Nightly release lock")
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
