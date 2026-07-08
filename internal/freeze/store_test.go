package freeze

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreCreatesAndListsActiveFreezes(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: " dev ", Reason: " QA freeze "})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected freeze id")
	}
	if created.RepositoryID != repo.ID || created.Branch != "dev" || created.Reason != "QA freeze" {
		t.Fatalf("unexpected freeze: %+v", created)
	}
	if created.Status != domain.BranchFreezeStatusActive || !created.Active {
		t.Fatalf("expected active freeze, got %+v", created)
	}
	if created.StartsAt == nil {
		t.Fatal("expected active freeze start time")
	}

	freezes, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(freezes) != 1 || freezes[0].ID != created.ID {
		t.Fatalf("expected created freeze in active list, got %+v", freezes)
	}
}

func TestStoreRejectsInvalidFreezeParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.CreateActive(ctx, CreateParams{Branch: "main", Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing branch validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main"}); !IsValidationError(err) {
		t.Fatalf("expected missing reason validation error, got %v", err)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: 999, Branch: "main", Reason: "release"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
}

func TestStoreRejectsDuplicateActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	params := CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}

	if _, err := store.CreateActive(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateActive(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected duplicate active freeze validation error, got %v", err)
	}
}

func TestStoreAllowsScheduledFreezeWhenBranchIsAlreadyFrozen(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}); err != nil {
		t.Fatal(err)
	}
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekend", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("expected scheduled freeze to be allowed while branch is active: %v", err)
	}
	if scheduled.Status != domain.BranchFreezeStatusScheduled || !scheduled.Scheduled {
		t.Fatalf("expected scheduled freeze, got %+v", scheduled)
	}
	store.now = func() time.Time { return now.Add(time.Hour + time.Minute) }
	activated, err := store.ActivateScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatalf("expected scheduled freeze to activate even while another freeze is active: %v", err)
	}
	if activated.Status != domain.BranchFreezeStatusActive || !activated.Active || !activated.Scheduled {
		t.Fatalf("expected active scheduled freeze, got %+v", activated)
	}
	active, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("expected manual and scheduled active freezes, got %+v", active)
	}
}

func TestStoreAllowsMultipleScheduledFreezesForSameBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekday freeze", StartsAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekend freeze", StartsAt: now.Add(48 * time.Hour)}); err != nil {
		t.Fatalf("expected multiple scheduled freezes for one branch: %v", err)
	}
	scheduled, err := store.ListScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scheduled) != 2 {
		t.Fatalf("expected two scheduled freezes for same branch, got %+v", scheduled)
	}
}

func TestStoreCreatesListsActivatesAndEndsScheduledFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	startsAt := now.Add(time.Hour)
	plannedEndsAt := startsAt.Add(2 * time.Hour)

	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: " main ", Reason: " weekend freeze ", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt})
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled.Scheduled || scheduled.Status != domain.BranchFreezeStatusScheduled || scheduled.Active || scheduled.StartsAt == nil || scheduled.PlannedEndsAt == nil {
		t.Fatalf("expected scheduled freeze metadata, got %+v", scheduled)
	}
	listed, err := store.ListScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != scheduled.ID {
		t.Fatalf("expected scheduled freeze in list, got %+v", listed)
	}
	if due, err := store.ListDueScheduled(ctx, 10); err != nil || len(due) != 0 {
		t.Fatalf("expected no due freezes before start, due=%+v err=%v", due, err)
	}

	store.now = func() time.Time { return startsAt.Add(123 * time.Millisecond) }
	due, err := store.ListDueScheduled(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != scheduled.ID {
		t.Fatalf("expected due scheduled freeze, got %+v", due)
	}
	activated, err := store.ActivateScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Status != domain.BranchFreezeStatusActive || !activated.Active || !activated.Scheduled || !activated.NeedsRecompute {
		t.Fatalf("expected activated scheduled freeze, got %+v", activated)
	}
	recompute, err := store.ListScheduledNeedsRecompute(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recompute) != 1 || recompute[0].ID != scheduled.ID {
		t.Fatalf("expected activated schedule to need recompute, got %+v", recompute)
	}
	marked, err := store.MarkScheduledRecomputed(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if marked.NeedsRecompute {
		t.Fatalf("expected recompute marker to clear, got %+v", marked)
	}

	store.now = func() time.Time { return plannedEndsAt.Add(time.Minute) }
	dueEnds, err := store.ListDuePlannedUnfreezes(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dueEnds) != 1 || dueEnds[0].ID != scheduled.ID {
		t.Fatalf("expected due planned unfreeze, got %+v", dueEnds)
	}
	ended, err := store.ExecutePlannedUnfreeze(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded || ended.Active || ended.EndsAt == nil || ended.PlannedEndsAt == nil || !ended.NeedsRecompute {
		t.Fatalf("expected ended scheduled freeze with planned end preserved, got %+v", ended)
	}
}

func TestStoreCancelsScheduledFreezeBeforeActivation(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "maintenance", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := store.CancelScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled || cancelled.EndsAt == nil || !cancelled.Scheduled {
		t.Fatalf("expected cancelled scheduled freeze, got %+v", cancelled)
	}
}

func TestStoreMarksActiveScheduledFreezeForRecomputeWhenManuallyClosed(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	scheduled, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "manual lift later", StartsAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(time.Hour) }
	activated, err := store.ActivateScheduled(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkScheduledRecomputed(ctx, activated.ID); err != nil {
		t.Fatal(err)
	}

	ended, err := store.End(ctx, scheduled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ended.Scheduled || !ended.NeedsRecompute || ended.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected manually ended scheduled freeze to need recompute, got %+v", ended)
	}
}

func TestStoreRejectsInvalidScheduledFreezeParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	startsAt := now.Add(time.Hour)
	plannedEndsAt := now.Add(30 * time.Minute)

	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: now}); !IsValidationError(err) {
		t.Fatalf("expected past start validation error, got %v", err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "release", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt}); !IsValidationError(err) {
		t.Fatalf("expected invalid planned end validation error, got %v", err)
	}
	if _, err := store.CreateScheduled(ctx, ScheduleParams{RepositoryID: 999, Branch: "main", Reason: "release", StartsAt: startsAt}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
}

func TestStoreEndsActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"})
	if err != nil {
		t.Fatal(err)
	}

	ended, err := store.End(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded || ended.Active || ended.EndsAt == nil {
		t.Fatalf("expected ended inactive freeze with end time, got %+v", ended)
	}
	freezes, err := store.ListActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(freezes) != 0 {
		t.Fatalf("expected no active freezes after ending, got %+v", freezes)
	}
	if _, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "next release"}); err != nil {
		t.Fatalf("expected branch to be free after ending freeze: %v", err)
	}
}

func TestStoreCancelsActiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "mistake"})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := store.Cancel(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled || cancelled.Active || cancelled.EndsAt == nil {
		t.Fatalf("expected cancelled inactive freeze with end time, got %+v", cancelled)
	}
}

func TestStoreRejectsClosingInvalidOrInactiveFreeze(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	created, err := store.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(ctx, 0); !IsValidationError(err) {
		t.Fatalf("expected missing freeze validation error, got %v", err)
	}
	if _, err := store.End(ctx, 999); !IsValidationError(err) {
		t.Fatalf("expected missing freeze validation error, got %v", err)
	}
	if _, err := store.End(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cancel(ctx, created.ID); !IsValidationError(err) {
		t.Fatalf("expected inactive freeze validation error, got %v", err)
	}
}

func TestServiceCreatesFreezeAndAuditEventAtomically(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)

	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	event := events[0]
	if event.Action != audit.ActionBranchFreezeCreated || event.SubjectType != audit.SubjectTypeBranchFreeze || event.SubjectID != "1" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" || details["branch"] != created.Branch || details["reason"] != created.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
	}
}

func TestServiceEndsFreezeAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	ended, err := service.End(ctx, created.ID, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if ended.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected ended freeze, got %+v", ended)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionBranchFreezeEnded, ended)
}

func TestServiceCancelsFreezeAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "mistake"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := service.Cancel(ctx, created.ID, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.BranchFreezeStatusCancelled {
		t.Fatalf("expected cancelled freeze, got %+v", cancelled)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionBranchFreezeCancelled, cancelled)
}

func TestServiceScheduledFreezeLifecycleRecordsAuditEvents(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	startsAt := time.Now().UTC().Add(time.Hour)
	plannedEndsAt := startsAt.Add(time.Hour)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	scheduled, err := service.CreateScheduled(ctx, ScheduleParams{RepositoryID: repo.ID, Branch: "main", Reason: "weekend", StartsAt: startsAt, PlannedEndsAt: &plannedEndsAt}, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionFreezeScheduleCreated, scheduled)

	cancelled, err := service.CancelScheduled(ctx, scheduled.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	assertLatestFreezeAudit(t, ctx, database, audit.ActionFreezeScheduleCancelled, cancelled)
}

func TestServiceRollsBackEndWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	created, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	missingUserID := int64(999)

	_, err = service.End(ctx, created.ID, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	freeze, getErr := NewStore(database).Get(ctx, created.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if freeze.Status != domain.BranchFreezeStatusActive || !freeze.Active || freeze.EndsAt != nil {
		t.Fatalf("expected rollback to leave freeze active, got %+v", freeze)
	}
}

func TestServiceRollsBackFreezeWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)
	missingUserID := int64(999)

	_, err := service.CreateActive(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release window"}, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"})
	if err == nil {
		t.Fatal("expected audit foreign-key error")
	}

	freezes, listErr := service.ListActive(ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(freezes) != 0 {
		t.Fatalf("expected rollback to leave no freezes, got %d", len(freezes))
	}
}

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func assertLatestFreezeAudit(t *testing.T, ctx context.Context, database *sql.DB, action string, freeze domain.BranchFreeze) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	event := events[0]
	if event.Action != action || event.SubjectType != audit.SubjectTypeBranchFreeze || event.SubjectID != strconv.FormatInt(freeze.ID, 10) {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["actor_kind"] != domain.ActorKindBootstrapAdmin || details["actor_role"] != "admin" || details["repository_id"] != strconv.FormatInt(freeze.RepositoryID, 10) || details["branch"] != freeze.Branch || details["status"] != string(freeze.Status) || details["reason"] != freeze.Reason {
		t.Fatalf("unexpected audit details: %s", event.DetailsJSON)
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
