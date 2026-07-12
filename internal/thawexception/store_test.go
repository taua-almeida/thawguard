package thawexception

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestStoreApprovesAndFindsActiveExceptionForPullRequest(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	approved, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, PullRequestURL: "https://codeberg.org/taua-almeida/thawguard/pulls/42", TargetBranch: " main ", HeadSHA: " ABC123 ", Reason: " production fix "}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if approved.ID == 0 || approved.RepositoryID != repo.ID || approved.PullRequestIndex != 42 || approved.TargetBranch != "main" || approved.HeadSHA != "abc123" || !approved.Active || approved.Reason != "production fix" {
		t.Fatalf("unexpected approved thaw exception: %+v", approved)
	}

	active, err := store.ActiveForPullRequest(ctx, domain.PullRequest{ID: 99, RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.ID != approved.ID || active.PullRequestID != 99 {
		t.Fatalf("expected active thaw exception for PR, got %+v", active)
	}
}

func TestStoreActiveForPullRequestIgnoresChangedOrExpiredHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)
	expiresAt := time.Now().UTC().Add(-time.Hour)
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix", ExpiresAt: &expiresAt}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	active, err := store.ActiveForPullRequest(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("expected expired exception to be ignored, got %+v", active)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveForPullRequest(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "def456"})
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("expected changed head to miss thaw exception, got %+v", active)
	}
}

func TestStoreRejectsInvalidApproveParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.Approve(ctx, ApproveParams{PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing pull request validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing target branch validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing head SHA validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing reason validation error, got %v", err)
	}
	if _, err := store.Approve(ctx, ApproveParams{RepositoryID: 999, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
}

func TestServiceApprovesAndRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)

	approved, err := service.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if approved.ID == 0 || !approved.Active {
		t.Fatalf("expected approved thaw exception, got %+v", approved)
	}
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one audit event, got %+v", events)
	}
	event := events[0]
	if event.Action != audit.ActionThawExceptionApproved || event.SubjectType != audit.SubjectTypeThawException || event.SubjectID != "1" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["repository_id"] != "1" || details["pull_request_index"] != "42" || details["target_branch"] != "main" || details["head_sha"] != "abc123" || details["reason"] != "production fix" {
		t.Fatalf("unexpected audit details: %+v", details)
	}
}

func TestServiceApprovesSharedHeadAtomicallyAndRecordsExplicitAudit(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)

	approved, err := service.ApproveSharedHead(ctx, ApproveSharedHeadParams{
		RepositoryID:               repo.ID,
		SelectedPullRequestIndex:   42,
		HeadSHA:                    "ABC123",
		Reason:                     " production fix ",
		AffectedPullRequestIndexes: []int{43, 42},
		Exceptions: []ApproveParams{
			{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"},
			{RepositoryID: repo.ID, PullRequestIndex: 43, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"},
		},
	}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 2 || approved[0].PullRequestIndex != 42 || approved[1].PullRequestIndex != 43 {
		t.Fatalf("unexpected shared-head exceptions: %+v", approved)
	}
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != audit.ActionThawExceptionSharedHeadApproved {
		t.Fatalf("expected one explicit shared-head audit event, got %+v", events)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["approval_scope"] != "shared_head" || details["affected_pull_request_indexes"] != "42,43" || details["created_pull_request_indexes"] != "42,43" || details["already_covered_pull_request_indexes"] != "" || details["already_covered_pull_request_count"] != "0" || details["head_sha"] != "abc123" {
		t.Fatalf("unexpected shared-head audit details: %+v", details)
	}
	if _, err := service.ApproveSharedHead(ctx, ApproveSharedHeadParams{
		RepositoryID:               repo.ID,
		SelectedPullRequestIndex:   42,
		HeadSHA:                    "abc123",
		Reason:                     "production fix",
		AffectedPullRequestIndexes: []int{42, 43},
		Exceptions: []ApproveParams{
			{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"},
			{RepositoryID: repo.ID, PullRequestIndex: 43, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"},
		},
	}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	var exceptionCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM thaw_exceptions`).Scan(&exceptionCount); err != nil {
		t.Fatal(err)
	}
	if exceptionCount != 2 {
		t.Fatalf("expected confirmation retry to reuse active exceptions, got %d rows", exceptionCount)
	}
}

func TestServiceSharedHeadApprovalAuditDistinguishesCreatedFromAlreadyCovered(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(database)

	existing, err := service.Approve(ctx, ApproveParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "earlier fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	approved, err := service.ApproveSharedHead(ctx, ApproveSharedHeadParams{
		RepositoryID:               repo.ID,
		SelectedPullRequestIndex:   43,
		HeadSHA:                    "abc123",
		Reason:                     "shared fix",
		AffectedPullRequestIndexes: []int{42, 43},
		Exceptions: []ApproveParams{
			{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "shared fix"},
			{RepositoryID: repo.ID, PullRequestIndex: 43, TargetBranch: "main", HeadSHA: "abc123", Reason: "shared fix"},
		},
	}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 2 {
		t.Fatalf("expected two covering exceptions, got %+v", approved)
	}
	if approved[0].ID != existing.ID || approved[0].Reason != "earlier fix" {
		t.Fatalf("expected the already-active exception to be reused with its original reason, got %+v", approved[0])
	}

	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var sharedEvent *audit.Event
	for i := range events {
		if events[i].Action == audit.ActionThawExceptionSharedHeadApproved {
			sharedEvent = &events[i]
		}
	}
	if sharedEvent == nil {
		t.Fatalf("expected a shared-head audit event, got %+v", events)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(sharedEvent.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["created_pull_request_indexes"] != "43" || details["created_pull_request_count"] != "1" {
		t.Fatalf("expected only PR 43 recorded as newly created, got %+v", details)
	}
	if details["already_covered_pull_request_indexes"] != "42" || details["already_covered_pull_request_count"] != "1" {
		t.Fatalf("expected PR 42 recorded as already covered, got %+v", details)
	}
	if details["approved_pull_request_indexes"] != "" {
		t.Fatalf("expected no ambiguous approved index list, got %+v", details)
	}
	if details["reason"] != "shared fix" {
		t.Fatalf("expected confirmation reason in details, got %+v", details)
	}
}

func TestServiceSharedHeadApprovalRollsBackEveryExceptionOnPersistenceFailure(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	if _, err := database.ExecContext(ctx, `
CREATE TRIGGER fail_second_shared_thaw
BEFORE INSERT ON thaw_exceptions
WHEN NEW.pull_request_index = 43
BEGIN
  SELECT RAISE(ABORT, 'forced shared thaw failure');
END`); err != nil {
		t.Fatal(err)
	}
	service := NewService(database)

	_, err := service.ApproveSharedHead(ctx, ApproveSharedHeadParams{
		RepositoryID:               repo.ID,
		SelectedPullRequestIndex:   42,
		HeadSHA:                    "abc123",
		Reason:                     "production fix",
		AffectedPullRequestIndexes: []int{42, 43},
		Exceptions: []ApproveParams{
			{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"},
			{RepositoryID: repo.ID, PullRequestIndex: 43, TargetBranch: "main", HeadSHA: "abc123", Reason: "production fix"},
		},
	}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err == nil {
		t.Fatal("expected forced shared-head persistence failure")
	}
	var exceptionCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM thaw_exceptions`).Scan(&exceptionCount); err != nil {
		t.Fatal(err)
	}
	if exceptionCount != 0 {
		t.Fatalf("expected all shared-head exceptions to roll back, got %d", exceptionCount)
	}
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("expected shared-head audit to roll back with exceptions, got %+v", events)
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
