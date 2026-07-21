package statusresult

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

func TestStoreCreatesAndListsStatusResults(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	created, err := store.Create(ctx, CreateParams{
		RepositoryID:     repo.ID,
		PullRequestIndex: 42,
		TargetBranch:     " main ",
		HeadSHA:          " ABC123 ",
		Context:          domain.RequiredStatusContext,
		State:            domain.CommitStatusSuccess,
		Description:      "No active freeze applies to this PR",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected status result id")
	}
	if created.TargetBranch != "main" || created.HeadSHA != "abc123" || created.PullRequestIndex != 42 || created.State != domain.CommitStatusSuccess {
		t.Fatalf("unexpected status result: %+v", created)
	}

	results, err := store.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != created.ID {
		t.Fatalf("expected created result in recent list, got %+v", results)
	}
}

func TestStoreListsDecisionsPage(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createTestRepository(t, ctx, database)
	repoB, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "frost-api", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(database)

	seed := []struct {
		repositoryID int64
		state        domain.CommitStatusState
	}{
		{repoA.ID, domain.CommitStatusSuccess},
		{repoA.ID, domain.CommitStatusFailure},
		{repoA.ID, domain.CommitStatusPending},
		{repoA.ID, domain.CommitStatusSuccess},
		{repoB.ID, domain.CommitStatusError},
		{repoB.ID, domain.CommitStatusSuccess},
	}
	ids := make([]int64, 0, len(seed))
	for i, params := range seed {
		created, err := store.Create(ctx, CreateParams{
			RepositoryID:     params.repositoryID,
			PullRequestIndex: 100 + i,
			TargetBranch:     "main",
			HeadSHA:          "abc123",
			Context:          domain.RequiredStatusContext,
			State:            params.state,
			Description:      "seeded decision",
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}

	assertPage := func(t *testing.T, state domain.CommitStatusState, repositoryID int64, offset, limit int, wantTotal int, wantIDs []int64) {
		t.Helper()
		rows, total, err := store.ListDecisionsPage(ctx, state, repositoryID, offset, limit)
		if err != nil {
			t.Fatal(err)
		}
		if total != wantTotal {
			t.Fatalf("expected total %d, got %d", wantTotal, total)
		}
		if len(rows) != len(wantIDs) {
			t.Fatalf("expected %d rows, got %+v", len(wantIDs), rows)
		}
		for i, row := range rows {
			if row.ID != wantIDs[i] {
				t.Fatalf("row %d: expected id %d, got %d", i, wantIDs[i], row.ID)
			}
		}
	}

	assertPage(t, "", 0, 0, 4, 6, []int64{ids[5], ids[4], ids[3], ids[2]})
	assertPage(t, "", 0, 4, 4, 6, []int64{ids[1], ids[0]})
	assertPage(t, domain.CommitStatusSuccess, 0, 0, 10, 3, []int64{ids[5], ids[3], ids[0]})
	assertPage(t, "", repoB.ID, 0, 10, 2, []int64{ids[5], ids[4]})
	assertPage(t, domain.CommitStatusSuccess, repoA.ID, 0, 10, 2, []int64{ids[3], ids[0]})
	assertPage(t, domain.CommitStatusSuccess, repoB.ID, 0, 10, 1, []int64{ids[5]})
	assertPage(t, domain.CommitStatusPending, repoB.ID, 0, 10, 0, nil)
	assertPage(t, "", 0, 10, 4, 6, nil)
	assertPage(t, "", 0, 0, 0, 6, []int64{ids[5], ids[4], ids[3], ids[2], ids[1], ids[0]})
	assertPage(t, "", 0, -3, 4, 6, []int64{ids[5], ids[4], ids[3], ids[2]})

	rows, _, err := store.ListDecisionsPage(ctx, domain.CommitStatusError, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].RepositoryID != repoB.ID || rows[0].Description != "seeded decision" || rows[0].State != domain.CommitStatusError {
		t.Fatalf("expected hydrated error row, got %+v", rows)
	}
}

func TestStoreRejectsInvalidStatusResultParams(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	if _, err := store.Create(ctx, CreateParams{PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, TargetBranch: "main", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing pull request validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing target branch validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "main", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing head SHA validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: "invalid", Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid state validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: 999, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "ma\nin", HeadSHA: "abc", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid target branch validation error, got %v", err)
	}
	if _, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, PullRequestIndex: 1, TargetBranch: "main", HeadSHA: "not-a-sha", Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "ok"}); !IsValidationError(err) {
		t.Fatalf("expected invalid head SHA validation error, got %v", err)
	}
}

func TestServiceRunLocalBlocksFrozenBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(NewStore(database), freezeService)

	result, err := service.RunLocal(ctx, LocalDecisionParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.Context != domain.RequiredStatusContext {
		t.Fatalf("expected failure decision for frozen branch, got %+v", result)
	}
	if result.Description != "Branch is frozen; merge is blocked by Thawguard: release" {
		t.Fatalf("unexpected description: %q", result.Description)
	}
}

func TestServiceRunLocalAllowsUnfrozenBranch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(NewStore(database), freeze.NewService(database))

	result, err := service.RunLocal(ctx, LocalDecisionParams{RepositoryID: repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusSuccess {
		t.Fatalf("expected success decision for unfrozen branch, got %+v", result)
	}
}

func TestServiceRunForPullRequestPersistsDecision(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(NewStore(database), freezeService)

	result, err := service.RunForPullRequest(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "ABC123"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.TargetBranch != "main" || result.HeadSHA != "abc123" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestServiceRunForPullRequestAllowsApprovedThaw(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	cached, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	thawStore := thawexception.NewStore(database)
	if _, err := thawStore.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: cached.Index, TargetBranch: cached.TargetBranch, HeadSHA: cached.HeadSHA, Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithThawExceptions(NewStore(database), freezeService, thawStore, prStore)

	result, err := service.RunForPullRequest(ctx, cached)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusSuccess || result.Description != "PR is explicitly thawed during an active freeze" {
		t.Fatalf("expected approved thaw success, got %+v", result)
	}
}

func TestServiceRunForPullRequestBlocksChangedHeadAfterThaw(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	cached, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	thawStore := thawexception.NewStore(database)
	if _, err := thawStore.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: cached.Index, TargetBranch: cached.TargetBranch, HeadSHA: cached.HeadSHA, Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithThawExceptions(NewStore(database), freezeService, thawStore, prStore)

	result, err := service.RunForPullRequest(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "def456"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.Description != "Branch is frozen; merge is blocked by Thawguard: release" {
		t.Fatalf("expected changed head to ignore stale thaw, got %+v", result)
	}
}

func TestServiceRunForSharedHeadFailsIfAnyOpenPullRequestIsFrozen(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "release", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(NewStore(database), freezeService)

	result, err := service.RunForSharedHead(ctx, []domain.PullRequest{
		{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"},
		{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "release", HeadSHA: "abc123"},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.PullRequestIndex != 2 || result.TargetBranch != "release" {
		t.Fatalf("expected shared-head failure on frozen PR, got %+v", result)
	}
}

func TestServiceRunForSharedHeadBlocksApprovedThawWithDuplicateOpenHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	pr1, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	pr2, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	thawStore := thawexception.NewStore(database)
	if _, err := thawStore.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: pr1.Index, TargetBranch: pr1.TargetBranch, HeadSHA: pr1.HeadSHA, Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithThawExceptions(NewStore(database), freezeService, thawStore, prStore)

	result, err := service.RunForSharedHead(ctx, []domain.PullRequest{pr1, pr2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure || result.PullRequestIndex != 1 || result.Description != "Thaw blocked because another open PR shares this head SHA" {
		t.Fatalf("expected duplicate head to block thaw, got %+v", result)
	}
}

func TestServiceRunForSharedHeadAllowsExplicitlyApprovedFrozenPullRequests(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	pr1, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	pr2, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	thawStore := thawexception.NewStore(database)
	for _, pr := range []domain.PullRequest{pr1, pr2} {
		if _, err := thawStore.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: pr.Index, TargetBranch: pr.TargetBranch, HeadSHA: pr.HeadSHA, Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	service := NewServiceWithThawExceptions(NewStore(database), freezeService, thawStore, prStore)

	result, err := service.RunForSharedHead(ctx, []domain.PullRequest{pr1, pr2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusSuccess || result.HeadSHA != "abc123" {
		t.Fatalf("expected shared-head thaw success, got %+v", result)
	}
}

func TestServiceRunForSharedHeadExpandsToOtherFrozenBranchesSharingSHA(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	for _, branch := range []string{"main", "release"} {
		if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: branch, Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	prStore := pullrequest.NewStore(database)
	pr1, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	pr2, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "release", HeadSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	thawStore := thawexception.NewStore(database)
	if _, err := thawStore.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: pr1.Index, TargetBranch: pr1.TargetBranch, HeadSHA: pr1.HeadSHA, Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithThawExceptions(NewStore(database), freezeService, thawStore, prStore)

	result, err := service.RunForSharedHead(ctx, []domain.PullRequest{pr1}, pr1.Index)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusFailure {
		t.Fatalf("expected shared SHA on another frozen branch to keep the status failing, got %+v", result)
	}

	if _, err := thawStore.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: pr2.Index, TargetBranch: pr2.TargetBranch, HeadSHA: pr2.HeadSHA, Reason: "production fix"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	result, err = service.RunForSharedHead(ctx, []domain.PullRequest{pr1}, pr1.Index)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.CommitStatusSuccess || result.HeadSHA != "abc123" {
		t.Fatalf("expected success only after every affected frozen PR is thawed, got %+v", result)
	}
}

func TestServiceRunForSharedHeadRejectsClosedPullRequest(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(NewStore(database), freeze.NewService(database))

	_, err := service.RunForSharedHead(ctx, []domain.PullRequest{{RepositoryID: repo.ID, Index: 1, State: "closed", TargetBranch: "main", HeadSHA: "abc123"}}, 1)
	if !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestServiceRunLocalRejectsMissingFields(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewService(NewStore(database), freeze.NewService(database))

	if _, err := service.RunLocal(ctx, LocalDecisionParams{}); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func createTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err = repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
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
