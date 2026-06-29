package webhook

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

func TestParsePullRequestEvent(t *testing.T) {
	body := readFixture(t, "codeberg_pull_request_opened.json")

	event, err := ParsePullRequestEvent(body)
	if err != nil {
		t.Fatal(err)
	}

	if event.Action != "opened" || event.Forge != "forgejo" || event.BaseURL != "https://codeberg.org" {
		t.Fatalf("unexpected repository event fields: %+v", event)
	}
	if event.Owner != "example-owner" || event.RepositoryName != "example-repo" {
		t.Fatalf("unexpected repository identity: %+v", event)
	}
	if event.PullRequest.Index != 42 || event.PullRequest.TargetBranch != "main" || event.PullRequest.HeadSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("unexpected pull request: %+v", event.PullRequest)
	}
}

func TestPullRequestProcessorCachesAndRecomputesLocalDecision(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	statusStore := statusresult.NewStore(database)
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusStore, freezeService))

	processed, err := processor.Process(ctx, readFixture(t, "codeberg_pull_request_opened.json"))
	if err != nil {
		t.Fatal(err)
	}
	if processed.Repository.ID != repo.ID {
		t.Fatalf("expected repository %d, got %d", repo.ID, processed.Repository.ID)
	}
	if processed.PullRequest.RepositoryID != repo.ID || processed.PullRequest.Index != 42 {
		t.Fatalf("unexpected cached pull request: %+v", processed.PullRequest)
	}
	if !processed.Recomputed || len(processed.StatusResults) != 1 {
		t.Fatalf("expected status recomputation, got %+v", processed)
	}
	if processed.StatusResults[0].State != domain.CommitStatusFailure || processed.StatusResults[0].Description != "Branch is frozen; merge is blocked by Thawguard" {
		t.Fatalf("unexpected status result: %+v", processed.StatusResults[0])
	}

	cached, err := prStore.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if cached.TargetBranch != "main" || cached.HeadSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("unexpected cached PR: %+v", cached)
	}
	recent, err := statusStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].PullRequestIndex != 42 || recent[0].State != domain.CommitStatusFailure {
		t.Fatalf("expected persisted status result, got %+v", recent)
	}
}

func TestPullRequestProcessorFailsClosedOverSharedHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "release", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	if _, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 7, State: "open", TargetBranch: "release", HeadSHA: "0123456789abcdef0123456789abcdef01234567"}); err != nil {
		t.Fatal(err)
	}
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freezeService))

	processed, err := processor.Process(ctx, readFixture(t, "codeberg_pull_request_opened.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !processed.Recomputed || len(processed.StatusResults) != 1 {
		t.Fatalf("expected status recomputation, got %+v", processed)
	}
	if processed.StatusResults[0].State != domain.CommitStatusFailure || processed.StatusResults[0].PullRequestIndex != 7 || processed.StatusResults[0].TargetBranch != "release" {
		t.Fatalf("expected shared-head failure for frozen PR, got %+v", processed.StatusResults[0])
	}
}

func TestPullRequestProcessorRecomputesOldHeadWhenPullRequestMoves(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "release", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	for _, pr := range []domain.PullRequest{
		{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "release", HeadSHA: "aaaaaa"},
		{RepositoryID: repo.ID, Index: 2, State: "open", TargetBranch: "main", HeadSHA: "aaaaaa"},
	} {
		if _, err := prStore.Upsert(ctx, pr); err != nil {
			t.Fatal(err)
		}
	}
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freezeService))

	processed, err := processor.Process(ctx, []byte(synchronizedPullRequestPayload))
	if err != nil {
		t.Fatal(err)
	}
	if !processed.Recomputed || len(processed.StatusResults) != 2 {
		t.Fatalf("expected current and old head recomputation, got %+v", processed)
	}
	newHead := processed.StatusResults[0]
	oldHead := processed.StatusResults[1]
	if newHead.HeadSHA != "bbbbbb" || newHead.State != domain.CommitStatusFailure || newHead.PullRequestIndex != 1 {
		t.Fatalf("expected failure for moved frozen PR new head, got %+v", newHead)
	}
	if oldHead.HeadSHA != "aaaaaa" || oldHead.State != domain.CommitStatusSuccess || oldHead.PullRequestIndex != 2 {
		t.Fatalf("expected success recomputation for old head remaining PR, got %+v", oldHead)
	}
}

func TestPullRequestProcessorCachesClosedEventWithoutStatusResultWhenNoOpenPRsShareHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freeze.NewService(database)))

	processed, err := processor.Process(ctx, []byte(closedPullRequestPayload))
	if err != nil {
		t.Fatal(err)
	}
	if processed.Recomputed || len(processed.StatusResults) != 0 {
		t.Fatalf("expected no status recomputation for closed-only head, got %+v", processed)
	}
	cached, err := prStore.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if cached.State != "closed" {
		t.Fatalf("expected closed PR cache state, got %+v", cached)
	}
}

func TestPullRequestProcessorRejectsUnknownRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	processor := NewPullRequestProcessor(repository.NewStore(database), pullrequest.NewStore(database), statusresult.NewService(statusresult.NewStore(database), freeze.NewService(database)))

	_, err := processor.Process(ctx, readFixture(t, "codeberg_pull_request_opened.json"))
	if !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(projectRoot(t), "testdata", "webhooks", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func newTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	migrations, err := db.LoadMigrations(filepath.Join(projectRoot(t), "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return database
}

func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

const closedPullRequestPayload = `{
  "action": "closed",
  "repository": {
    "owner": { "login": "example-owner" },
    "name": "example-repo",
    "full_name": "example-owner/example-repo",
    "clone_url": "https://codeberg.org/example-owner/example-repo.git"
  },
  "pull_request": {
    "number": 42,
    "title": "Example bug fix",
    "state": "closed",
    "html_url": "https://codeberg.org/example-owner/example-repo/pulls/42",
    "base": { "ref": "main" },
    "head": { "sha": "0123456789abcdef0123456789abcdef01234567" }
  }
}`

const synchronizedPullRequestPayload = `{
  "action": "synchronized",
  "repository": {
    "owner": { "login": "example-owner" },
    "name": "example-repo",
    "full_name": "example-owner/example-repo",
    "clone_url": "https://codeberg.org/example-owner/example-repo.git"
  },
  "pull_request": {
    "number": 1,
    "title": "Release fix",
    "state": "open",
    "html_url": "https://codeberg.org/example-owner/example-repo/pulls/1",
    "base": { "ref": "release" },
    "head": { "sha": "bbbbbb" }
  }
}`
