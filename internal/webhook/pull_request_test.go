package webhook

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
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
	repo := createEnforcedTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	statusStore := statusresult.NewStore(database)
	publicationStore := statuspublication.NewStore(database)
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusStore, freezeService), recordingTestPublisher{store: publicationStore})

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
	if len(processed.Publications) != 1 || processed.Publications[0].StatusResultID != processed.StatusResults[0].ID || processed.Publications[0].DeliveryMode != statuspublication.DeliveryModeForgejoStatus {
		t.Fatalf("unexpected publications: %+v", processed.Publications)
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
	publications, err := publicationStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 1 || publications[0].StatusResultID != recent[0].ID || publications[0].HeadSHA != recent[0].HeadSHA {
		t.Fatalf("expected persisted publication intent, got %+v", publications)
	}
	attempts, err := publicationStore.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].PublicationID != publications[0].ID || attempts[0].StatusResultID != recent[0].ID || attempts[0].Mode != statuspublication.AttemptModeForgejoStatus || attempts[0].Result != statuspublication.AttemptResultPosted {
		t.Fatalf("expected persisted posted publication attempt, got %+v", attempts)
	}
}

func TestPullRequestProcessorFailsClosedOverSharedHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createEnforcedTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "release", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	if _, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 7, State: "open", TargetBranch: "release", HeadSHA: "0123456789abcdef0123456789abcdef01234567"}); err != nil {
		t.Fatal(err)
	}
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freezeService), recordingTestPublisher{store: statuspublication.NewStore(database)})

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
	repo := createEnforcedTestRepository(t, ctx, database)
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
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freezeService), recordingTestPublisher{store: statuspublication.NewStore(database)})

	processed, err := processor.Process(ctx, []byte(synchronizedPullRequestPayload))
	if err != nil {
		t.Fatal(err)
	}
	if !processed.Recomputed || len(processed.StatusResults) != 2 {
		t.Fatalf("expected current and old head recomputation, got %+v", processed)
	}
	if len(processed.Publications) != 2 {
		t.Fatalf("expected two publication intents, got %+v", processed.Publications)
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

func TestPullRequestProcessorDoesNotOverwriteCacheWhenPublicationFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createEnforcedTestRepository(t, ctx, database)
	freezeService := freeze.NewService(database)
	if _, err := freezeService.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "release", Reason: "release"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	prStore := pullrequest.NewStore(database)
	if _, err := prStore.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "release", HeadSHA: "aaaaaa"}); err != nil {
		t.Fatal(err)
	}
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freezeService), failingPublisher{})

	if _, err := processor.Process(ctx, []byte(synchronizedPullRequestPayload)); err == nil {
		t.Fatal("expected publication failure")
	}
	cached, err := prStore.Get(ctx, repo.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cached.HeadSHA != "aaaaaa" {
		t.Fatalf("expected cache to retain old head for retry, got %+v", cached)
	}
}

func TestPullRequestProcessorCachesClosedEventWithoutStatusResultWhenNoOpenPRsShareHead(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createEnforcedTestRepository(t, ctx, database)
	prStore := pullrequest.NewStore(database)
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusresult.NewStore(database), freeze.NewService(database)), recordingTestPublisher{store: statuspublication.NewStore(database)})

	processed, err := processor.Process(ctx, []byte(closedPullRequestPayload))
	if err != nil {
		t.Fatal(err)
	}
	if processed.Recomputed || len(processed.StatusResults) != 0 {
		t.Fatalf("expected no status recomputation for closed-only head, got %+v", processed)
	}
	if len(processed.Publications) != 0 {
		t.Fatalf("expected no publication intents for closed-only head, got %+v", processed.Publications)
	}
	cached, err := prStore.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if cached.State != "closed" {
		t.Fatalf("expected closed PR cache state, got %+v", cached)
	}
}

func TestPullRequestProcessorCachesWithoutPublishingBeforeEnforcementActivation(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	freezeService := freeze.NewService(database)
	prStore := pullrequest.NewStore(database)
	statusStore := statusresult.NewStore(database)
	publicationStore := statuspublication.NewStore(database)
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusStore, freezeService), recordingTestPublisher{store: publicationStore})

	processed, err := processor.Process(ctx, readFixture(t, "codeberg_pull_request_opened.json"))
	if err != nil {
		t.Fatal(err)
	}
	if processed.Recomputed || len(processed.StatusResults) != 0 || len(processed.Publications) != 0 {
		t.Fatalf("expected no recompute or publication before activation, got %+v", processed)
	}
	cached, err := prStore.Get(ctx, repo.ID, 42)
	if err != nil {
		t.Fatal(err)
	}
	if cached.HeadSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("expected delivery evidence in PR cache, got %+v", cached)
	}
	results, err := statusStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no status results before activation, got %+v", results)
	}
	publications, err := publicationStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 0 {
		t.Fatalf("expected no publication intents before activation, got %+v", publications)
	}
	attempts, err := publicationStore.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected no publication attempts before activation, got %+v", attempts)
	}
}

func TestPullRequestProcessorStopsBeforePublicationWhenClaimIsSuperseded(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createEnforcedTestRepository(t, ctx, database)
	prStore := pullrequest.NewStore(database)
	statusStore := statusresult.NewStore(database)
	publicationStore := statuspublication.NewStore(database)
	convergence := &webhookTestConvergence{current: []bool{true, false}}
	processor := NewPullRequestProcessor(repository.NewStore(database), prStore, statusresult.NewService(statusStore, freeze.NewService(database)), recordingTestPublisher{store: publicationStore})
	processor.SetConvergence(convergence)

	processed, err := processor.Process(ctx, readFixture(t, "codeberg_pull_request_opened.json"))
	if err != nil {
		t.Fatal(err)
	}
	if processed.Recomputed || len(processed.StatusResults) != 0 || len(processed.Publications) != 0 {
		t.Fatalf("superseded webhook claim must report delegated convergence, got %+v", processed)
	}
	if _, err := prStore.Get(ctx, repo.ID, 42); err != nil {
		t.Fatalf("webhook cache should still record current forge state: %v", err)
	}
	publications, err := publicationStore.ListRecent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 0 {
		t.Fatalf("superseded webhook claim must not create publication intent, got %+v", publications)
	}
	if convergence.currentCalls != 2 || convergence.completeCalls != 0 || convergence.failCalls != 0 {
		t.Fatalf("expected newer work to retain ownership, convergence=%+v", convergence)
	}
}

func TestPullRequestProcessorRejectsUnknownRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	processor := NewPullRequestProcessor(repository.NewStore(database), pullrequest.NewStore(database), statusresult.NewService(statusresult.NewStore(database), freeze.NewService(database)), recordingTestPublisher{store: statuspublication.NewStore(database)})

	_, err := processor.Process(ctx, readFixture(t, "codeberg_pull_request_opened.json"))
	if !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func createEnforcedTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	store := repository.NewStore(database)
	repo, err := store.Create(ctx, repository.CreateParams{BaseURL: "https://codeberg.org", Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err = store.SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

// recordingTestPublisher stands in for the live Forgejo publisher: it records
// the intent and a posted attempt without calling a forge.
type recordingTestPublisher struct {
	store *statuspublication.Store
}

func (p recordingTestPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	publication, err := p.store.PublishForgejoStatus(ctx, result)
	if err != nil {
		return statuspublication.Publication{}, err
	}
	if _, err := p.store.RecordForgejoStatusAttempt(ctx, publication, statuspublication.AttemptResultPosted, ""); err != nil {
		return statuspublication.Publication{}, err
	}
	return publication, nil
}

type failingPublisher struct{}

func (failingPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	return statuspublication.Publication{}, errors.New("publication failed")
}

type webhookTestConvergence struct {
	current       []bool
	currentCalls  int
	completeCalls int
	failCalls     int
}

func (c *webhookTestConvergence) Enqueue(context.Context, int64) error { return nil }

func (c *webhookTestConvergence) Claim(context.Context, int64) (jobs.Job, bool, error) {
	return jobs.Job{ID: 1, RepositoryID: 1, Generation: 1}, true, nil
}

func (c *webhookTestConvergence) Current(context.Context, jobs.Job) (bool, error) {
	index := c.currentCalls
	c.currentCalls++
	if index >= len(c.current) {
		return true, nil
	}
	return c.current[index], nil
}

func (c *webhookTestConvergence) Complete(context.Context, jobs.Job) error {
	c.completeCalls++
	return nil
}

func (c *webhookTestConvergence) Fail(context.Context, jobs.Job, string) error {
	c.failCalls++
	return nil
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
