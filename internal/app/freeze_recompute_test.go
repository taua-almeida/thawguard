package app

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

func TestFreezeRecomputingStorePublishesCachedPRHeadsOnCreate(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{
		{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"},
		{RepositoryID: 7, Index: 2, State: "open", TargetBranch: "main", HeadSHA: "aaa111"},
		{RepositoryID: 7, Index: 3, State: "open", TargetBranch: "main", HeadSHA: "bbb222"},
	}}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	store := newFreezeRecomputingStore(freezes, pulls, statuses, publisher)

	created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != freezes.created.ID {
		t.Fatalf("unexpected created freeze %+v", created)
	}
	if len(statuses.calls) != 2 {
		t.Fatalf("expected one recompute per cached head, got %+v", statuses.calls)
	}
	if len(statuses.calls[0].prs) != 2 || statuses.calls[0].preferredIndex != 1 {
		t.Fatalf("expected shared head to recompute together, got %+v", statuses.calls[0])
	}
	if len(statuses.calls[1].prs) != 1 || statuses.calls[1].preferredIndex != 3 {
		t.Fatalf("expected second head recompute, got %+v", statuses.calls[1])
	}
	if len(publisher.results) != 2 || publisher.results[0].HeadSHA != "aaa111" || publisher.results[1].HeadSHA != "bbb222" {
		t.Fatalf("expected published status results for each head, got %+v", publisher.results)
	}
}

func TestDryRunFreezeLifecycleRecomputesOfflineWithoutLiveAllowlistOrToken(t *testing.T) {
	ctx := context.Background()
	database := newAppTestDB(t, ctx)
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	pullRequests := pullrequest.NewStore(database)
	if _, err := pullRequests.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "abc123"}); err != nil {
		t.Fatal(err)
	}
	freezes := freeze.NewService(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freezes, thawexception.NewService(database), pullRequests)
	publications := statuspublication.NewStore(database)
	publisher, err := statusPublisherFromConfig(config.Config{}, statuspublication.AttemptModeDryRun, publications, repository.NewStore(database), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := newFreezeRecomputingStore(freezes, pullRequests, statuses, publisher)

	created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release freeze"}, admin)
	if err != nil {
		t.Fatalf("expected dry-run freeze create to recompute offline without allowlist or token, got %v", err)
	}
	if _, err := store.End(ctx, created.ID, admin); err != nil {
		t.Fatalf("expected dry-run freeze end to recompute offline without allowlist or token, got %v", err)
	}
	attempts, err := publications.ListRecentAttempts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected one cached recompute publication per freeze action, got %+v", attempts)
	}
	for _, attempt := range attempts {
		if attempt.Mode != statuspublication.AttemptModeDryRun || attempt.Error != "" {
			t.Fatalf("expected offline dry-run publication attempts, got %+v", attempt)
		}
	}
}

func TestFreezeRecomputingStorePublishesCachedPRHeadsOnEndAndCancel(t *testing.T) {
	for _, test := range []struct {
		name   string
		close  func(context.Context, *freezeRecomputingStore) (domain.BranchFreeze, error)
		status domain.BranchFreezeStatus
	}{
		{name: "end", status: domain.BranchFreezeStatusEnded, close: func(ctx context.Context, store *freezeRecomputingStore) (domain.BranchFreeze, error) {
			return store.End(ctx, 9, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
		}},
		{name: "cancel", status: domain.BranchFreezeStatusCancelled, close: func(ctx context.Context, store *freezeRecomputingStore) (domain.BranchFreeze, error) {
			return store.Cancel(ctx, 9, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			freezes := &fakeFreezeOperations{closed: domain.BranchFreeze{ID: 9, RepositoryID: 7, Branch: "main", Status: test.status}}
			pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 4, State: "open", TargetBranch: "main", HeadSHA: "ccc333"}}}
			statuses := &fakeSharedHeadStatusRunner{}
			publisher := &fakeStatusPublisher{}
			store := newFreezeRecomputingStore(freezes, pulls, statuses, publisher)

			closed, err := test.close(ctx, store)
			if err != nil {
				t.Fatal(err)
			}
			if closed.Status != test.status {
				t.Fatalf("unexpected close status %+v", closed)
			}
			if len(statuses.calls) != 1 || len(publisher.results) != 1 || publisher.results[0].HeadSHA != "ccc333" {
				t.Fatalf("expected one recompute/publish for close, calls=%+v results=%+v", statuses.calls, publisher.results)
			}
		})
	}
}

func TestFreezeRecomputingStoreSkipsWhenNoCachedPRs(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	store := newFreezeRecomputingStore(freezes, &fakeOpenPullRequestBranchLister{}, statuses, publisher)

	if _, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if len(statuses.calls) != 0 || len(publisher.results) != 0 {
		t.Fatalf("expected no recompute without cached PRs, calls=%+v results=%+v", statuses.calls, publisher.results)
	}
}

func TestFreezeRecomputingStoreReturnsPublishErrorAfterFreezeChange(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}}}
	statuses := &fakeSharedHeadStatusRunner{}
	publishErr := errors.New("publisher failed")
	publisher := &fakeStatusPublisher{err: publishErr}
	store := newFreezeRecomputingStore(freezes, pulls, statuses, publisher)

	created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !errors.Is(err, publishErr) {
		t.Fatalf("expected publish error, got %v", err)
	}
	if created.ID != freezes.created.ID {
		t.Fatalf("expected freeze returned with recompute error, got %+v", created)
	}
}

type fakeFreezeOperations struct {
	created domain.BranchFreeze
	closed  domain.BranchFreeze
}

func (f *fakeFreezeOperations) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	return nil, nil
}

func (f *fakeFreezeOperations) CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	return f.created, nil
}

func (f *fakeFreezeOperations) End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return f.closed, nil
}

func (f *fakeFreezeOperations) Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return f.closed, nil
}

type fakeOpenPullRequestBranchLister struct {
	prs []domain.PullRequest
}

func (l *fakeOpenPullRequestBranchLister) ListOpenByTargetBranch(ctx context.Context, repositoryID int64, targetBranch string) ([]domain.PullRequest, error) {
	return l.prs, nil
}

type fakeSharedHeadStatusRunner struct {
	calls []fakeSharedHeadStatusCall
}

type fakeSharedHeadStatusCall struct {
	prs            []domain.PullRequest
	preferredIndex int
}

func (r *fakeSharedHeadStatusRunner) RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error) {
	copyPRs := append([]domain.PullRequest(nil), prs...)
	r.calls = append(r.calls, fakeSharedHeadStatusCall{prs: copyPRs, preferredIndex: preferredIndex})
	selected := copyPRs[0]
	return statusresult.Result{ID: int64(len(r.calls)), RepositoryID: selected.RepositoryID, PullRequestIndex: selected.Index, TargetBranch: selected.TargetBranch, HeadSHA: selected.HeadSHA, Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess, Description: "No active freeze applies to this PR"}, nil
}

type fakeStatusPublisher struct {
	results []statusresult.Result
	err     error
}

func (p *fakeStatusPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	p.results = append(p.results, result)
	if p.err != nil {
		return statuspublication.Publication{}, p.err
	}
	return statuspublication.Publication{ID: int64(len(p.results)), StatusResultID: result.ID, RepositoryID: result.RepositoryID, PullRequestIndex: result.PullRequestIndex, TargetBranch: result.TargetBranch, HeadSHA: result.HeadSHA, Context: result.Context, State: result.State, Description: result.Description}, nil
}
