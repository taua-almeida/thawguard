package app

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

func newRecomputeTestRepository(id int64, state domain.EnforcementState) domain.Repository {
	return domain.Repository{ID: id, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main", HasStatusToken: true, Active: true, EnforcementState: state}
}

func TestFreezeRecomputingStoreSyncsThenPublishesPRHeadsOnCreate(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	pulls := &fakeOpenPullRequestBranchLister{}
	// The branch cache is empty until the syncer runs, proving forge sync
	// happens before status recomputation.
	syncer := &fakeRecomputeSyncer{onSync: func() {
		pulls.prs = []domain.PullRequest{
			{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"},
			{RepositoryID: 7, Index: 2, State: "open", TargetBranch: "main", HeadSHA: "aaa111"},
			{RepositoryID: 7, Index: 3, State: "open", TargetBranch: "main", HeadSHA: "bbb222"},
		}
	}}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, pulls, statuses, publisher)

	created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != freezes.created.ID {
		t.Fatalf("unexpected created freeze %+v", created)
	}
	if len(syncer.calls) != 1 || syncer.calls[0].repositoryID != 7 || syncer.calls[0].targetBranch != "" {
		t.Fatalf("expected one repository-wide sync before recompute, got %+v", syncer.calls)
	}
	if len(statuses.calls) != 2 {
		t.Fatalf("expected one recompute per synced head, got %+v", statuses.calls)
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

func TestFreezeRecomputingStoreRejectsCreateWithoutActiveEnforcement(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main"}}
	syncer := &fakeRecomputeSyncer{}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementSetupIncomplete)}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, &fakeOpenPullRequestBranchLister{}, statuses, publisher)

	_, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !freeze.IsValidationError(err) {
		t.Fatalf("expected enforcement validation error, got %v", err)
	}
	if err.Error() != domain.EnforcementNotActiveMessage {
		t.Fatalf("expected shared enforcement message, got %q", err.Error())
	}
	if freezes.createCalls != 0 {
		t.Fatalf("expected no freeze mutation for inactive repository, got %d", freezes.createCalls)
	}
	if len(syncer.calls) != 0 || len(statuses.calls) != 0 || len(publisher.results) != 0 {
		t.Fatalf("expected no sync/recompute/publish for rejected freeze, sync=%+v statuses=%+v publish=%+v", syncer.calls, statuses.calls, publisher.results)
	}
}

func TestFreezeRecomputingStoreClosesWithoutPublishingForInactiveRepository(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{closed: domain.BranchFreeze{ID: 9, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusEnded}}
	syncer := &fakeRecomputeSyncer{}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementSetupIncomplete)}
	pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 4, State: "open", TargetBranch: "main", HeadSHA: "ccc333"}}}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, pulls, statuses, publisher)

	closed, err := store.End(ctx, 9, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != domain.BranchFreezeStatusEnded {
		t.Fatalf("expected freeze cleanup to stay possible, got %+v", closed)
	}
	if len(syncer.calls) != 0 || len(statuses.calls) != 0 || len(publisher.results) != 0 {
		t.Fatalf("expected no sync/recompute/publish for inactive repository, sync=%+v statuses=%+v publish=%+v", syncer.calls, statuses.calls, publisher.results)
	}
}

func TestFreezeRecomputingStorePublishesPRHeadsOnEndAndCancel(t *testing.T) {
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
			syncer := &fakeRecomputeSyncer{}
			statuses := &fakeSharedHeadStatusRunner{}
			publisher := &fakeStatusPublisher{}
			repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}
			store := newFreezeRecomputingStore(freezes, repositories, syncer, pulls, statuses, publisher)

			closed, err := test.close(ctx, store)
			if err != nil {
				t.Fatal(err)
			}
			if closed.Status != test.status {
				t.Fatalf("unexpected close status %+v", closed)
			}
			if len(syncer.calls) != 1 {
				t.Fatalf("expected forge sync before close recompute, got %+v", syncer.calls)
			}
			if len(statuses.calls) != 1 || len(publisher.results) != 1 || publisher.results[0].HeadSHA != "ccc333" {
				t.Fatalf("expected one recompute/publish for close, calls=%+v results=%+v", statuses.calls, publisher.results)
			}
		})
	}
}

func TestFreezeRecomputingStoreMissingTokenFailsSyncClosedWithoutStalePublication(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}}}
	syncer := &fakeRecomputeSyncer{err: ErrOpenPullRequestSyncStatusTokenMissing}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repo := newRecomputeTestRepository(7, domain.EnforcementActive)
	repo.HasStatusToken = false
	repositories := &fakeOpenPRRepositoryGetter{repo: repo}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, pulls, statuses, publisher)

	_, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !errors.Is(err, ErrOpenPullRequestSyncStatusTokenMissing) {
		t.Fatalf("expected missing-token sync failure to fail closed, got %v", err)
	}
	if len(syncer.calls) != 1 {
		t.Fatalf("expected an active repository to always attempt sync, got %+v", syncer.calls)
	}
	if len(statuses.calls) != 0 || len(publisher.results) != 0 {
		t.Fatalf("expected no stale recompute/publish after sync failure, calls=%+v results=%+v", statuses.calls, publisher.results)
	}
}

func TestFreezeRecomputingStoreFailsClosedWhenSyncFails(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}}}
	syncErr := errors.New("forge unavailable")
	syncer := &fakeRecomputeSyncer{err: syncErr}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, pulls, statuses, publisher)

	if _, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); !errors.Is(err, syncErr) {
		t.Fatalf("expected sync failure to fail closed, got %v", err)
	}
	if len(statuses.calls) != 0 || len(publisher.results) != 0 {
		t.Fatalf("expected no recompute/publish from stale cache after sync failure, calls=%+v results=%+v", statuses.calls, publisher.results)
	}
}

func TestFreezeRecomputingStoreSkipsWhenNoCachedPRs(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{created: domain.BranchFreeze{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true}}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}
	store := newFreezeRecomputingStore(freezes, repositories, &fakeRecomputeSyncer{}, &fakeOpenPullRequestBranchLister{}, statuses, publisher)

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
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}
	store := newFreezeRecomputingStore(freezes, repositories, &fakeRecomputeSyncer{}, pulls, statuses, publisher)

	created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !errors.Is(err, publishErr) {
		t.Fatalf("expected publish error, got %v", err)
	}
	if created.ID != freezes.created.ID {
		t.Fatalf("expected freeze returned with recompute error, got %+v", created)
	}
}

type fakeFreezeOperations struct {
	created     domain.BranchFreeze
	closed      domain.BranchFreeze
	createCalls int
}

func (f *fakeFreezeOperations) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	return nil, nil
}

func (f *fakeFreezeOperations) CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	f.createCalls++
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

type fakeRecomputeSyncer struct {
	calls  []fakeRecomputeSyncCall
	err    error
	onSync func()
}

type fakeRecomputeSyncCall struct {
	repositoryID int64
	targetBranch string
}

func (s *fakeRecomputeSyncer) SyncOpenPullRequests(ctx context.Context, repositoryID int64, targetBranch string) error {
	s.calls = append(s.calls, fakeRecomputeSyncCall{repositoryID: repositoryID, targetBranch: targetBranch})
	if s.err != nil {
		return s.err
	}
	if s.onSync != nil {
		s.onSync()
	}
	return nil
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

func TestFreezeRecomputingStoreRejectsCreateForUnmanagedBranch(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeFreezeOperations{}
	syncer := &fakeRecomputeSyncer{}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive), unmanagedBranches: map[string]bool{"release/2.0": true}}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, &fakeOpenPullRequestBranchLister{}, statuses, publisher)

	_, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "release/2.0", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !freeze.IsValidationError(err) || err.Error() != domain.BranchNotManagedMessage {
		t.Fatalf("expected managed branch validation error, got %v", err)
	}
	if freezes.createCalls != 0 {
		t.Fatalf("expected no freeze mutation for unmanaged branch, got %d", freezes.createCalls)
	}
	if len(syncer.calls) != 0 || len(statuses.calls) != 0 || len(publisher.results) != 0 {
		t.Fatalf("expected no sync/recompute/publish for rejected freeze, sync=%+v statuses=%+v publish=%+v", syncer.calls, statuses.calls, publisher.results)
	}

	if _, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: 7, Branch: "main", Reason: "release freeze"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatalf("expected managed branch freeze to proceed, got %v", err)
	}
	if freezes.createCalls != 1 {
		t.Fatalf("expected managed branch freeze mutation, got %d", freezes.createCalls)
	}
}

func TestFreezeRecomputingStoreRejectsScheduledCreateForUnmanagedBranch(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeScheduledFreezeOperations{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive), unmanagedBranches: map[string]bool{"release/2.0": true}}
	store := newFreezeRecomputingStore(freezes, repositories, &fakeRecomputeSyncer{}, &fakeOpenPullRequestBranchLister{}, &fakeSharedHeadStatusRunner{}, &fakeStatusPublisher{})

	_, err := store.CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: 7, Branch: "release/2.0", Reason: "window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !freeze.IsValidationError(err) || err.Error() != domain.BranchNotManagedMessage {
		t.Fatalf("expected managed branch validation error, got %v", err)
	}
	if freezes.scheduleCalls != 0 {
		t.Fatalf("expected no schedule mutation for unmanaged branch, got %d", freezes.scheduleCalls)
	}

	if _, err := store.CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: 7, Branch: "main", Reason: "window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}); err != nil {
		t.Fatalf("expected managed branch schedule to proceed, got %v", err)
	}
	if freezes.scheduleCalls != 1 {
		t.Fatalf("expected managed branch schedule mutation, got %d", freezes.scheduleCalls)
	}
}
