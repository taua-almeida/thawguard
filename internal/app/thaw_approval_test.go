package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

func TestThawApprovalRejectsRepositoryWithoutActiveEnforcement(t *testing.T) {
	cache := &thawApprovalTestPullRequestCache{}
	exceptions := &thawApprovalTestExceptionApprover{}
	statuses := &thawApprovalTestStatusRunner{}
	publisher := &thawApprovalTestPublisher{}
	syncer := &thawApprovalTestSyncer{cache: cache}
	tokens := &countingThawApprovalTokenGetter{}
	service := newThawApprovalService(
		inactiveThawApprovalRepositoryGetter{},
		tokens,
		cache,
		exceptions,
		&thawApprovalTestFreezeLister{},
		statuses,
		publisher,
		syncer,
		func(repository domain.Repository, token string) (thawApprovalForgeClient, error) {
			t.Fatal("forge client must not be created without active enforcement")
			return nil, nil
		},
	)

	_, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(nil), thawApprovalTestActor())
	if !statusresult.IsValidationError(err) || err.Error() != domain.EnforcementNotActiveMessage {
		t.Fatalf("expected enforcement validation error, got %v", err)
	}
	if tokens.calls != 0 {
		t.Fatalf("expected no token lookup without active enforcement, got %d", tokens.calls)
	}
	if syncer.calls != 0 {
		t.Fatalf("expected no forge sync without active enforcement, got %d", syncer.calls)
	}
	assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
}

type inactiveThawApprovalRepositoryGetter struct{}

func (inactiveThawApprovalRepositoryGetter) Get(context.Context, int64) (domain.Repository, error) {
	return domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard", EnforcementState: domain.EnforcementSetupIncomplete}, nil
}

type countingThawApprovalTokenGetter struct {
	calls int
}

func (g *countingThawApprovalTokenGetter) StatusToken(context.Context, int64) (string, bool, error) {
	g.calls++
	return "secret-token", true, nil
}

func TestThawApprovalChangedHeadRequiresConfirmationAgain(t *testing.T) {
	selectedABC := thawApprovalTestPullRequest(42, "abc123")
	selectedDEF := thawApprovalTestPullRequest(42, "def456")
	other := thawApprovalTestPullRequest(43, "abc123")
	cache := &thawApprovalTestPullRequestCache{}
	exceptions := &thawApprovalTestExceptionApprover{}
	statuses := &thawApprovalTestStatusRunner{}
	publisher := &thawApprovalTestPublisher{}
	service := newThawApprovalTestService(
		cache,
		exceptions,
		statuses,
		publisher,
		&thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selectedABC, other}, {selectedDEF, other}}},
		&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selectedABC, selectedDEF}},
	)

	initial := requireThawApprovalConfirmation(t, service, nil)
	refreshed := requireThawApprovalConfirmation(t, service, initial.Confirmation)

	if len(refreshed.AffectedPullRequests) != 1 || refreshed.AffectedPullRequests[0].HeadSHA != "def456" {
		t.Fatalf("expected changed head to return the refreshed confirmation set, got %+v", refreshed)
	}
	assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
}

func TestThawApprovalChangedAffectedSetRequiresConfirmationAgain(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	other := thawApprovalTestPullRequest(43, "abc123")
	added := thawApprovalTestPullRequest(44, "abc123")

	for _, test := range []struct {
		name        string
		second      []domain.PullRequest
		wantIndexes []int
	}{
		{name: "added pull request", second: []domain.PullRequest{selected, other, added}, wantIndexes: []int{42, 43, 44}},
		{name: "removed pull request", second: []domain.PullRequest{selected}, wantIndexes: []int{42}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := &thawApprovalTestPullRequestCache{}
			exceptions := &thawApprovalTestExceptionApprover{}
			statuses := &thawApprovalTestStatusRunner{}
			publisher := &thawApprovalTestPublisher{}
			service := newThawApprovalTestService(
				cache,
				exceptions,
				statuses,
				publisher,
				&thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selected, other}, test.second}},
				&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected, selected}},
			)

			initial := requireThawApprovalConfirmation(t, service, nil)
			refreshed := requireThawApprovalConfirmation(t, service, initial.Confirmation)

			if got := affectedPullRequestIndexes(refreshed); !slices.Equal(got, test.wantIndexes) {
				t.Fatalf("expected refreshed indexes %v, got %v", test.wantIndexes, got)
			}
			assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
		})
	}
}

func TestThawApprovalChangedAffectedTargetBranchRequiresConfirmationAgain(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	otherBefore := thawApprovalTestPullRequest(43, "abc123")
	otherBefore.TargetBranch = "release"
	otherAfter := thawApprovalTestPullRequest(43, "abc123")
	cache := &thawApprovalTestPullRequestCache{}
	exceptions := &thawApprovalTestExceptionApprover{}
	statuses := &thawApprovalTestStatusRunner{}
	publisher := &thawApprovalTestPublisher{}
	service := newThawApprovalTestService(
		cache,
		exceptions,
		statuses,
		publisher,
		&thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selected, otherBefore}, {selected, otherAfter}}},
		&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected, selected}},
	)

	initial := requireThawApprovalConfirmation(t, service, nil)
	refreshed := requireThawApprovalConfirmation(t, service, initial.Confirmation)
	if len(refreshed.AffectedPullRequests) != 2 || refreshed.AffectedPullRequests[1].TargetBranch != "main" || refreshed.Confirmation.AffectedSignature == initial.Confirmation.AffectedSignature {
		t.Fatalf("expected retargeted PR to require a new branch-sensitive confirmation, got %+v", refreshed)
	}
	assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
}

func TestThawApprovalFreezeEndedBeforeSharedHeadConfirmationDoesNothing(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	other := thawApprovalTestPullRequest(43, "abc123")
	cache := &thawApprovalTestPullRequestCache{}
	exceptions := &thawApprovalTestExceptionApprover{}
	statuses := &thawApprovalTestStatusRunner{}
	publisher := &thawApprovalTestPublisher{}
	freezes := &thawApprovalTestFreezeLister{freezes: []domain.BranchFreeze{{RepositoryID: 7, Branch: "main", Active: true}}}
	syncer := &thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selected, other}, {selected, other}}}
	service := newThawApprovalTestServiceWithFreezes(
		cache,
		exceptions,
		statuses,
		publisher,
		syncer,
		&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected, selected}},
		freezes,
	)

	initial := requireThawApprovalConfirmation(t, service, nil)
	freezes.freezes = nil
	outcome, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(initial.Confirmation), thawApprovalTestActor())
	if err == nil || !statusresult.IsValidationError(err) {
		t.Fatalf("expected typed validation error, got %v", err)
	}
	const want = "No thaw is needed because none of the affected pull requests currently targets an actively frozen branch."
	if err.Error() != want {
		t.Fatalf("expected %q, got %q", want, err.Error())
	}
	if outcome.Result != nil || outcome.ConfirmationRequired || outcome.Confirmation != nil || len(outcome.AffectedPullRequests) != 0 {
		t.Fatalf("expected empty failed-confirmation outcome, got %+v", outcome)
	}
	if syncer.calls != 2 {
		t.Fatalf("expected forge state to refresh before rejecting confirmation, got %d syncs", syncer.calls)
	}
	assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
}

func TestThawApprovalShrunkAffectedSetWithEndedFreezeSkipsUniqueApproval(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	other := thawApprovalTestPullRequest(43, "abc123")
	cache := &thawApprovalTestPullRequestCache{}
	exceptions := &thawApprovalTestExceptionApprover{}
	statuses := &thawApprovalTestStatusRunner{}
	publisher := &thawApprovalTestPublisher{}
	freezes := &thawApprovalTestFreezeLister{freezes: []domain.BranchFreeze{{RepositoryID: 7, Branch: "main", Active: true}}}
	syncer := &thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selected, other}, {selected}}}
	service := newThawApprovalTestServiceWithFreezes(
		cache,
		exceptions,
		statuses,
		publisher,
		syncer,
		&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected, selected}},
		freezes,
	)

	initial := requireThawApprovalConfirmation(t, service, nil)
	if got := affectedPullRequestIndexes(initial); !slices.Equal(got, []int{42, 43}) {
		t.Fatalf("expected initial shared-head confirmation for 42 and 43, got %v", got)
	}

	// Before confirmation, PR 43 closes and every relevant freeze ends; the
	// refresh sees only PR 42, which would previously fall into the
	// len(openPRs) == 1 immediate-approval path.
	freezes.freezes = nil

	const want = "No thaw is needed because none of the affected pull requests currently targets an actively frozen branch."
	outcome, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(initial.Confirmation), thawApprovalTestActor())
	if err == nil || !statusresult.IsValidationError(err) || err.Error() != want {
		t.Fatalf("expected exact no-thaw-needed validation error, got %v", err)
	}
	if outcome.Result != nil || outcome.ConfirmationRequired || outcome.Confirmation != nil || len(outcome.AffectedPullRequests) != 0 {
		t.Fatalf("expected empty outcome for unnecessary thaw, got %+v", outcome)
	}
	assertNoThawApprovalMutation(t, exceptions, statuses, publisher)

	// A fresh submission without a confirmation tuple hits the same guard
	// instead of the unique-head immediate-approval path.
	outcome, err = service.ApproveThaw(context.Background(), thawApprovalTestParams(nil), thawApprovalTestActor())
	if err == nil || !statusresult.IsValidationError(err) || err.Error() != want {
		t.Fatalf("expected exact no-thaw-needed validation error on fresh submission, got %v", err)
	}
	if outcome.Result != nil || outcome.ConfirmationRequired {
		t.Fatalf("expected empty outcome for fresh unnecessary thaw, got %+v", outcome)
	}
	assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
}

func TestThawApprovalPersistsBeforeRecomputeAndPublication(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	other := thawApprovalTestPullRequest(43, "abc123")
	other.TargetBranch = "release"
	cache := &thawApprovalTestPullRequestCache{}
	order := make([]string, 0, 3)
	exceptions := &thawApprovalTestExceptionApprover{order: &order}
	statuses := &thawApprovalTestStatusRunner{order: &order}
	publisher := &thawApprovalTestPublisher{order: &order}
	service := newThawApprovalTestService(
		cache,
		exceptions,
		statuses,
		publisher,
		&thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selected, other}, {selected, other}}},
		&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected, selected}},
	)

	initial := requireThawApprovalConfirmation(t, service, nil)
	outcome, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(initial.Confirmation), thawApprovalTestActor())
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result == nil || outcome.Result.Context != domain.RequiredStatusContext {
		t.Fatalf("expected confirmed thawguard/freeze result, got %+v", outcome)
	}
	if got, want := strings.Join(order, ","), "persist,recompute,publish"; got != want {
		t.Fatalf("expected %s ordering, got %s", want, got)
	}
	if len(exceptions.sharedParams) != 1 || len(exceptions.sharedParams[0].Exceptions) != 1 || exceptions.sharedParams[0].Exceptions[0].PullRequestIndex != selected.Index {
		t.Fatalf("expected only the still-frozen PR to need an exception, got %+v", exceptions.sharedParams)
	}
}

func TestThawApprovalStopsBeforePublicationWhenClaimIsSuperseded(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	cache := &thawApprovalTestPullRequestCache{}
	exceptions := &thawApprovalTestExceptionApprover{}
	statuses := &thawApprovalTestStatusRunner{}
	publisher := &thawApprovalTestPublisher{}
	service := newThawApprovalTestService(
		cache,
		exceptions,
		statuses,
		publisher,
		&thawApprovalTestSyncer{cache: cache, snapshots: [][]domain.PullRequest{{selected}}},
		&thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected}},
	)
	convergence := newTestEnforcementConvergence(true, false)
	service.convergence = convergence

	outcome, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(nil), thawApprovalTestActor())
	if err != nil {
		t.Fatal(err)
	}
	if exceptions.uniqueCalls != 1 || statuses.calls != 1 {
		t.Fatalf("expected durable thaw policy to persist and evaluate once, exceptions=%d statuses=%d", exceptions.uniqueCalls, statuses.calls)
	}
	if publisher.calls != 0 || outcome.Result != nil {
		t.Fatalf("superseded thaw claim must not publish, calls=%d outcome=%+v", publisher.calls, outcome)
	}
	if convergence.currentCalls != 2 || convergence.completeCalls != 0 || convergence.failCalls != 0 {
		t.Fatalf("expected newer work to retain ownership, convergence=%+v", convergence)
	}
}

func TestThawApprovalForgeFailuresAreFailClosedAndRedactTokens(t *testing.T) {
	selected := thawApprovalTestPullRequest(42, "abc123")
	for _, test := range []struct {
		name   string
		client *thawApprovalTestForgeClient
		syncer *thawApprovalTestSyncer
	}{
		{name: "current pull request", client: &thawApprovalTestForgeClient{err: errors.New("secret-token rejected")}, syncer: &thawApprovalTestSyncer{}},
		{name: "open pull request sync", client: &thawApprovalTestForgeClient{pullRequests: []domain.PullRequest{selected}}, syncer: &thawApprovalTestSyncer{err: errors.New("secret-token rejected")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := &thawApprovalTestPullRequestCache{}
			test.syncer.cache = cache
			exceptions := &thawApprovalTestExceptionApprover{}
			statuses := &thawApprovalTestStatusRunner{}
			publisher := &thawApprovalTestPublisher{}
			service := newThawApprovalTestService(cache, exceptions, statuses, publisher, test.syncer, test.client)

			_, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(nil), thawApprovalTestActor())
			if err == nil {
				t.Fatal("expected forge failure")
			}
			if strings.Contains(err.Error(), "secret-token") || !strings.Contains(err.Error(), "[redacted]") {
				t.Fatalf("expected redacted error, got %q", err.Error())
			}
			assertNoThawApprovalMutation(t, exceptions, statuses, publisher)
		})
	}
}

func requireThawApprovalConfirmation(t *testing.T, service *thawApprovalService, confirmation *statusresult.ThawApprovalConfirmation) statusresult.ThawApprovalOutcome {
	t.Helper()
	outcome, err := service.ApproveThaw(context.Background(), thawApprovalTestParams(confirmation), thawApprovalTestActor())
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.ConfirmationRequired || outcome.Result != nil {
		t.Fatalf("expected confirmation requirement, got %+v", outcome)
	}
	if outcome.Confirmation == nil || outcome.Confirmation.AffectedSignature == "" {
		t.Fatalf("expected server-derived confirmation tuple, got %+v", outcome)
	}
	return outcome
}

func thawApprovalTestParams(confirmation *statusresult.ThawApprovalConfirmation) statusresult.ThawApprovalParams {
	return statusresult.ThawApprovalParams{RepositoryID: 7, PullRequestIndex: 42, TargetBranch: "main", Reason: "production fix", Confirmation: confirmation}
}

func thawApprovalTestActor() domain.Actor {
	return domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
}

func thawApprovalTestPullRequest(index int, headSHA string) domain.PullRequest {
	return domain.PullRequest{RepositoryID: 7, Index: index, Title: "Release fix", State: "open", TargetBranch: "main", HeadSHA: headSHA, URL: "https://codeberg.org/taua-almeida/thawguard/pulls/"}
}

func affectedPullRequestIndexes(outcome statusresult.ThawApprovalOutcome) []int {
	indexes := make([]int, 0, len(outcome.AffectedPullRequests))
	for _, pr := range outcome.AffectedPullRequests {
		indexes = append(indexes, pr.Index)
	}
	return indexes
}

func assertNoThawApprovalMutation(t *testing.T, exceptions *thawApprovalTestExceptionApprover, statuses *thawApprovalTestStatusRunner, publisher *thawApprovalTestPublisher) {
	t.Helper()
	if exceptions.uniqueCalls != 0 || exceptions.sharedCalls != 0 || statuses.calls != 0 || publisher.calls != 0 {
		t.Fatalf("expected no approval mutation, unique=%d shared=%d status=%d publish=%d", exceptions.uniqueCalls, exceptions.sharedCalls, statuses.calls, publisher.calls)
	}
}

func newThawApprovalTestService(cache *thawApprovalTestPullRequestCache, exceptions *thawApprovalTestExceptionApprover, statuses *thawApprovalTestStatusRunner, publisher *thawApprovalTestPublisher, syncer *thawApprovalTestSyncer, client *thawApprovalTestForgeClient) *thawApprovalService {
	return newThawApprovalTestServiceWithFreezes(cache, exceptions, statuses, publisher, syncer, client, &thawApprovalTestFreezeLister{freezes: []domain.BranchFreeze{{RepositoryID: 7, Branch: "main", Active: true}}})
}

func newThawApprovalTestServiceWithFreezes(cache *thawApprovalTestPullRequestCache, exceptions *thawApprovalTestExceptionApprover, statuses *thawApprovalTestStatusRunner, publisher *thawApprovalTestPublisher, syncer *thawApprovalTestSyncer, client *thawApprovalTestForgeClient, freezes thawApprovalFreezeLister) *thawApprovalService {
	return newThawApprovalService(
		thawApprovalTestRepositoryGetter{},
		thawApprovalTestTokenGetter{},
		cache,
		exceptions,
		freezes,
		statuses,
		publisher,
		syncer,
		func(repository domain.Repository, token string) (thawApprovalForgeClient, error) { return client, nil },
	)
}

type thawApprovalTestRepositoryGetter struct{}

func (thawApprovalTestRepositoryGetter) Get(context.Context, int64) (domain.Repository, error) {
	return domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard", EnforcementState: domain.EnforcementActive}, nil
}

type thawApprovalTestTokenGetter struct{}

func (thawApprovalTestTokenGetter) StatusToken(context.Context, int64) (string, bool, error) {
	return "secret-token", true, nil
}

type thawApprovalTestPullRequestCache struct {
	prs []domain.PullRequest
}

func (c *thawApprovalTestPullRequestCache) Upsert(_ context.Context, pr domain.PullRequest) (domain.PullRequest, error) {
	for i := range c.prs {
		if c.prs[i].Index == pr.Index {
			c.prs[i] = pr
			return pr, nil
		}
	}
	c.prs = append(c.prs, pr)
	return pr, nil
}

func (c *thawApprovalTestPullRequestCache) ListOpenByHead(_ context.Context, repositoryID int64, headSHA string) ([]domain.PullRequest, error) {
	var prs []domain.PullRequest
	for _, pr := range c.prs {
		if pr.RepositoryID == repositoryID && pr.IsOpen() && pr.HeadSHA == headSHA {
			prs = append(prs, pr)
		}
	}
	return prs, nil
}

type thawApprovalTestExceptionApprover struct {
	uniqueCalls  int
	sharedCalls  int
	sharedParams []thawexception.ApproveSharedHeadParams
	order        *[]string
}

func (a *thawApprovalTestExceptionApprover) Approve(context.Context, thawexception.ApproveParams, domain.Actor) (domain.ThawException, error) {
	a.uniqueCalls++
	return domain.ThawException{}, nil
}

func (a *thawApprovalTestExceptionApprover) ApproveSharedHead(_ context.Context, params thawexception.ApproveSharedHeadParams, _ domain.Actor) ([]domain.ThawException, error) {
	a.sharedCalls++
	a.sharedParams = append(a.sharedParams, params)
	if a.order != nil {
		*a.order = append(*a.order, "persist")
	}
	approved := make([]domain.ThawException, len(params.Exceptions))
	return approved, nil
}

type thawApprovalTestFreezeLister struct {
	freezes []domain.BranchFreeze
}

func (l *thawApprovalTestFreezeLister) ListActive(context.Context) ([]domain.BranchFreeze, error) {
	return l.freezes, nil
}

type thawApprovalTestStatusRunner struct {
	calls int
	order *[]string
}

func (r *thawApprovalTestStatusRunner) ListRecent(context.Context, int) ([]statusresult.Result, error) {
	return nil, nil
}

func (r *thawApprovalTestStatusRunner) RunForSharedHead(_ context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error) {
	r.calls++
	if r.order != nil {
		*r.order = append(*r.order, "recompute")
	}
	return statusresult.Result{ID: 1, RepositoryID: prs[0].RepositoryID, PullRequestIndex: preferredIndex, TargetBranch: prs[0].TargetBranch, HeadSHA: prs[0].HeadSHA, Context: domain.RequiredStatusContext, State: domain.CommitStatusSuccess}, nil
}

type thawApprovalTestPublisher struct {
	calls int
	order *[]string
}

func (p *thawApprovalTestPublisher) Publish(_ context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	p.calls++
	if p.order != nil {
		*p.order = append(*p.order, "publish")
	}
	return statuspublication.Publication{StatusResultID: result.ID}, nil
}

type thawApprovalTestSyncer struct {
	cache     *thawApprovalTestPullRequestCache
	snapshots [][]domain.PullRequest
	calls     int
	err       error
}

func (s *thawApprovalTestSyncer) SyncOpenPullRequests(_ context.Context, _ int64, targetBranch string) error {
	if targetBranch != "" {
		return errors.New("shared-head thaw sync must refresh all repository branches")
	}
	if s.err != nil {
		return s.err
	}
	if len(s.snapshots) > 0 {
		index := s.calls
		if index >= len(s.snapshots) {
			index = len(s.snapshots) - 1
		}
		s.cache.prs = append([]domain.PullRequest(nil), s.snapshots[index]...)
	}
	s.calls++
	return nil
}

type thawApprovalTestForgeClient struct {
	pullRequests []domain.PullRequest
	calls        int
	err          error
}

func (c *thawApprovalTestForgeClient) GetPullRequest(context.Context, string, string, int) (domain.PullRequest, error) {
	if c.err != nil {
		return domain.PullRequest{}, c.err
	}
	index := c.calls
	if index >= len(c.pullRequests) {
		index = len(c.pullRequests) - 1
	}
	c.calls++
	return c.pullRequests[index], nil
}
