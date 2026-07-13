package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

type postedForgeStatus struct {
	SHA   string
	State string
}

type enforcementLifecycleHarness struct {
	database *sql.DB
	repo     domain.Repository
	store    *freezeRecomputingStore
	posted   *[]postedForgeStatus
}

// newEnforcementLifecycleHarness wires the real freeze lifecycle path (stores,
// syncer, publisher) against an httptest forge that lists openPRs and records
// posted statuses.
func newEnforcementLifecycleHarness(t *testing.T, ctx context.Context, openPRs *[]forgejoPullRequestResponse) *enforcementLifecycleHarness {
	t.Helper()
	posted := &[]postedForgeStatus{}
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/pulls":
			_ = json.NewEncoder(w).Encode(*openPRs)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/repos/taua-almeida/thawguard/statuses/"):
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			*posted = append(*posted, postedForgeStatus{SHA: strings.TrimPrefix(r.URL.Path, "/api/v1/repos/taua-almeida/thawguard/statuses/"), State: body["state"]})
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected forge request %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(forge.Close)

	database := newAppTestDB(t, ctx)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, newAppTestSecretStore(t))
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forge.URL, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, "live-status-token-123", admin); err != nil {
		t.Fatal(err)
	}
	repo, err = repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
	if err != nil {
		t.Fatal(err)
	}

	pullRequests := pullrequest.NewStore(database)
	freezes := freeze.NewService(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freezes, thawexception.NewService(database), pullRequests)
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, forgejoPullRequestClientForRepository)
	store := newFreezeRecomputingStore(freezes, repository.NewStore(database), syncer, pullRequests, statuses, publisher)
	return &enforcementLifecycleHarness{database: database, repo: repo, store: store, posted: posted}
}

func TestActiveFreezeLifecycleSyncsForgePRsAndPostsStatuses(t *testing.T) {
	ctx := context.Background()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	openPRs := &[]forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "ABC123")}
	h := newEnforcementLifecycleHarness(t, ctx, openPRs)

	// The PR cache is empty; freeze create must discover PR 42 from the forge
	// before recomputing, then post a failure for its head.
	created, err := h.store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(*h.posted) != 1 || (*h.posted)[0].SHA != "abc123" || (*h.posted)[0].State != "failure" {
		t.Fatalf("expected freeze create to sync and post failure for discovered PR, got %+v", *h.posted)
	}

	// Lift refreshes current PRs and posts success for the current head.
	*h.posted = nil
	*openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "DEF456")}
	if _, err := h.store.End(ctx, created.ID, admin); err != nil {
		t.Fatal(err)
	}
	if len(*h.posted) != 1 || (*h.posted)[0].SHA != "def456" || (*h.posted)[0].State != "success" {
		t.Fatalf("expected lift to refresh and post success for current head, got %+v", *h.posted)
	}
}

func TestDueImmediateFreezePublishesThawedPolicyAndClearsRetryMarker(t *testing.T) {
	ctx := context.Background()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	openPRs := &[]forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "ABC123")}
	h := newEnforcementLifecycleHarness(t, ctx, openPRs)
	plannedEndsAt := time.Now().UTC().Add(time.Hour)

	created, err := h.store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "deployment", PlannedEndsAt: &plannedEndsAt}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(*h.posted) != 1 || (*h.posted)[0].State != "failure" {
		t.Fatalf("expected immediate freeze to publish failure before its planned end, got %+v", *h.posted)
	}
	if _, err := h.database.ExecContext(ctx, `UPDATE branch_freezes SET planned_ends_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z"), created.ID); err != nil {
		t.Fatal(err)
	}
	*h.posted = nil
	ended, err := h.store.ExecutePlannedUnfreeze(ctx, created.ID, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"})
	if err != nil {
		t.Fatal(err)
	}
	if len(*h.posted) != 1 || (*h.posted)[0].State != "success" {
		t.Fatalf("expected due immediate freeze to publish current thawed policy, got %+v", *h.posted)
	}
	reloaded, err := freeze.NewService(h.database).Get(ctx, ended.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != domain.BranchFreezeStatusEnded || reloaded.NeedsRecompute {
		t.Fatalf("expected successful automatic end to clear retry marker, got %+v", reloaded)
	}
}

func TestDueImmediateFreezeKeepsSharedHeadBlockedByAnotherActiveFreeze(t *testing.T) {
	ctx := context.Background()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	openPRs := &[]forgejoPullRequestResponse{
		newAppPullRequestResponse(1, "open", "main", "ABC123"),
		newAppPullRequestResponse(2, "open", "develop", "ABC123"),
	}
	h := newEnforcementLifecycleHarness(t, ctx, openPRs)
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	plannedEndsAt := time.Now().UTC().Add(time.Hour)
	mainFreeze, err := h.store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "deployment", PlannedEndsAt: &plannedEndsAt}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "develop", Reason: "release"}, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(ctx, `UPDATE branch_freezes SET planned_ends_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z"), mainFreeze.ID); err != nil {
		t.Fatal(err)
	}
	*h.posted = nil
	if _, err := h.store.ExecutePlannedUnfreeze(ctx, mainFreeze.ID, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}); err != nil {
		t.Fatal(err)
	}
	if len(*h.posted) != 1 || (*h.posted)[0].SHA != "abc123" || (*h.posted)[0].State != "failure" {
		t.Fatalf("expected remaining active freeze to keep shared-head policy blocked, got %+v", *h.posted)
	}
}

func TestActiveFreezeLifecycleCrossBranchSharedHeadCannotPublishAccidentalSuccess(t *testing.T) {
	ctx := context.Background()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	// PR 1 targets main, PR 2 targets develop; both share one head SHA.
	openPRs := &[]forgejoPullRequestResponse{
		newAppPullRequestResponse(1, "open", "main", "ABC123"),
		newAppPullRequestResponse(2, "open", "develop", "ABC123"),
	}
	h := newEnforcementLifecycleHarness(t, ctx, openPRs)
	// Manage develop directly at the store layer: the service guard blocks
	// branch-scope changes once enforcement is active.
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}

	mainFreeze, err := h.store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "develop", Reason: "develop freeze"}, admin); err != nil {
		t.Fatal(err)
	}

	// Lifting the main freeze recomputes the shared head repository-wide; the
	// develop freeze still covers PR 2, so the one SHA decision stays failure.
	*h.posted = nil
	if _, err := h.store.End(ctx, mainFreeze.ID, admin); err != nil {
		t.Fatal(err)
	}
	if len(*h.posted) != 1 || (*h.posted)[0].SHA != "abc123" || (*h.posted)[0].State != "failure" {
		t.Fatalf("expected one repository-wide failure for shared head, got %+v", *h.posted)
	}
}

func TestDueScheduledFreezeStaysScheduledWhenRepositoryEnforcementIsInactive(t *testing.T) {
	ctx := context.Background()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	openPRs := &[]forgejoPullRequestResponse{}
	h := newEnforcementLifecycleHarness(t, ctx, openPRs)

	startsAt := time.Now().UTC().Add(time.Hour)
	scheduled, err := h.store.CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release window", StartsAt: startsAt}, admin)
	if err != nil {
		t.Fatal(err)
	}
	// Make the existing scheduled row due, then deactivate the repository
	// before the runner would pick it up.
	if _, err := h.database.ExecContext(ctx, `UPDATE branch_freezes SET starts_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z"), scheduled.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(h.database).SetEnforcementState(ctx, h.repo.ID, domain.EnforcementSetupIncomplete); err != nil {
		t.Fatal(err)
	}

	_, err = h.store.ActivateScheduled(ctx, scheduled.ID, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"})
	if !freeze.IsValidationError(err) || err.Error() != domain.EnforcementNotActiveMessage {
		t.Fatalf("expected enforcement validation error, got %v", err)
	}

	var status string
	if err := h.database.QueryRowContext(ctx, `SELECT status FROM branch_freezes WHERE id = ?`, scheduled.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(domain.BranchFreezeStatusScheduled) {
		t.Fatalf("expected due window to remain scheduled, got %q", status)
	}
	events, err := audit.NewStore(h.database).List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == audit.ActionFreezeScheduleActivated {
			t.Fatalf("expected no activation audit event, got %+v", event)
		}
	}
	assertAppTableCount(t, h.database, "status_results", 0)
	assertAppTableCount(t, h.database, "status_publication_intents", 0)
	assertAppTableCount(t, h.database, "status_publication_attempts", 0)
	if len(*h.posted) != 0 {
		t.Fatalf("expected no forge status post, got %+v", *h.posted)
	}
}

// Matrix row: active repository, missing token, stale cached PR — sync fails
// closed before any stale status is recomputed or published.
func TestActiveFreezeMissingTokenFailsSyncClosedWithoutStalePublication(t *testing.T) {
	ctx := context.Background()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	database := newAppTestDB(t, ctx)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, newAppTestSecretStore(t))
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	pullRequests := pullrequest.NewStore(database)
	if _, err := pullRequests.Upsert(ctx, domain.PullRequest{RepositoryID: repo.ID, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}); err != nil {
		t.Fatal(err)
	}
	freezes := freeze.NewService(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freezes, thawexception.NewService(database), pullRequests)
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, forgejoPullRequestClientForRepository)
	store := newFreezeRecomputingStore(freezes, repository.NewStore(database), syncer, pullRequests, statuses, publisher)

	_, err = store.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "main", Reason: "release freeze"}, admin)
	if !errors.Is(err, ErrOpenPullRequestSyncStatusTokenMissing) {
		t.Fatalf("expected missing-token sync failure, got %v", err)
	}
	assertAppTableCount(t, database, "status_results", 0)
	assertAppTableCount(t, database, "status_publication_intents", 0)
	assertAppTableCount(t, database, "status_publication_attempts", 0)
}

func TestScheduledFreezeActivationAndPlannedUnfreezeUseSyncInvariant(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeScheduledFreezeOperations{
		activated: domain.BranchFreeze{ID: 3, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true},
		ended:     domain.BranchFreeze{ID: 3, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusEnded, Scheduled: true},
	}
	pulls := &fakeOpenPullRequestBranchLister{}
	syncer := &fakeRecomputeSyncer{onSync: func() {
		pulls.prs = []domain.PullRequest{{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}}
	}}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}
	store := newFreezeRecomputingStore(freezes, repositories, syncer, pulls, statuses, publisher)
	actor := domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}

	if _, err := store.ActivateScheduled(ctx, 3, actor); err != nil {
		t.Fatal(err)
	}
	if len(syncer.calls) != 1 || len(publisher.results) != 1 || publisher.results[0].HeadSHA != "aaa111" {
		t.Fatalf("expected scheduled activation to sync then publish, sync=%+v publish=%+v", syncer.calls, publisher.results)
	}
	if freezes.recomputedIDs["activate"] != 3 {
		t.Fatalf("expected activation recompute mark, got %+v", freezes.recomputedIDs)
	}

	syncer.calls = nil
	publisher.results = nil
	if _, err := store.ExecutePlannedUnfreeze(ctx, 3, actor); err != nil {
		t.Fatal(err)
	}
	if len(syncer.calls) != 1 || len(publisher.results) != 1 {
		t.Fatalf("expected planned unfreeze to sync then publish, sync=%+v publish=%+v", syncer.calls, publisher.results)
	}
}

func TestImmediatePlannedUnfreezeRecomputesAndClearsMarkerAfterSuccess(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeScheduledFreezeOperations{
		ended: domain.BranchFreeze{ID: 8, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusEnded, NeedsRecompute: true},
	}
	pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}}}
	syncer := &fakeRecomputeSyncer{}
	statuses := &fakeSharedHeadStatusRunner{}
	publisher := &fakeStatusPublisher{}
	store := newFreezeRecomputingStore(freezes, &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}, syncer, pulls, statuses, publisher)

	ended, err := store.ExecutePlannedUnfreeze(ctx, 8, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"})
	if err != nil {
		t.Fatal(err)
	}
	if ended.Scheduled || len(syncer.calls) != 1 || len(publisher.results) != 1 || len(freezes.markCalls) != 1 || freezes.markCalls[0] != 8 {
		t.Fatalf("expected immediate planned end to sync, publish, and clear marker; ended=%+v sync=%+v publish=%+v marks=%+v", ended, syncer.calls, publisher.results, freezes.markCalls)
	}
}

func TestScheduledActivationKeepsMarkerIfEnforcementChangesBeforeRecompute(t *testing.T) {
	ctx := context.Background()
	activated := domain.BranchFreeze{ID: 3, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true, NeedsRecompute: true}
	freezes := &fakeScheduledFreezeOperations{activated: activated}
	repositories := &fakeOpenPRRepositoryGetter{
		repo: newRecomputeTestRepository(7, domain.EnforcementActive),
		repos: []domain.Repository{
			newRecomputeTestRepository(7, domain.EnforcementActive),
			newRecomputeTestRepository(7, domain.EnforcementUnhealthy),
		},
	}
	store := newFreezeRecomputingStore(freezes, repositories, &fakeRecomputeSyncer{}, &fakeOpenPullRequestBranchLister{}, &fakeSharedHeadStatusRunner{}, &fakeStatusPublisher{})

	if _, err := store.ActivateScheduled(ctx, activated.ID, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}); err != nil {
		t.Fatal(err)
	}
	if len(freezes.markCalls) != 0 {
		t.Fatalf("expected activation marker to remain pending without convergence, got %+v", freezes.markCalls)
	}
	if err := store.RetryRecompute(ctx, activated); err != nil {
		t.Fatal(err)
	}
	if len(freezes.markCalls) != 1 || freezes.markCalls[0] != activated.ID {
		t.Fatalf("expected later active retry to clear marker, got %+v", freezes.markCalls)
	}
}

func TestPlannedUnfreezeFailureLeavesMarkerForLaterRetry(t *testing.T) {
	for _, test := range []struct {
		name       string
		syncErr    error
		publishErr error
	}{
		{name: "sync failure", syncErr: errors.New("forge unavailable")},
		{name: "publication failure", publishErr: errors.New("publication failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			freezes := &fakeScheduledFreezeOperations{ended: domain.BranchFreeze{ID: 8, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusEnded, NeedsRecompute: true}}
			pulls := &fakeOpenPullRequestBranchLister{prs: []domain.PullRequest{{RepositoryID: 7, Index: 1, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}}}
			syncer := &fakeRecomputeSyncer{err: test.syncErr}
			publisher := &fakeStatusPublisher{err: test.publishErr}
			store := newFreezeRecomputingStore(freezes, &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementActive)}, syncer, pulls, &fakeSharedHeadStatusRunner{}, publisher)

			ended, err := store.ExecutePlannedUnfreeze(ctx, 8, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"})
			if err == nil || ended.Status != domain.BranchFreezeStatusEnded || len(freezes.markCalls) != 0 {
				t.Fatalf("expected ended freeze with pending marker after failure, ended=%+v err=%v marks=%+v", ended, err, freezes.markCalls)
			}
			syncer.err = nil
			publisher.err = nil
			if err := store.RetryRecompute(ctx, ended); err != nil {
				t.Fatal(err)
			}
			if len(freezes.markCalls) != 1 || freezes.markCalls[0] != ended.ID {
				t.Fatalf("expected successful retry to clear marker, got %+v", freezes.markCalls)
			}
		})
	}
}

func TestPlannedUnfreezeDoesNotClearMarkerWhileEnforcementInactive(t *testing.T) {
	ctx := context.Background()
	ended := domain.BranchFreeze{ID: 8, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusEnded, NeedsRecompute: true}
	freezes := &fakeScheduledFreezeOperations{ended: ended}
	store := newFreezeRecomputingStore(freezes, &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementUnhealthy)}, &fakeRecomputeSyncer{}, &fakeOpenPullRequestBranchLister{}, &fakeSharedHeadStatusRunner{}, &fakeStatusPublisher{})

	if _, err := store.ExecutePlannedUnfreeze(ctx, ended.ID, domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RetryRecompute(ctx, ended); err != nil {
		t.Fatal(err)
	}
	if len(freezes.markCalls) != 0 {
		t.Fatalf("expected unhealthy repository to preserve pending recompute, got marks %+v", freezes.markCalls)
	}
}

func TestFreezeRecomputingStoreRejectsScheduledCreateWithoutActiveEnforcement(t *testing.T) {
	ctx := context.Background()
	freezes := &fakeScheduledFreezeOperations{}
	repositories := &fakeOpenPRRepositoryGetter{repo: newRecomputeTestRepository(7, domain.EnforcementSetupIncomplete)}
	store := newFreezeRecomputingStore(freezes, repositories, &fakeRecomputeSyncer{}, &fakeOpenPullRequestBranchLister{}, &fakeSharedHeadStatusRunner{}, &fakeStatusPublisher{})

	_, err := store.CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: 7, Branch: "main", Reason: "window"}, domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !freeze.IsValidationError(err) || err.Error() != domain.EnforcementNotActiveMessage {
		t.Fatalf("expected enforcement validation error, got %v", err)
	}
	if freezes.scheduleCalls != 0 {
		t.Fatalf("expected no schedule mutation for inactive repository, got %d", freezes.scheduleCalls)
	}
}

type fakeScheduledFreezeOperations struct {
	fakeFreezeOperations
	activated     domain.BranchFreeze
	ended         domain.BranchFreeze
	scheduleCalls int
	recomputedIDs map[string]int64
	markCalls     []int64
}

func (f *fakeScheduledFreezeOperations) Get(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	return domain.BranchFreeze{ID: id, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true}, nil
}

func (f *fakeScheduledFreezeOperations) ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return nil, nil
}

func (f *fakeScheduledFreezeOperations) CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	f.scheduleCalls++
	return domain.BranchFreeze{}, nil
}

func (f *fakeScheduledFreezeOperations) CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return domain.BranchFreeze{}, nil
}

func (f *fakeScheduledFreezeOperations) ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return nil, nil
}

func (f *fakeScheduledFreezeOperations) ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return f.activated, nil
}

func (f *fakeScheduledFreezeOperations) ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return nil, nil
}

func (f *fakeScheduledFreezeOperations) ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return f.ended, nil
}

func (f *fakeScheduledFreezeOperations) ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return nil, nil
}

func (f *fakeScheduledFreezeOperations) MarkRecomputed(ctx context.Context, id int64) (domain.BranchFreeze, error) {
	f.markCalls = append(f.markCalls, id)
	if f.recomputedIDs == nil {
		f.recomputedIDs = map[string]int64{}
	}
	f.recomputedIDs["activate"] = id
	return domain.BranchFreeze{}, nil
}
