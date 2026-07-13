package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

func TestRepositoryReconciliationRunnerRecoversUnhealthyRepositoryWithFullProof(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	h.setState(t, ctx, domain.EnforcementActive)
	created, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(ctx, `UPDATE branch_freezes SET needs_recompute = 1 WHERE id = ?`, created.ID); err != nil {
		t.Fatal(err)
	}
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	if _, err := repository.NewStore(h.database).SetEnforcementFailure(ctx, h.repo.ID, domain.EnforcementFailurePublication, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	jobStore := jobs.NewStore(h.database)
	runner := newRepositoryReconciliationRunner(jobStore, h.service, nil)

	if err := runner.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementActive || repo.EnforcementFailureReason != "" {
		t.Fatalf("expected fully recovered active repository, got %+v", repo)
	}
	if len(h.setupContextPosts()) != 1 || len(h.freezeContextPosts()) != 1 {
		t.Fatalf("expected setup proof and current freeze policy publication, got %+v", h.forge.posted)
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
	reloaded, err := freeze.NewService(h.database).Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.NeedsRecompute {
		t.Fatalf("expected repository-wide success to clear lifecycle marker, got %+v", reloaded)
	}
}

func TestFreezeRuntimeFailurePersistsUnhealthyStateAndOneDurableJob(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	h.forge.failFreezePost = true
	store := runtimeFreezeStore(h)
	before := time.Now().UTC()

	created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin)
	if err == nil || created.ID == 0 {
		t.Fatalf("expected post-commit publication failure with persisted freeze, created=%+v err=%v", created, err)
	}
	assertRuntimeFailureState(t, ctx, h, domain.EnforcementFailurePublication)
	jobStore := jobs.NewStore(h.database)
	job, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil || job.Generation != 1 || job.Attempts != 1 || job.LockedAt != nil || job.RunAt.Before(before.Add(14*time.Second)) {
		t.Fatalf("expected first durable generation, job=%+v err=%v", job, err)
	}
	if _, err := store.End(ctx, created.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	refreshed, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil || refreshed.ID != job.ID || refreshed.Generation != 2 {
		t.Fatalf("expected unhealthy cleanup to refresh one job, old=%+v new=%+v err=%v", job, refreshed, err)
	}
}

func TestSuccessfulFreezeRuntimeConvergenceCompletesClaimedIntent(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	store := runtimeFreezeStore(h)
	if _, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin); err != nil {
		t.Fatal(err)
	}
	assertNoReconciliationJob(t, ctx, jobs.NewStore(h.database), h.repo.ID)
}

func TestFreezeInlineConvergenceDefersToExistingWorkerClaim(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	created, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	jobStore := jobs.NewStore(h.database)
	claim, claimed, err := jobStore.ClaimRepository(ctx, h.repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected worker to own committed intent, claim=%+v claimed=%v err=%v", claim, claimed, err)
	}

	if err := runtimeFreezeStore(h).convergeFreeze(ctx, created); err != nil {
		t.Fatal(err)
	}
	if posts := h.freezeContextPosts(); len(posts) != 0 {
		t.Fatalf("inline path must not publish while worker owns the lease, got %+v", posts)
	}
	if _, err := h.service.processReconciliationClaim(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if posts := h.freezeContextPosts(); len(posts) != 1 {
		t.Fatalf("expected exactly one worker publication, got %+v", posts)
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
}

func TestFreezeCloseFailuresRetainDurableRecovery(t *testing.T) {
	for _, test := range []struct {
		name  string
		close func(context.Context, *freezeRecomputingStore, int64, domain.Actor) error
	}{
		{name: "lift", close: func(ctx context.Context, store *freezeRecomputingStore, id int64, actor domain.Actor) error {
			_, err := store.End(ctx, id, actor)
			return err
		}},
		{name: "cancel", close: func(ctx context.Context, store *freezeRecomputingStore, id int64, actor domain.Actor) error {
			_, err := store.Cancel(ctx, id, actor)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			h := newEnforcementHarness(t, ctx)
			h.setState(t, ctx, domain.EnforcementActive)
			h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
			store := runtimeFreezeStore(h)
			created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin)
			if err != nil {
				t.Fatal(err)
			}
			h.forge.failFreezePost = true
			if err := test.close(ctx, store, created.ID, h.admin); err == nil {
				t.Fatal("expected post-commit close publication failure")
			}
			assertRuntimeFailureState(t, ctx, h, domain.EnforcementFailurePublication)
			if _, err := jobs.NewStore(h.database).GetReconciliation(ctx, h.repo.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScheduledActivationAndPlannedUnfreezeFailuresRetainDurableRecovery(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(context.Context, *enforcementHarness, *freezeRecomputingStore) error
	}{
		{name: "scheduled activation", mutate: func(ctx context.Context, h *enforcementHarness, store *freezeRecomputingStore) error {
			start := time.Now().UTC().Add(time.Hour)
			scheduled, err := freeze.NewService(h.database).CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "window", StartsAt: start}, h.admin)
			if err != nil {
				return err
			}
			if _, err := h.database.ExecContext(ctx, `UPDATE branch_freezes SET starts_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z"), scheduled.ID); err != nil {
				return err
			}
			_, err = store.ActivateScheduled(ctx, scheduled.ID, h.admin)
			return err
		}},
		{name: "scheduled Start Now", mutate: func(ctx context.Context, h *enforcementHarness, store *freezeRecomputingStore) error {
			start := time.Now().UTC().Add(time.Hour)
			scheduled, err := freeze.NewService(h.database).CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "window", StartsAt: start}, h.admin)
			if err != nil {
				return err
			}
			h.forge.failFreezePost = true
			_, err = store.StartScheduledNow(ctx, scheduled.ID, h.admin)
			return err
		}},
		{name: "planned unfreeze", mutate: func(ctx context.Context, h *enforcementHarness, store *freezeRecomputingStore) error {
			planned := time.Now().UTC().Add(time.Hour)
			created, err := store.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release", PlannedEndsAt: &planned}, h.admin)
			if err != nil {
				return err
			}
			if _, err := h.database.ExecContext(ctx, `UPDATE branch_freezes SET planned_ends_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z"), created.ID); err != nil {
				return err
			}
			h.forge.failFreezePost = true
			_, err = store.ExecutePlannedUnfreeze(ctx, created.ID, h.admin)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			h := newEnforcementHarness(t, ctx)
			h.setState(t, ctx, domain.EnforcementActive)
			h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
			store := runtimeFreezeStore(h)
			if test.name == "scheduled activation" {
				h.forge.failFreezePost = true
			}
			if err := test.mutate(ctx, h, store); err == nil {
				t.Fatal("expected post-commit lifecycle convergence failure")
			}
			assertRuntimeFailureState(t, ctx, h, domain.EnforcementFailurePublication)
			if _, err := jobs.NewStore(h.database).GetReconciliation(ctx, h.repo.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStartScheduledNowSynchronizesSharedHeadsAndCompletesDurableIntent(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(42, "open", "main", "AAA111BBB222"),
		newAppPullRequestResponse(43, "open", "develop", "AAA111BBB222"),
	}
	store := runtimeFreezeStore(h)
	planned := time.Now().UTC().Add(3 * time.Hour)
	scheduled, err := freeze.NewService(h.database).CreateScheduled(ctx, freeze.ScheduleParams{
		RepositoryID:  h.repo.ID,
		Branch:        "main",
		Reason:        "release window",
		StartsAt:      time.Now().UTC().Add(2 * time.Hour),
		PlannedEndsAt: &planned,
	}, h.admin)
	if err != nil {
		t.Fatal(err)
	}

	started, err := store.StartScheduledNow(ctx, scheduled.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != domain.BranchFreezeStatusActive || started.StartsAt == nil || !started.StartsAt.Before(scheduled.StartsAt.UTC()) || started.PlannedEndsAt == nil || !started.PlannedEndsAt.Equal(planned) {
		t.Fatalf("expected converged active schedule with preserved planned end, got %+v", started)
	}
	converged, err := freeze.NewService(h.database).Get(ctx, scheduled.ID)
	if err != nil || converged.NeedsRecompute {
		t.Fatalf("expected successful repository convergence to clear recompute state, freeze=%+v err=%v", converged, err)
	}
	posts := h.freezeContextPosts()
	if len(posts) != 1 || posts[0].SHA != "aaa111bbb222" || posts[0].State != string(domain.CommitStatusFailure) {
		t.Fatalf("expected one repository-wide shared-head failure publication, got %+v", posts)
	}
	assertNoReconciliationJob(t, ctx, jobs.NewStore(h.database), h.repo.ID)
}

func TestStartScheduledNowRefreshesGenerationHeldByReconciliationWorker(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.EnqueueReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	workerClaim, claimed, err := jobStore.ClaimRepository(ctx, h.repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected worker claim, claim=%+v claimed=%v err=%v", workerClaim, claimed, err)
	}
	scheduled, err := freeze.NewService(h.database).CreateScheduled(ctx, freeze.ScheduleParams{
		RepositoryID: h.repo.ID,
		Branch:       "main",
		Reason:       "release window",
		StartsAt:     time.Now().UTC().Add(2 * time.Hour),
	}, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	started, err := runtimeFreezeStore(h).StartScheduledNow(ctx, scheduled.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if started.Status != domain.BranchFreezeStatusActive {
		t.Fatalf("expected committed active schedule, got %+v", started)
	}
	refreshed, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil || refreshed.Generation != workerClaim.Generation+1 || refreshed.LockedAt == nil {
		t.Fatalf("expected Start Now generation retained under worker lease, job=%+v err=%v", refreshed, err)
	}
	if completed, err := jobStore.CompleteClaim(ctx, workerClaim); err != nil || completed {
		t.Fatalf("old worker must not consume Start Now generation, completed=%v err=%v", completed, err)
	}
	if err := newRepositoryReconciliationRunner(jobStore, h.service, nil).RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	converged, err := freeze.NewService(h.database).Get(ctx, scheduled.ID)
	if err != nil || converged.NeedsRecompute {
		t.Fatalf("expected refreshed generation to converge and clear marker, freeze=%+v err=%v", converged, err)
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
}

func TestRepositoryReconciliationRunnerReconcilesActiveWriteAheadJob(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin); err != nil {
		t.Fatal(err)
	}
	jobStore := jobs.NewStore(h.database)
	runner := newRepositoryReconciliationRunner(jobStore, h.service, nil)

	if err := runner.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.setupContextPosts()) != 0 || len(h.freezeContextPosts()) != 1 {
		t.Fatalf("active write-ahead work must reconcile without setup post, got %+v", h.forge.posted)
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
}

func TestClaimantDoesNotClearConcurrentReadinessFailure(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.EnqueueReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := jobStore.ClaimRepository(ctx, h.repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected active reconciliation claim, claim=%+v claimed=%v err=%v", claim, claimed, err)
	}
	h.readiness.onRun = func() {
		h.setState(t, ctx, domain.EnforcementUnhealthy)
		if _, err := repository.NewStore(h.database).SetEnforcementFailure(ctx, h.repo.ID, domain.EnforcementFailureReadinessChecks, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if _, err := jobStore.EnsureReconciliationFailure(ctx, h.repo.ID, domain.EnforcementFailureReadinessChecks); err != nil {
			t.Fatal(err)
		}
	}
	before := time.Now().UTC()

	category, err := h.service.processReconciliationClaim(ctx, claim)
	if err == nil || category != domain.EnforcementFailureReadinessChecks {
		t.Fatalf("expected concurrent readiness transition to fence success, category=%q err=%v", category, err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailureReadinessChecks {
		t.Fatalf("expected newer unhealthy reason preserved, got %+v", repo)
	}
	job, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil || job.Generation != claim.Generation || job.LockedAt != nil || job.LastError != domain.EnforcementFailureReadinessChecks || job.RunAt.Before(before.Add(14*time.Second)) {
		t.Fatalf("expected preserved job with readiness backoff, job=%+v claim=%+v err=%v", job, claim, err)
	}
}

func TestRepositoryReconciliationRunnerFailureStaysUnhealthyAndBacksOff(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	h.forge.failSetupPost = true
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.EnqueueReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	runner := newRepositoryReconciliationRunner(jobStore, h.service, nil)
	if err := runner.RunDue(ctx); err == nil {
		t.Fatal("expected recovery failure")
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailureSetupStatusPost {
		t.Fatalf("expected unhealthy setup-post failure, got %+v", repo)
	}
	job, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Attempts != 1 || job.LockedAt != nil || job.LastError != domain.EnforcementFailureSetupStatusPost || job.RunAt.Before(before.Add(14*time.Second)) || job.RunAt.After(before.Add(17*time.Second)) {
		t.Fatalf("expected released 15-second retry, got %+v", job)
	}
}

func TestRepositoryReconciliationRunnerRemovesInapplicableReadyJob(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementReady)
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.EnqueueReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	if err := newRepositoryReconciliationRunner(jobStore, h.service, nil).RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if h.forge.requests != 0 {
		t.Fatalf("ready repository must not be activated automatically, forge requests=%d", h.forge.requests)
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
}

func TestManualRecoveryUsesDurableClaimAndBackoff(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.EnqueueReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := jobStore.ClaimRepository(ctx, h.repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected worker claim, claimed=%v err=%v", claimed, err)
	}
	_, err = h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("expected manual retry lease conflict, got %v", err)
	}
	if _, err := jobStore.RescheduleClaim(ctx, claim, domain.EnforcementFailurePublication); err != nil {
		t.Fatal(err)
	}

	h.forge.failSetupPost = true
	before := time.Now().UTC()
	_, err = h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if err == nil {
		t.Fatal("expected manual recovery failure")
	}
	job, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Attempts != 2 || job.LastError != domain.EnforcementFailureSetupStatusPost || job.RunAt.Before(before.Add(29*time.Second)) {
		t.Fatalf("expected attempt-two manual backoff, got %+v", job)
	}
}

func TestThawFailureBeforeExceptionCommitDoesNotCreateRecoveryJob(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	pr := domain.PullRequest{RepositoryID: h.repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "aaa111bbb222", URL: "https://codeberg.org/example/pulls/42"}
	service := runtimeThawService(h, []domain.PullRequest{pr})
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin); err != nil {
		t.Fatal(err)
	}
	if err := jobs.NewStore(h.database).RemoveReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	h.forge.failPulls = true
	_, err := service.ApproveThaw(ctx, statusresult.ThawApprovalParams{RepositoryID: h.repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "hotfix"}, h.admin)
	if err == nil {
		t.Fatal("expected pre-commit synchronization failure")
	}
	var exceptions int
	if err := h.database.QueryRowContext(ctx, `SELECT count(*) FROM thaw_exceptions WHERE repository_id = ?`, h.repo.ID).Scan(&exceptions); err != nil {
		t.Fatal(err)
	}
	if exceptions != 0 {
		t.Fatalf("expected no committed exception, got %d", exceptions)
	}
	assertNoReconciliationJob(t, ctx, jobs.NewStore(h.database), h.repo.ID)
	if repo := h.currentRepo(t, ctx); repo.EnforcementState != domain.EnforcementActive {
		t.Fatalf("pre-commit thaw failure must not mark unhealthy, got %+v", repo)
	}
}

func TestSharedHeadThawPublicationFailureRetriesWithoutDuplicatingExceptions(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	freezes := freeze.NewService(h.database)
	if _, err := freezes.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "main"}, h.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := freezes.CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "develop", Reason: "develop"}, h.admin); err != nil {
		t.Fatal(err)
	}
	if err := jobs.NewStore(h.database).RemoveReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	prs := []domain.PullRequest{
		{RepositoryID: h.repo.ID, Index: 42, State: "open", TargetBranch: "main", HeadSHA: "aaa111bbb222", URL: "https://codeberg.org/example/pulls/42"},
		{RepositoryID: h.repo.ID, Index: 43, State: "open", TargetBranch: "develop", HeadSHA: "aaa111bbb222", URL: "https://codeberg.org/example/pulls/43"},
	}
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(42, "open", "main", "AAA111BBB222"),
		newAppPullRequestResponse(43, "open", "develop", "AAA111BBB222"),
	}
	service := runtimeThawService(h, prs)
	h.forge.failFreezePost = true
	confirmation := &statusresult.ThawApprovalConfirmation{HeadSHA: prs[0].HeadSHA, AffectedSignature: thawApprovalAffectedSignature(prs)}
	_, err := service.ApproveThaw(ctx, statusresult.ThawApprovalParams{RepositoryID: h.repo.ID, PullRequestIndex: 42, TargetBranch: "main", Reason: "hotfix", Confirmation: confirmation}, h.admin)
	if err == nil {
		t.Fatal("expected publication failure after shared exceptions commit")
	}
	assertRuntimeFailureState(t, ctx, h, domain.EnforcementFailurePublication)
	var before int
	if err := h.database.QueryRowContext(ctx, `SELECT count(*) FROM thaw_exceptions WHERE repository_id = ?`, h.repo.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 2 {
		t.Fatalf("expected two persisted shared-head exceptions, got %d", before)
	}
	h.forge.failFreezePost = false
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.MakeDueNow(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	if err := newRepositoryReconciliationRunner(jobStore, h.service, nil).RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := h.database.QueryRowContext(ctx, `SELECT count(*) FROM thaw_exceptions WHERE repository_id = ?`, h.repo.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("recovery must evaluate persisted policy without recreating exceptions: before=%d after=%d", before, after)
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
}

func TestActiveWebhookPublicationFailureCreatesDurableRecovery(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release"}, h.admin); err != nil {
		t.Fatal(err)
	}
	jobStore := jobs.NewStore(h.database)
	if err := jobStore.RemoveReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	processor := webhook.NewPullRequestProcessor(repository.NewStore(h.database), pullrequest.NewStore(h.database), h.service.statuses, h.service.publisher)
	processor.SetConvergence(newRuntimeConvergenceService(jobStore, h.service))
	h.forge.failFreezePost = true
	body := []byte(fmt.Sprintf(`{"action":"opened","repository":{"owner":{"login":"taua-almeida"},"name":"thawguard","clone_url":%q},"pull_request":{"number":42,"title":"Release","state":"open","html_url":%q,"base":{"ref":"main"},"head":{"sha":"AAA111BBB222"}}}`, h.repo.BaseURL+"/taua-almeida/thawguard.git", h.repo.BaseURL+"/taua-almeida/thawguard/pulls/42"))

	if _, err := processor.Process(ctx, body); err == nil {
		t.Fatal("expected active webhook publication failure")
	}
	assertRuntimeFailureState(t, ctx, h, domain.EnforcementFailurePublication)
	if _, err := jobStore.GetReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	postedBefore := len(h.freezeContextPosts())
	h.forge.failFreezePost = false
	if _, err := processor.Process(ctx, body); err != nil {
		t.Fatalf("expected unhealthy webhook to refresh cache without publication: %v", err)
	}
	if len(h.freezeContextPosts()) != postedBefore {
		t.Fatalf("unhealthy webhook must not publish, before=%d after=%d", postedBefore, len(h.freezeContextPosts()))
	}
	if _, err := jobStore.GetReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatalf("unhealthy webhook must preserve pending recovery: %v", err)
	}
}

func TestActiveWebhookDefersPublicationAndRefreshesWorkWhenWorkerOwnsLease(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	jobStore := jobs.NewStore(h.database)
	if _, err := jobStore.EnqueueReconciliation(ctx, h.repo.ID); err != nil {
		t.Fatal(err)
	}
	workerClaim, claimed, err := jobStore.ClaimRepository(ctx, h.repo.ID)
	if err != nil || !claimed {
		t.Fatalf("expected worker claim, claim=%+v claimed=%v err=%v", workerClaim, claimed, err)
	}
	pulls := pullrequest.NewStore(h.database)
	processor := webhook.NewPullRequestProcessor(repository.NewStore(h.database), pulls, h.service.statuses, h.service.publisher)
	processor.SetConvergence(newRuntimeConvergenceService(jobStore, h.service))
	body := []byte(fmt.Sprintf(`{"action":"opened","repository":{"owner":{"login":"taua-almeida"},"name":"thawguard","clone_url":%q},"pull_request":{"number":42,"title":"Release","state":"open","html_url":%q,"base":{"ref":"main"},"head":{"sha":"AAA111BBB222"}}}`, h.repo.BaseURL+"/taua-almeida/thawguard.git", h.repo.BaseURL+"/taua-almeida/thawguard/pulls/42"))

	result, err := processor.Process(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if result.Recomputed || len(h.freezeContextPosts()) != 0 {
		t.Fatalf("webhook must defer publication to lease owner, result=%+v posts=%+v", result, h.freezeContextPosts())
	}
	if _, err := pulls.Get(ctx, h.repo.ID, 42); err != nil {
		t.Fatalf("expected current webhook state cached before delegation: %v", err)
	}
	refreshed, err := jobStore.GetReconciliation(ctx, h.repo.ID)
	if err != nil || refreshed.Generation != workerClaim.Generation+2 || refreshed.LockedAt == nil {
		t.Fatalf("expected newer durable generation under worker lease, job=%+v err=%v", refreshed, err)
	}
	if completed, err := jobStore.CompleteClaim(ctx, workerClaim); err != nil || completed {
		t.Fatalf("old worker must not consume refreshed webhook work, completed=%v err=%v", completed, err)
	}
	if err := newRepositoryReconciliationRunner(jobStore, h.service, nil).RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.freezeContextPosts()) != 1 {
		t.Fatalf("expected one publication from refreshed worker pass, got %+v", h.freezeContextPosts())
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
}

func TestInvalidWebhookDoesNotCreateRecoveryJob(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	jobStore := jobs.NewStore(h.database)
	processor := webhook.NewPullRequestProcessor(repository.NewStore(h.database), pullrequest.NewStore(h.database), h.service.statuses, h.service.publisher)
	processor.SetConvergence(newRuntimeConvergenceService(jobStore, h.service))
	if _, err := processor.Process(ctx, []byte(`{"action":"opened"}`)); err == nil {
		t.Fatal("expected invalid webhook rejection")
	}
	assertNoReconciliationJob(t, ctx, jobStore, h.repo.ID)
	if repo := h.currentRepo(t, ctx); repo.EnforcementState != domain.EnforcementActive {
		t.Fatalf("invalid webhook must not mark unhealthy, got %+v", repo)
	}
}

func assertNoReconciliationJob(t *testing.T, ctx context.Context, store *jobs.Store, repositoryID int64) {
	t.Helper()
	if _, err := store.GetReconciliation(ctx, repositoryID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected no reconciliation job, got %v", err)
	}
}

func runtimeFreezeStore(h *enforcementHarness) *freezeRecomputingStore {
	store := newFreezeRecomputingStore(freeze.NewService(h.database), repository.NewStore(h.database), h.service.syncer, h.service.pullRequests, h.service.statuses, h.service.publisher)
	store.convergence = newRuntimeConvergenceService(jobs.NewStore(h.database), h.service)
	return store
}

func assertRuntimeFailureState(t *testing.T, ctx context.Context, h *enforcementHarness, category string) {
	t.Helper()
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != category || repo.EnforcementFailedAt == nil {
		t.Fatalf("expected unhealthy repository with %q, got %+v", category, repo)
	}
	var count int
	if err := h.database.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE type = ? AND repository_id = ?`, jobs.ReconcileRepositoryEnforcement, h.repo.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one repository reconciliation job, got %d", count)
	}
	job, err := jobs.NewStore(h.database).GetReconciliation(ctx, h.repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := h.database.QueryRowContext(ctx, `SELECT payload_json FROM jobs WHERE id = ?`, job.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if job.LastError != category || payload != "{}" || strings.Contains(job.LastError, "token") {
		t.Fatalf("expected only stable category and empty payload, job=%+v payload=%q", job, payload)
	}
}

func runtimeThawService(h *enforcementHarness, current []domain.PullRequest) *thawApprovalService {
	pulls := pullrequest.NewStore(h.database)
	exceptions := thawexception.NewService(h.database)
	freezes := freeze.NewService(h.database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(h.database), freezes, exceptions, pulls)
	client := &thawApprovalTestForgeClient{pullRequests: current}
	service := newThawApprovalService(repository.NewStore(h.database), h.service.tokens, pulls, exceptions, freezes, statuses, h.service.publisher, h.service.syncer, func(domain.Repository, string) (thawApprovalForgeClient, error) {
		return client, nil
	})
	service.convergence = newRuntimeConvergenceService(jobs.NewStore(h.database), h.service)
	return service
}
