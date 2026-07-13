package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

type failingStatusRunner struct{}

func (failingStatusRunner) RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error) {
	return statusresult.Result{}, errors.New("policy evaluation exploded")
}

func (h *enforcementHarness) setStoredFailure(t *testing.T, ctx context.Context, reason string) time.Time {
	t.Helper()
	failedAt := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	if _, err := repository.NewStore(h.database).SetEnforcementFailure(ctx, h.repo.ID, reason, failedAt); err != nil {
		t.Fatal(err)
	}
	return failedAt
}

func (h *enforcementHarness) freezeContextPosts() []postedEnforcementStatus {
	posts := make([]postedEnforcementStatus, 0)
	for _, post := range h.forge.posted {
		if post.Context == domain.RequiredStatusContext {
			posts = append(posts, post)
		}
	}
	return posts
}

func (h *enforcementHarness) setupContextPosts() []postedEnforcementStatus {
	posts := make([]postedEnforcementStatus, 0)
	for _, post := range h.forge.posted {
		if post.Context == domain.SetupStatusContext {
			posts = append(posts, post)
		}
	}
	return posts
}

func failingReadinessResults() []setupcheck.Result {
	return []setupcheck.Result{
		{Name: setupcheck.CheckBranchProtectionEnabled, Status: setupcheck.StatusFailed, Description: "protection removed"},
		{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "untested"},
	}
}

func TestReconcileEnforcementOnlyAllowedFromActive(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	for _, state := range []domain.EnforcementState{domain.EnforcementSetupIncomplete, domain.EnforcementReady, domain.EnforcementUnhealthy} {
		h.setState(t, ctx, state)
		_, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
		if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "only available while repository enforcement is active") {
			t.Fatalf("expected %s reconcile rejection, got %v", state, err)
		}
		if repo := h.currentRepo(t, ctx); repo.EnforcementState != state {
			t.Fatalf("expected state %s to stay untouched, got %s", state, repo.EnforcementState)
		}
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request for rejected reconcile, got %d", h.forge.requests)
	}
}

func TestReconcileEnforcementSuccessRepublishesPolicyAndClearsFailure(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(42, "open", "main", "AAA111BBB222"),
		newAppPullRequestResponse(43, "open", "develop", "CCC333DDD444"),
	}
	h.setState(t, ctx, domain.EnforcementActive)
	h.setStoredFailure(t, ctx, domain.EnforcementFailurePublication)

	updated, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive {
		t.Fatalf("expected repository to stay active, got %s", updated.EnforcementState)
	}
	if updated.EnforcementFailureReason != "" || updated.EnforcementFailedAt != nil {
		t.Fatalf("expected cleared failure state after success, got %+v", updated)
	}
	if setupPosts := h.setupContextPosts(); len(setupPosts) != 0 {
		t.Fatalf("ordinary reconciliation must not post %s, got %+v", domain.SetupStatusContext, setupPosts)
	}
	statuses := map[string]string{}
	for _, post := range h.freezeContextPosts() {
		statuses[post.SHA] = post.State
	}
	if len(statuses) != 2 || statuses["aaa111bbb222"] != string(domain.CommitStatusFailure) || statuses["ccc333ddd444"] != string(domain.CommitStatusSuccess) {
		t.Fatalf("expected republished frozen failure and unfrozen success, got %+v", h.forge.posted)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementReconciled)
	if len(events) != 1 {
		t.Fatalf("expected one reconcile success audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"open_pull_request_count":"2"`) || !strings.Contains(details, `"statuses_posted":"2"`) ||
		!strings.Contains(details, `"managed_branch_count":"2"`) || !strings.Contains(details, `"enforcement_state":"active"`) {
		t.Fatalf("unexpected reconcile audit details: %s", details)
	}
	if strings.Contains(details, enforcementTestToken) {
		t.Fatalf("token leaked into reconcile audit: %s", details)
	}

	// A duplicate reconcile after success is idempotent: publication intents
	// are keyed by repository, SHA, context, and mode.
	again, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil || again.EnforcementState != domain.EnforcementActive {
		t.Fatalf("expected idempotent second reconcile, got repo=%+v err=%v", again, err)
	}
}

func TestReconcileEnforcementKeepsRepositoryWideSharedHeadPolicy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(1, "open", "main", "ABC123"),
		newAppPullRequestResponse(2, "open", "develop", "ABC123"),
	}
	h.setState(t, ctx, domain.EnforcementActive)

	if _, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	posts := h.freezeContextPosts()
	if len(posts) != 1 || posts[0].SHA != "abc123" || posts[0].State != string(domain.CommitStatusFailure) {
		t.Fatalf("expected one repository-wide failure for shared head, got %+v", posts)
	}
}

func TestReconcileEnforcementRespectsCurrentThawException(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := thawexception.NewService(h.database).Approve(ctx, thawexception.ApproveParams{RepositoryID: h.repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "aaa111bbb222", Reason: "hotfix"}, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	h.setState(t, ctx, domain.EnforcementActive)

	if _, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	posts := h.freezeContextPosts()
	if len(posts) != 1 || posts[0].SHA != "aaa111bbb222" || posts[0].State != string(domain.CommitStatusSuccess) {
		t.Fatalf("expected thaw exception to reconcile to success, got %+v", posts)
	}
}

func TestReconcileEnforcementReadinessFailureBecomesUnhealthyBeforeAnyForgeCall(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.readiness.results = failingReadinessResults()

	_, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "marked unhealthy") {
		t.Fatalf("expected reconcile readiness rejection, got %v", err)
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request after readiness failure, got %d", h.forge.requests)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy {
		t.Fatalf("expected unhealthy repository, got %s", repo.EnforcementState)
	}
	if repo.EnforcementFailureReason != domain.EnforcementFailureReadinessChecks || repo.EnforcementFailedAt == nil {
		t.Fatalf("expected stored readiness failure, got %+v", repo)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementReconcileFail)
	if len(events) != 1 || !strings.Contains(events[0].DetailsJSON, domain.EnforcementFailureReadinessChecks) {
		t.Fatalf("expected reconcile failure audit, got %+v", events)
	}
}

func TestReconcileEnforcementOperationalReadinessErrorBecomesUnhealthySafely(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	h.readiness.results = nil
	h.readiness.err = errors.New("network exploded with " + enforcementTestToken)

	_, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized operational readiness failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailureReadinessChecks {
		t.Fatalf("expected unhealthy repository with safe reason, got %+v", repo)
	}
	if len(h.freezeContextPosts()) != 0 {
		t.Fatalf("expected no publication after operational readiness error, got %+v", h.forge.posted)
	}
}

func TestReconcileEnforcementSyncFailureBecomesUnhealthyWithoutStalePublication(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementActive)
	// Stale cached PR that must not be republished after the sync failure.
	if _, err := pullrequest.NewStore(h.database).Upsert(ctx, domain.PullRequest{RepositoryID: h.repo.ID, Index: 9, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}); err != nil {
		t.Fatal(err)
	}
	h.forge.failPulls = true

	_, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized sync failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailureOpenPRSync {
		t.Fatalf("expected unhealthy repository with sync reason, got %+v", repo)
	}
	if len(h.freezeContextPosts()) != 0 {
		t.Fatalf("expected no stale-cache publication, got %+v", h.forge.posted)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementReconcileFail)
	if len(events) != 1 || !strings.Contains(events[0].DetailsJSON, domain.EnforcementFailureOpenPRSync) {
		t.Fatalf("expected reconcile failure audit for sync, got %+v", events)
	}
}

func TestReconcileEnforcementEvaluationFailureBecomesUnhealthy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	h.setState(t, ctx, domain.EnforcementActive)
	h.service.statuses = failingStatusRunner{}

	_, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "evaluating") {
		t.Fatalf("expected evaluation failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailureEvaluation {
		t.Fatalf("expected unhealthy repository with evaluation reason, got %+v", repo)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementReconcileFail)
	if len(events) != 1 {
		t.Fatalf("expected one reconcile failure audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"statuses_attempted":"1"`) || !strings.Contains(details, `"statuses_posted":"0"`) || !strings.Contains(details, `"statuses_failed":"1"`) {
		t.Fatalf("expected truthful attempted/failed counts, got %s", details)
	}
	if events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementReconciled); len(events) != 0 {
		t.Fatalf("expected no reconcile success audit, got %+v", events)
	}
}

func TestReconcileEnforcementPublicationFailureBecomesUnhealthyKeepingPartialPosts(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(42, "open", "main", "AAA111BBB222"),
		newAppPullRequestResponse(43, "open", "main", "CCC333DDD444"),
	}
	h.setState(t, ctx, domain.EnforcementActive)
	h.forge.failFreezePostSHA = "ccc333ddd444"

	_, err := h.service.ReconcileEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "not rolled back") {
		t.Fatalf("expected publication failure with rollback note, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailurePublication {
		t.Fatalf("expected unhealthy repository with publication reason, got %+v", repo)
	}
	if job, err := jobs.NewStore(h.database).GetReconciliation(ctx, h.repo.ID); err != nil || job.Generation < 1 {
		t.Fatalf("expected reconciliation failure to enqueue durable work, job=%+v err=%v", job, err)
	}
	posts := h.freezeContextPosts()
	if len(posts) != 1 || posts[0].SHA != "aaa111bbb222" {
		t.Fatalf("expected the first group's post to stay, got %+v", posts)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementReconcileFail)
	if len(events) != 1 {
		t.Fatalf("expected one reconcile failure audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"statuses_attempted":"2"`) || !strings.Contains(details, `"statuses_posted":"1"`) || !strings.Contains(details, `"statuses_failed":"1"`) {
		t.Fatalf("expected truthful partial publication counts, got %s", details)
	}
}

func TestRecoverEnforcementOnlyAllowedFromUnhealthy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	for _, state := range []domain.EnforcementState{domain.EnforcementSetupIncomplete, domain.EnforcementReady, domain.EnforcementActive} {
		h.setState(t, ctx, state)
		_, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
		if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "only available for an unhealthy repository") {
			t.Fatalf("expected %s recovery rejection, got %v", state, err)
		}
		if repo := h.currentRepo(t, ctx); repo.EnforcementState != state {
			t.Fatalf("expected state %s to stay untouched, got %s", state, repo.EnforcementState)
		}
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request for rejected recovery, got %d", h.forge.requests)
	}
}

func TestRecoverEnforcementSuccessBecomesActiveAndClearsFailure(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	staleFailedAt := h.setStoredFailure(t, ctx, domain.EnforcementFailurePublication)

	updated, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive {
		t.Fatalf("expected active repository after recovery, got %s", updated.EnforcementState)
	}
	if updated.EnforcementFailureReason != "" || updated.EnforcementFailedAt != nil {
		t.Fatalf("expected cleared failure state, got %+v", updated)
	}
	if updated.StatusPostVerifiedAt == nil || !updated.StatusPostVerifiedAt.After(staleFailedAt) {
		t.Fatalf("expected fresh status-post verification evidence, got %+v", updated.StatusPostVerifiedAt)
	}
	setupPosts := h.setupContextPosts()
	if len(setupPosts) != 1 || setupPosts[0].SHA != enforcementTestHeadSHA || setupPosts[0].State != string(domain.CommitStatusSuccess) {
		t.Fatalf("expected one controlled setup post on the current head, got %+v", setupPosts)
	}
	posts := h.freezeContextPosts()
	if len(posts) != 1 || posts[0].SHA != "aaa111bbb222" || posts[0].State != string(domain.CommitStatusFailure) {
		t.Fatalf("expected republished frozen-branch failure, got %+v", posts)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementRecovered)
	if len(events) != 1 {
		t.Fatalf("expected one recovery success audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"enforcement_state":"active"`) || !strings.Contains(details, `"statuses_posted":"1"`) || !strings.Contains(details, `"head_sha":"feedbeefcafe"`) {
		t.Fatalf("unexpected recovery audit details: %s", details)
	}

	// A duplicate recovery POST after success is safely rejected by the state gate.
	if _, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin); !repository.IsValidationError(err) {
		t.Fatalf("expected duplicate recovery rejection, got %v", err)
	}
}

func TestRecoverEnforcementWithNoOpenPullRequestsBecomesActive(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	h.setStoredFailure(t, ctx, domain.EnforcementFailureReadinessChecks)

	updated, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive || updated.EnforcementFailureReason != "" {
		t.Fatalf("expected active repository without failure state, got %+v", updated)
	}
	if len(h.setupContextPosts()) != 1 || len(h.freezeContextPosts()) != 0 {
		t.Fatalf("expected only the controlled setup post, got %+v", h.forge.posted)
	}
}

func TestRecoverEnforcementReadinessFailureStaysUnhealthy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	h.setStoredFailure(t, ctx, domain.EnforcementFailurePublication)
	h.readiness.results = failingReadinessResults()

	_, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "remains unhealthy") {
		t.Fatalf("expected recovery readiness rejection, got %v", err)
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no setup post, sync, or publication after readiness failure, got %d requests", h.forge.requests)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy {
		t.Fatalf("expected repository to remain unhealthy, got %s", repo.EnforcementState)
	}
	if repo.EnforcementFailureReason != domain.EnforcementFailureReadinessChecks || repo.EnforcementFailedAt == nil {
		t.Fatalf("expected updated stored failure, got %+v", repo)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementRecoverFail)
	if len(events) != 1 || !strings.Contains(events[0].DetailsJSON, domain.EnforcementFailureReadinessChecks) {
		t.Fatalf("expected recovery failure audit, got %+v", events)
	}
}

func TestRecoverEnforcementSetupPostFailureStaysUnhealthy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	h.forge.failSetupPost = true

	_, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized setup post failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy {
		t.Fatalf("expected repository to remain unhealthy, got %s", repo.EnforcementState)
	}
	if repo.EnforcementFailureReason != domain.EnforcementFailureSetupStatusPost {
		t.Fatalf("expected setup post failure reason, got %q", repo.EnforcementFailureReason)
	}
	if repo.StatusPostVerifiedAt != nil {
		t.Fatalf("expected disproven verification evidence to be cleared, got %+v", repo.StatusPostVerifiedAt)
	}
	if len(h.freezeContextPosts()) != 0 {
		t.Fatalf("expected no real publication after setup post failure, got %+v", h.forge.posted)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementRecoverFail)
	if len(events) != 1 || strings.Contains(events[0].DetailsJSON, "exploded") {
		t.Fatalf("expected sanitized recovery failure audit, got %+v", events)
	}
}

func TestRecoverEnforcementSyncFailureStaysUnhealthyWithoutStalePublication(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	if _, err := pullrequest.NewStore(h.database).Upsert(ctx, domain.PullRequest{RepositoryID: h.repo.ID, Index: 9, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}); err != nil {
		t.Fatal(err)
	}
	h.forge.failPulls = true

	_, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized sync failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailureOpenPRSync {
		t.Fatalf("expected unhealthy repository with sync reason, got %+v", repo)
	}
	if len(h.freezeContextPosts()) != 0 {
		t.Fatalf("expected no stale-cache publication, got %+v", h.forge.posted)
	}
}

func TestRecoverEnforcementPublicationFailureStaysUnhealthy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	h.setState(t, ctx, domain.EnforcementUnhealthy)
	h.forge.failFreezePost = true

	_, err := h.service.RecoverEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "remains unhealthy") {
		t.Fatalf("expected recovery publication failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy || repo.EnforcementFailureReason != domain.EnforcementFailurePublication {
		t.Fatalf("expected unhealthy repository with publication reason, got %+v", repo)
	}
	// The real attempt history stays in the publication tables.
	assertAppTableCount(t, h.database, "status_publication_attempts", 1)
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementRecoverFail)
	if len(events) != 1 || !strings.Contains(events[0].DetailsJSON, `"statuses_failed":"1"`) {
		t.Fatalf("expected truthful recovery failure audit, got %+v", events)
	}
	if events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementRecovered); len(events) != 0 {
		t.Fatalf("expected no recovery success audit, got %+v", events)
	}
}

func TestActivateEnforcementSuccessClearsStoredFailure(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	h.setStoredFailure(t, ctx, domain.EnforcementFailurePublication)

	updated, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive || updated.EnforcementFailureReason != "" || updated.EnforcementFailedAt != nil {
		t.Fatalf("expected activation to clear stored failure, got %+v", updated)
	}
}
