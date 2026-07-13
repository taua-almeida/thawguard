package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

const enforcementTestToken = "live-status-token-123"
const enforcementTestHeadSHA = "feedbeefcafe123456"

type postedEnforcementStatus struct {
	SHA     string
	State   string
	Context string
}

type enforcementForgeState struct {
	headSHA        string
	openPRs        []forgejoPullRequestResponse
	posted         []postedEnforcementStatus
	failBranchHead bool
	failSetupPost  bool
	failFreezePost bool
	// failFreezePostSHA fails only the freeze-status post for this exact
	// (lowercase) head SHA so partial publication can be exercised.
	failFreezePostSHA string
	failPulls         bool
	requests          int
}

type fakeEnforcementReadiness struct {
	results []setupcheck.Result
	err     error
	runs    int
}

func (f *fakeEnforcementReadiness) Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error) {
	f.runs++
	return f.results, f.err
}

func okReadinessResults() []setupcheck.Result {
	return []setupcheck.Result{
		{Name: setupcheck.CheckStatusTokenConfigured, Status: setupcheck.StatusOK, Description: "ok"},
		{Name: setupcheck.CheckPullRequestReadAccess, Status: setupcheck.StatusOK, Description: "ok"},
		{Name: setupcheck.CheckRecentVerifiedPullRequestWebhook, Status: setupcheck.StatusOK, Description: "ok"},
		{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "untested"},
		{Name: setupcheck.CheckBranchProtectionEnabled, Status: setupcheck.StatusOK, Description: "ok"},
	}
}

type enforcementHarness struct {
	database  *sql.DB
	repo      domain.Repository
	service   *enforcementService
	forge     *enforcementForgeState
	readiness *fakeEnforcementReadiness
	admin     domain.Actor
}

func newEnforcementHarness(t *testing.T, ctx context.Context) *enforcementHarness {
	t.Helper()
	state := &enforcementForgeState{headSHA: enforcementTestHeadSHA}
	forgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.requests++
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/branches/main":
			if state.failBranchHead {
				http.Error(w, enforcementTestToken+" head lookup exploded", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "commit": map[string]string{"id": state.headSHA}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/taua-almeida/thawguard/pulls":
			if state.failPulls {
				http.Error(w, enforcementTestToken+" pull listing exploded", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(state.openPRs)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/repos/taua-almeida/thawguard/statuses/"):
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			postSHA := strings.TrimPrefix(r.URL.Path, "/api/v1/repos/taua-almeida/thawguard/statuses/")
			if (state.failSetupPost && body["context"] == domain.SetupStatusContext) ||
				(state.failFreezePost && body["context"] == domain.RequiredStatusContext) ||
				(state.failFreezePostSHA != "" && body["context"] == domain.RequiredStatusContext && postSHA == state.failFreezePostSHA) {
				http.Error(w, enforcementTestToken+" status post exploded", http.StatusInternalServerError)
				return
			}
			state.posted = append(state.posted, postedEnforcementStatus{
				SHA:     postSHA,
				State:   body["state"],
				Context: body["context"],
			})
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected forge request %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(forgeServer.Close)

	database := newAppTestDB(t, ctx)
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, newAppTestSecretStore(t))
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := repositorySetup.Create(ctx, repository.CreateParams{Forge: "forgejo", BaseURL: forgeServer.URL, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositorySetup.SetStatusToken(ctx, repo.ID, enforcementTestToken, admin); err != nil {
		t.Fatal(err)
	}

	pullRequests := pullrequest.NewStore(database)
	freezes := freeze.NewService(database)
	statuses := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freezes, thawexception.NewService(database), pullRequests)
	publications := statuspublication.NewStore(database)
	publisher := newRuntimeStatusPublisher(publications, repository.NewStore(database), repositorySetup)
	syncer := newForgeOpenPullRequestSyncer(repository.NewStore(database), repositorySetup, pullRequests, forgejoPullRequestClientForRepository)
	readiness := &fakeEnforcementReadiness{results: okReadinessResults()}
	service := newEnforcementService(database, repositorySetup, readiness, forgejoEnforcementClientForRepository, syncer, pullRequests, statuses, publisher)
	return &enforcementHarness{database: database, repo: repo, service: service, forge: state, readiness: readiness, admin: admin}
}

func (h *enforcementHarness) setState(t *testing.T, ctx context.Context, state domain.EnforcementState) {
	t.Helper()
	if _, err := repository.NewStore(h.database).SetEnforcementState(ctx, h.repo.ID, state); err != nil {
		t.Fatal(err)
	}
}

func (h *enforcementHarness) currentRepo(t *testing.T, ctx context.Context) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(h.database).Get(ctx, h.repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func (h *enforcementHarness) auditEvents(t *testing.T, ctx context.Context, action string) []audit.Event {
	t.Helper()
	events, err := audit.NewStore(h.database).List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	matched := make([]audit.Event, 0)
	for _, event := range events {
		if event.Action == action {
			matched = append(matched, event)
		}
	}
	return matched
}

func TestVerifyStatusPostingRejectsIncompleteReadinessBeforeAnyForgeCall(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.readiness.results = []setupcheck.Result{
		{Name: setupcheck.CheckStatusTokenConfigured, Status: setupcheck.StatusFailed, Description: "missing"},
		{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "untested"},
	}

	_, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), setupcheck.CheckStatusTokenConfigured) {
		t.Fatalf("expected readiness validation error naming the failing check, got %v", err)
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request before readiness passes, got %d", h.forge.requests)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementSetupIncomplete || repo.StatusPostVerifiedAt != nil {
		t.Fatalf("expected untouched setup-incomplete repository, got %+v", repo)
	}
	if events := h.auditEvents(t, ctx, audit.ActionRepositoryStatusPostVerifyFailed); len(events) != 0 {
		t.Fatalf("expected no failed-verification audit before a post attempt, got %+v", events)
	}
}

func TestVerifyStatusPostingBlocksOnStaleWebhookWarning(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.readiness.results = []setupcheck.Result{
		{Name: setupcheck.CheckStatusTokenConfigured, Status: setupcheck.StatusOK, Description: "ok"},
		{Name: setupcheck.CheckRecentVerifiedPullRequestWebhook, Status: setupcheck.StatusWarning, Description: "stale"},
		{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "untested"},
	}

	_, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), setupcheck.CheckRecentVerifiedPullRequestWebhook) {
		t.Fatalf("expected stale webhook warning to block verification, got %v", err)
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request, got %d", h.forge.requests)
	}
}

func TestVerifyStatusPostingSuccessPostsSetupContextAndBecomesReady(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)

	updated, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementReady || updated.StatusPostVerifiedAt == nil {
		t.Fatalf("expected ready repository with verification evidence, got %+v", updated)
	}
	if len(h.forge.posted) != 1 {
		t.Fatalf("expected exactly one controlled status post, got %+v", h.forge.posted)
	}
	post := h.forge.posted[0]
	if post.Context != domain.SetupStatusContext || post.State != string(domain.CommitStatusSuccess) || post.SHA != enforcementTestHeadSHA {
		t.Fatalf("expected thawguard/setup success on the exact default branch head, got %+v", post)
	}
	if h.readiness.runs != 1 {
		t.Fatalf("expected readiness rerun, got %d", h.readiness.runs)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryStatusPostVerified)
	if len(events) != 1 {
		t.Fatalf("expected one verified audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"enforcement_state":"ready"`) || !strings.Contains(details, `"head_sha":"feedbeefcafe"`) {
		t.Fatalf("unexpected verified audit details: %s", details)
	}
	if strings.Contains(details, enforcementTestToken) {
		t.Fatalf("token leaked into audit details: %s", details)
	}
	// The controlled setup post is not a freeze-policy decision: no status
	// result or publication rows may be fabricated for it.
	assertAppTableCount(t, h.database, "status_results", 0)
	assertAppTableCount(t, h.database, "status_publication_intents", 0)
	assertAppTableCount(t, h.database, "status_publication_attempts", 0)
}

func TestVerifyStatusPostingFailureStaysSetupIncompleteWithSanitizedEvidence(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.forge.failSetupPost = true

	_, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) {
		t.Fatalf("expected safe operator-facing validation error, got %v", err)
	}
	if strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("token leaked into verification error: %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementSetupIncomplete || repo.StatusPostVerifiedAt != nil {
		t.Fatalf("expected setup-incomplete without verification evidence, got %+v", repo)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryStatusPostVerifyFailed)
	if len(events) != 1 {
		t.Fatalf("expected one failed-verification audit event, got %+v", events)
	}
	if strings.Contains(events[0].DetailsJSON, enforcementTestToken) || strings.Contains(events[0].DetailsJSON, "exploded") {
		t.Fatalf("failed audit details must stay generic and token-free: %s", events[0].DetailsJSON)
	}
	assertAppTableCount(t, h.database, "status_results", 0)

	// Retry after remediation succeeds and transitions to ready.
	h.forge.failSetupPost = false
	updated, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
	if err != nil || updated.EnforcementState != domain.EnforcementReady {
		t.Fatalf("expected retry to become ready, got repo=%+v err=%v", updated, err)
	}
}

func TestVerifyStatusPostingExplicitRetryFromReady(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}

	updated, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
	if err != nil || updated.EnforcementState != domain.EnforcementReady || updated.StatusPostVerifiedAt == nil {
		t.Fatalf("expected explicit ready retry to stay ready, got repo=%+v err=%v", updated, err)
	}
	if len(h.forge.posted) != 2 {
		t.Fatalf("expected a second controlled post on retry, got %+v", h.forge.posted)
	}
}

func TestVerifyStatusPostingRejectsActiveAndUnhealthyStates(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	for _, state := range []domain.EnforcementState{domain.EnforcementActive, domain.EnforcementUnhealthy} {
		h.setState(t, ctx, state)
		_, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin)
		if !repository.IsValidationError(err) {
			t.Fatalf("expected %s verification rejection, got %v", state, err)
		}
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request for rejected states, got %d", h.forge.requests)
	}
}

func TestActivateEnforcementOnlyAllowedFromReady(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	for _, state := range []domain.EnforcementState{domain.EnforcementSetupIncomplete, domain.EnforcementActive, domain.EnforcementUnhealthy} {
		h.setState(t, ctx, state)
		_, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
		if !repository.IsValidationError(err) || !strings.Contains(err.Error(), "ready state") {
			t.Fatalf("expected %s activation rejection, got %v", state, err)
		}
		if repo := h.currentRepo(t, ctx); repo.EnforcementState != state {
			t.Fatalf("expected state %s to stay untouched, got %s", state, repo.EnforcementState)
		}
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request for rejected activation, got %d", h.forge.requests)
	}
}

func TestActivateEnforcementRejectsReadinessDrift(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.setState(t, ctx, domain.EnforcementReady)
	h.readiness.results = []setupcheck.Result{
		{Name: setupcheck.CheckRequiredThawguardFreezeContextConfigured, Status: setupcheck.StatusFailed, Description: "drifted"},
		{Name: setupcheck.CheckStatusPostingUntested, Status: setupcheck.StatusWarning, Description: "untested"},
	}

	_, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || !strings.Contains(err.Error(), setupcheck.CheckRequiredThawguardFreezeContextConfigured) {
		t.Fatalf("expected drift rejection, got %v", err)
	}
	if h.forge.requests != 0 {
		t.Fatalf("expected no forge request after drift, got %d", h.forge.requests)
	}
	if repo := h.currentRepo(t, ctx); repo.EnforcementState != domain.EnforcementReady {
		t.Fatalf("expected repository to stay ready, got %s", repo.EnforcementState)
	}
}

func TestActivateEnforcementSetupPostFailureReturnsToSetupIncomplete(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.failSetupPost = true

	_, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized activation rejection, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementSetupIncomplete || repo.StatusPostVerifiedAt != nil {
		t.Fatalf("expected setup-incomplete with cleared verification, got %+v", repo)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementActivateFail)
	if len(events) != 1 || !strings.Contains(events[0].DetailsJSON, "setup status post failed") {
		t.Fatalf("expected activation failure audit, got %+v", events)
	}
}

func TestActivateEnforcementSyncFailureStaysReadyWithoutPublication(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	// Stale cached PR that must not be published from.
	if _, err := pullrequest.NewStore(h.database).Upsert(ctx, domain.PullRequest{RepositoryID: h.repo.ID, Index: 9, State: "open", TargetBranch: "main", HeadSHA: "aaa111"}); err != nil {
		t.Fatal(err)
	}
	h.forge.failPulls = true

	_, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized sync failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementReady {
		t.Fatalf("expected repository to stay ready, got %s", repo.EnforcementState)
	}
	for _, post := range h.forge.posted {
		if post.Context == domain.RequiredStatusContext {
			t.Fatalf("expected no freeze status publication from stale cache, got %+v", h.forge.posted)
		}
	}
	assertAppTableCount(t, h.database, "status_results", 0)
	assertAppTableCount(t, h.database, "status_publication_intents", 0)
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementActivateFail)
	if len(events) != 1 || !strings.Contains(events[0].DetailsJSON, "synchronization failed") {
		t.Fatalf("expected activation failure audit for sync, got %+v", events)
	}
}

func TestActivateEnforcementWithNoOpenPullRequestsBecomesActive(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}

	updated, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive || updated.StatusPostVerifiedAt == nil {
		t.Fatalf("expected active repository, got %+v", updated)
	}
	freezeStatuses := 0
	for _, post := range h.forge.posted {
		if post.Context == domain.RequiredStatusContext {
			freezeStatuses++
		}
	}
	if freezeStatuses != 0 {
		t.Fatalf("expected no real freeze statuses without open PRs, got %+v", h.forge.posted)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementActivated)
	if len(events) != 1 {
		t.Fatalf("expected one activation audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"open_pull_request_count":"0"`) || !strings.Contains(details, `"statuses_posted":"0"`) || !strings.Contains(details, `"enforcement_state":"active"`) {
		t.Fatalf("unexpected activation audit details: %s", details)
	}
}

func TestActivateEnforcementPublishesCurrentPolicyStatuses(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	admin := h.admin
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	// Historical stored policy: main is actively frozen from before activation.
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(42, "open", "main", "AAA111BBB222"),
		newAppPullRequestResponse(43, "open", "develop", "CCC333DDD444"),
	}
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}

	updated, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementActive {
		t.Fatalf("expected active repository, got %+v", updated)
	}
	statuses := map[string]string{}
	for _, post := range h.forge.posted {
		if post.Context == domain.RequiredStatusContext {
			statuses[post.SHA] = post.State
		}
	}
	if len(statuses) != 2 || statuses["aaa111bbb222"] != string(domain.CommitStatusFailure) || statuses["ccc333ddd444"] != string(domain.CommitStatusSuccess) {
		t.Fatalf("expected frozen-branch failure and unfrozen-branch success, got %+v", h.forge.posted)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementActivated)
	if len(events) != 1 {
		t.Fatalf("expected one activation audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, `"open_pull_request_count":"2"`) || !strings.Contains(details, `"statuses_posted":"2"`) || !strings.Contains(details, `"managed_branch_count":"2"`) {
		t.Fatalf("unexpected activation audit details: %s", details)
	}
	if strings.Contains(details, enforcementTestToken) {
		t.Fatalf("token leaked into activation audit: %s", details)
	}
}

func TestActivateEnforcementKeepsRepositoryWideSharedHeadPolicy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := repository.NewStore(h.database).AddBranch(ctx, h.repo.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	// PRs on a frozen and an unfrozen managed branch share one head SHA: the
	// SHA-scoped decision must stay failure repository-wide.
	h.forge.openPRs = []forgejoPullRequestResponse{
		newAppPullRequestResponse(1, "open", "main", "ABC123"),
		newAppPullRequestResponse(2, "open", "develop", "ABC123"),
	}
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	freezePosts := make([]postedEnforcementStatus, 0)
	for _, post := range h.forge.posted {
		if post.Context == domain.RequiredStatusContext {
			freezePosts = append(freezePosts, post)
		}
	}
	if len(freezePosts) != 1 || freezePosts[0].SHA != "abc123" || freezePosts[0].State != string(domain.CommitStatusFailure) {
		t.Fatalf("expected one repository-wide failure for shared head, got %+v", freezePosts)
	}
}

func TestActivateEnforcementRespectsCurrentHeadThawException(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	if _, err := freeze.NewService(h.database).CreateActive(ctx, freeze.CreateParams{RepositoryID: h.repo.ID, Branch: "main", Reason: "release freeze"}, h.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := thawexception.NewService(h.database).Approve(ctx, thawexception.ApproveParams{RepositoryID: h.repo.ID, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "aaa111bbb222", Reason: "hotfix"}, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	for _, post := range h.forge.posted {
		if post.Context == domain.RequiredStatusContext && (post.SHA != "aaa111bbb222" || post.State != string(domain.CommitStatusSuccess)) {
			t.Fatalf("expected thaw exception to keep the frozen PR successful, got %+v", h.forge.posted)
		}
	}
}

func TestActivateEnforcementPublicationFailureBecomesUnhealthy(t *testing.T) {
	ctx := context.Background()
	h := newEnforcementHarness(t, ctx)
	h.forge.openPRs = []forgejoPullRequestResponse{newAppPullRequestResponse(42, "open", "main", "AAA111BBB222")}
	if _, err := h.service.VerifyStatusPosting(ctx, h.repo.ID, h.admin); err != nil {
		t.Fatal(err)
	}
	h.forge.failFreezePost = true

	_, err := h.service.ActivateEnforcement(ctx, h.repo.ID, h.admin)
	if !repository.IsValidationError(err) || strings.Contains(err.Error(), enforcementTestToken) {
		t.Fatalf("expected sanitized publication failure, got %v", err)
	}
	repo := h.currentRepo(t, ctx)
	if repo.EnforcementState != domain.EnforcementUnhealthy {
		t.Fatalf("expected unhealthy repository, got %s", repo.EnforcementState)
	}
	events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementActivateFail)
	if len(events) != 1 {
		t.Fatalf("expected one activation failure audit event, got %+v", events)
	}
	details := events[0].DetailsJSON
	if !strings.Contains(details, "publication failed") || !strings.Contains(details, `"enforcement_state":"unhealthy"`) || !strings.Contains(details, `"statuses_failed":"1"`) {
		t.Fatalf("unexpected activation failure details: %s", details)
	}
	if strings.Contains(details, enforcementTestToken) {
		t.Fatalf("token leaked into failure audit: %s", details)
	}
	if events := h.auditEvents(t, ctx, audit.ActionRepositoryEnforcementActivated); len(events) != 0 {
		t.Fatalf("expected no success audit event after publication failure, got %+v", events)
	}
	// Attempt history is preserved through the normal publication tables.
	assertAppTableCount(t, h.database, "status_publication_attempts", 1)
}
