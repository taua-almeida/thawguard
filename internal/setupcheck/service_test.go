package setupcheck

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

var readinessNow = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

func TestReadinessServiceChecksEveryManagedBranchAndPersistsOneRun(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createReadinessRepository(t, ctx, database, "release/1.0")
	inspector := healthyInspector()
	service := readinessService(database, inspector, fakeTokenProvider{token: "encrypted-token-plaintext", found: true}, recentWebhook(repo.ID))

	results, err := service.Run(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 12 {
		t.Fatalf("expected 4 repository and 8 branch results, got %d", len(results))
	}
	if inspector.pullRequestBranch != "main" || strings.Join(inspector.branches, ",") != "main,release/1.0" {
		t.Fatalf("expected deterministic branch order, PR=%q branches=%v", inspector.pullRequestBranch, inspector.branches)
	}
	if resultByName(results, CheckStatusPostingUntested).Status != StatusWarning {
		t.Fatalf("status posting must remain warning, got %+v", results)
	}

	checks, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 12 {
		t.Fatalf("expected 12 persisted checks, got %d", len(checks))
	}
	for _, check := range checks {
		if !check.CheckedAt.Equal(readinessNow) {
			t.Fatalf("expected one run timestamp %s, got %s", readinessNow, check.CheckedAt)
		}
	}
	branches, err := repository.NewStore(database).ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, branch := range branches {
		if !branch.Protected || branch.SetupStatus != "ok" || branch.LastCheckedAt == nil || !branch.LastCheckedAt.Equal(readinessNow) {
			t.Fatalf("unexpected branch summary %+v", branch)
		}
	}
	storedRepo, err := repository.NewStore(database).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedRepo.EnforcementState != domain.EnforcementSetupIncomplete {
		t.Fatalf("setup-incomplete repository must not become ready, got %s", storedRepo.EnforcementState)
	}
	assertAuditCount(t, ctx, database, audit.ActionRepositorySetupCheckRun, 1)
}

func TestReadinessServiceMissingTokenAvoidsForgeAndPreservesBranchSummary(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createReadinessRepository(t, ctx, database)
	factoryCalls := 0
	service := NewReadinessService(database, fakeTokenProvider{}, recentWebhook(repo.ID), func(domain.Repository, string) (Inspector, error) {
		factoryCalls++
		return healthyInspector(), nil
	})
	service.now = func() time.Time { return readinessNow }

	results, err := service.Run(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 0 {
		t.Fatalf("expected no forge client creation, got %d", factoryCalls)
	}
	if resultByName(results, CheckStatusTokenConfigured).Status != StatusFailed || resultByName(results, CheckPullRequestReadAccess).Status != StatusFailed {
		t.Fatalf("expected token-required failures, got %+v", results)
	}
	branches, err := repository.NewStore(database).ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if branches[0].LastCheckedAt != nil || branches[0].SetupStatus != "unknown" {
		t.Fatalf("missing token must not replace branch evidence, got %+v", branches[0])
	}
}

func TestReadinessServiceWebhookFreshness(t *testing.T) {
	cases := []struct {
		name     string
		delivery fakeWebhookEvidence
		status   Status
	}{
		{name: "recent", delivery: fakeWebhookEvidence{delivery: webhook.Delivery{RepositoryID: 1, Event: "pull_request", Verified: true, ReceivedAt: readinessNow.Add(-24 * time.Hour)}, found: true}, status: StatusOK},
		{name: "stale", delivery: fakeWebhookEvidence{delivery: webhook.Delivery{RepositoryID: 1, Event: "pull_request", Verified: true, ReceivedAt: readinessNow.Add(-24*time.Hour - time.Nanosecond)}, found: true}, status: StatusWarning},
		{name: "missing", delivery: fakeWebhookEvidence{}, status: StatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := &Service{deliveries: tc.delivery}
			result, fresh, err := service.webhookResult(context.Background(), 1, readinessNow)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.status || fresh != (tc.status == StatusOK) {
				t.Fatalf("unexpected webhook result %+v fresh=%v", result, fresh)
			}
		})
	}
}

func TestReadinessServicePersistsMixedBranchOutcomesAndOneDriftTransition(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createReadinessRepository(t, ctx, database, "release")
	healthy := healthyInspector()
	service := readinessService(database, healthy, fakeTokenProvider{token: "token", found: true}, recentWebhook(repo.ID))
	if _, err := service.Run(ctx, repo); err != nil {
		t.Fatal(err)
	}

	mixed := healthyInspector()
	mixed.inspections["release"] = unprotectedInspection("release")
	service = readinessService(database, mixed, fakeTokenProvider{token: "token", found: true}, recentWebhook(repo.ID))
	if _, err := service.Run(ctx, repo); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(ctx, repo); err != nil {
		t.Fatal(err)
	}

	branches, err := repository.NewStore(database).ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if branches[0].Name != "main" || branches[0].SetupStatus != "ok" || branches[1].Name != "release" || branches[1].Protected || branches[1].SetupStatus != "unknown" {
		t.Fatalf("unexpected mixed summaries %+v", branches)
	}
	checks, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	latestCount := 0
	for _, check := range checks {
		if check.CheckedAt.Equal(checks[0].CheckedAt) {
			latestCount++
		}
	}
	if latestCount != 12 {
		t.Fatalf("expected latest run to remain a distinct 12-check batch, got %d", latestCount)
	}
	assertAuditCount(t, ctx, database, audit.ActionRepositorySetupDriftDetected, 1)
}

func TestReadinessServiceOperationalFailurePreservesEvidenceAndActiveState(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createReadinessRepository(t, ctx, database)
	active, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
	if err != nil {
		t.Fatal(err)
	}
	active.HasStatusToken = true
	healthy := healthyInspector()
	service := readinessService(database, healthy, fakeTokenProvider{token: "secret-token", found: true}, recentWebhook(repo.ID))
	if _, err := service.Run(ctx, active); err != nil {
		t.Fatal(err)
	}
	before, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}

	failing := healthyInspector()
	failing.branchErr["main"] = errors.New("network failed with secret-token")
	service = readinessService(database, failing, fakeTokenProvider{token: "secret-token", found: true}, recentWebhook(repo.ID))
	_, err = service.Run(ctx, active)
	if err == nil {
		t.Fatal("expected operational error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("expected token redaction, got %v", err)
	}
	after, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("operational failure replaced evidence: before=%d after=%d", len(before), len(after))
	}
	stored, err := repository.NewStore(database).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnforcementState != domain.EnforcementActive {
		t.Fatalf("operational failure must preserve active state, got %s", stored.EnforcementState)
	}
}

func TestReadinessServiceDefinitiveFailureMakesActiveRepositoryUnhealthy(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createReadinessRepository(t, ctx, database)
	active, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive)
	if err != nil {
		t.Fatal(err)
	}
	active.HasStatusToken = true
	inspector := healthyInspector()
	inspector.inspections["main"] = unprotectedInspection("main")
	service := readinessService(database, inspector, fakeTokenProvider{token: "token", found: true}, recentWebhook(repo.ID))
	if _, err := service.Run(ctx, active); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.NewStore(database).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnforcementState != domain.EnforcementUnhealthy {
		t.Fatalf("expected unhealthy state, got %s", stored.EnforcementState)
	}
}

func TestReadinessServiceRollsBackChecksAndAuditWhenBranchSummaryFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createReadinessRepository(t, ctx, database)
	inspector := healthyInspector()
	inspector.onBranch = func(branch string) {
		if err := repository.NewStore(database).RemoveBranch(ctx, repo.ID, branch); err != nil {
			t.Fatal(err)
		}
	}
	service := readinessService(database, inspector, fakeTokenProvider{token: "token", found: true}, recentWebhook(repo.ID))
	if _, err := service.Run(ctx, repo); err == nil {
		t.Fatal("expected branch summary persistence failure")
	}
	checks, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 0 {
		t.Fatalf("expected setup checks rollback, got %+v", checks)
	}
	assertAuditCount(t, ctx, database, audit.ActionRepositorySetupCheckRun, 0)
}

type fakeTokenProvider struct {
	token string
	found bool
	err   error
}

func (p fakeTokenProvider) StatusToken(context.Context, int64) (string, bool, error) {
	return p.token, p.found, p.err
}

type fakeWebhookEvidence struct {
	delivery webhook.Delivery
	found    bool
	err      error
}

func (e fakeWebhookEvidence) LatestVerifiedPullRequestByRepository(context.Context, int64) (webhook.Delivery, bool, error) {
	return e.delivery, e.found, e.err
}

type fakeInspector struct {
	pullRequestResult Result
	pullRequestErr    error
	pullRequestBranch string
	inspections       map[string]BranchInspection
	branchErr         map[string]error
	branches          []string
	onBranch          func(string)
}

func (i *fakeInspector) InspectPullRequestRead(_ context.Context, _ domain.Repository, branch string) (Result, error) {
	i.pullRequestBranch = branch
	return i.pullRequestResult, i.pullRequestErr
}

func (i *fakeInspector) InspectBranch(_ context.Context, _ domain.Repository, branch string) (BranchInspection, error) {
	i.branches = append(i.branches, branch)
	if i.onBranch != nil {
		i.onBranch(branch)
		i.onBranch = nil
	}
	if err := i.branchErr[branch]; err != nil {
		return BranchInspection{}, err
	}
	if inspection, ok := i.inspections[branch]; ok {
		return inspection, nil
	}
	return protectedInspection(branch), nil
}

func healthyInspector() *fakeInspector {
	return &fakeInspector{
		pullRequestResult: Result{Name: CheckPullRequestReadAccess, Status: StatusOK, Description: "Pull requests are readable."},
		inspections:       make(map[string]BranchInspection),
		branchErr:         make(map[string]error),
	}
}

func protectedInspection(branch string) BranchInspection {
	return BranchInspection{Protected: true, Results: []Result{
		{Name: CheckBranchProtectionReadable, Status: StatusOK, Description: "readable"},
		{Name: CheckBranchProtectionEnabled, Status: StatusOK, Description: "protected"},
		{Name: CheckRequiredStatusChecksEnabled, Status: StatusOK, Description: "enabled"},
		{Name: CheckRequiredThawguardFreezeContextConfigured, Status: StatusOK, Description: "exact context"},
	}}
}

func unprotectedInspection(branch string) BranchInspection {
	inspection := protectedInspection(branch)
	inspection.Protected = false
	for index := 1; index < len(inspection.Results); index++ {
		inspection.Results[index].Status = StatusFailed
	}
	return inspection
}

func readinessService(database *sql.DB, inspector *fakeInspector, tokens fakeTokenProvider, deliveries fakeWebhookEvidence) *Service {
	service := NewReadinessService(database, tokens, deliveries, func(domain.Repository, string) (Inspector, error) { return inspector, nil })
	service.now = func() time.Time { return readinessNow }
	return service
}

func recentWebhook(repositoryID int64) fakeWebhookEvidence {
	return fakeWebhookEvidence{delivery: webhook.Delivery{RepositoryID: repositoryID, Event: "pull_request", Verified: true, ReceivedAt: readinessNow.Add(-time.Hour)}, found: true}
}

func createReadinessRepository(t *testing.T, ctx context.Context, database *sql.DB, branches ...string) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	repo.HasStatusToken = true
	for _, branch := range branches {
		if _, err := repository.NewStore(database).AddBranch(ctx, repo.ID, branch); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

func resultByName(results []Result, name string) Result {
	for _, result := range results {
		if result.Name == name {
			return result
		}
	}
	return Result{}
}

func assertAuditCount(t *testing.T, ctx context.Context, database *sql.DB, action string, want int) {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, event := range events {
		if event.Action == action {
			got++
		}
	}
	if got != want {
		t.Fatalf("expected %d %s events, got %d", want, action, got)
	}
}
