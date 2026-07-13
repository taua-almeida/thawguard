package repositorysetup

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/repository"
)

var branchTestAdmin = domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

func newBranchTestService(t *testing.T, ctx context.Context) (*Service, domain.Repository) {
	t.Helper()
	service := NewService(newTestDB(t, ctx))
	repo, err := service.Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, branchTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return service, repo
}

func TestServiceCreateInsertsDefaultManagedBranchAtomically(t *testing.T) {
	ctx := context.Background()
	service, repo := newBranchTestService(t, ctx)

	branches, err := service.ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(branches) != 1 || branches[0].Name != "main" {
		t.Fatalf("expected new repository to manage its default branch, got %+v", branches)
	}

	missingUserID := int64(999)
	if _, err := service.Create(ctx, repository.CreateParams{Owner: "other", Name: "repo"}, domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"}); err == nil {
		t.Fatal("expected audit foreign-key error")
	}
	var orphanBranches int
	if err := service.db.QueryRowContext(ctx, `
SELECT count(*) FROM repository_branches
WHERE repository_id NOT IN (SELECT id FROM repositories)`).Scan(&orphanBranches); err != nil {
		t.Fatal(err)
	}
	if orphanBranches != 0 {
		t.Fatalf("expected rollback to leave no orphan managed branches, got %d", orphanBranches)
	}
}

func TestServiceAddBranchRecordsAuditEventTransactionally(t *testing.T) {
	ctx := context.Background()
	service, repo := newBranchTestService(t, ctx)

	added, err := service.AddBranch(ctx, repo.ID, "release/1.4", branchTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if added.Name != "release/1.4" || added.SetupStatus != "unknown" || added.Protected || added.LastCheckedAt != nil {
		t.Fatalf("expected unverified managed branch, got %+v", added)
	}

	events, err := audit.NewStore(service.db).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Action != audit.ActionRepositoryBranchAdded {
		t.Fatalf("expected branch added audit event, got %+v", events)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["branch"] != "release/1.4" || details["actor_role"] != "admin" {
		t.Fatalf("unexpected branch added details: %s", events[0].DetailsJSON)
	}

	// A duplicate add is a friendly validation error with no new row or event.
	if _, err := service.AddBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); !IsValidationError(err) && !repository.IsValidationError(err) {
		t.Fatalf("expected duplicate validation error, got %v", err)
	} else if err.Error() != "branch is already managed" {
		t.Fatalf("expected friendly duplicate message, got %q", err.Error())
	}
	events, err = audit.NewStore(service.db).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected no audit event for rejected duplicate, got %d", len(events))
	}

	// A forced audit failure rolls the branch row back too.
	missingUserID := int64(999)
	if _, err := service.AddBranch(ctx, repo.ID, "release/2.0", domain.Actor{UserID: &missingUserID, Kind: "user", Role: "admin"}); err == nil {
		t.Fatal("expected audit foreign-key error")
	}
	managed, err := repository.NewStore(service.db).BranchManaged(ctx, repo.ID, "release/2.0")
	if err != nil {
		t.Fatal(err)
	}
	if managed {
		t.Fatal("expected audit failure to roll back the branch add")
	}
}

func TestServiceBranchScopeChangesAdvanceRepositorySnapshot(t *testing.T) {
	ctx := context.Background()
	service, repo := newBranchTestService(t, ctx)
	before := repo.UpdatedAt

	if _, err := service.AddBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); err != nil {
		t.Fatal(err)
	}
	afterAdd, err := repository.NewStore(service.db).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !afterAdd.UpdatedAt.After(before) {
		t.Fatalf("expected branch add to advance repository snapshot, before=%s after=%s", before, afterAdd.UpdatedAt)
	}

	if err := service.RemoveBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); err != nil {
		t.Fatal(err)
	}
	afterRemove, err := repository.NewStore(service.db).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !afterRemove.UpdatedAt.After(afterAdd.UpdatedAt) {
		t.Fatalf("expected branch removal to advance repository snapshot, add=%s remove=%s", afterAdd.UpdatedAt, afterRemove.UpdatedAt)
	}
}

func TestServiceBranchScopeIsLockedWhileEnforcementIsActive(t *testing.T) {
	ctx := context.Background()
	service, repo := newBranchTestService(t, ctx)
	if _, err := service.AddBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(service.db).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}

	if _, err := service.AddBranch(ctx, repo.ID, "release/2.0", branchTestAdmin); !IsValidationError(err) || err.Error() != EnforcementScopeLockedMessage {
		t.Fatalf("expected enforcement scope lock error, got %v", err)
	}
	if err := service.RemoveBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); !IsValidationError(err) || err.Error() != EnforcementScopeLockedMessage {
		t.Fatalf("expected enforcement scope lock error, got %v", err)
	}
	branches, err := service.ListBranches(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(branches) != 2 {
		t.Fatalf("expected branch scope to stay unchanged, got %+v", branches)
	}
}

func TestServiceRemoveBranchGuardsAndAudits(t *testing.T) {
	ctx := context.Background()
	service, repo := newBranchTestService(t, ctx)

	if err := service.RemoveBranch(ctx, repo.ID, "main", branchTestAdmin); !IsValidationError(err) {
		t.Fatalf("expected default branch removal rejection, got %v", err)
	}
	if err := service.RemoveBranch(ctx, repo.ID, "missing", branchTestAdmin); !IsValidationError(err) && !repository.IsValidationError(err) {
		t.Fatalf("expected unknown branch validation error, got %v", err)
	} else if err.Error() != "managed branch not found" {
		t.Fatalf("expected managed branch not found message, got %q", err.Error())
	}

	if _, err := service.AddBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); err != nil {
		t.Fatal(err)
	}
	freezes := freeze.NewService(service.db)
	if _, err := repository.NewStore(service.db).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	active, err := freezes.CreateActive(ctx, freeze.CreateParams{RepositoryID: repo.ID, Branch: "release/1.4", Reason: "release freeze"}, branchTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(service.db).SetEnforcementState(ctx, repo.ID, domain.EnforcementSetupIncomplete); err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); !IsValidationError(err) && !repository.IsValidationError(err) {
		t.Fatalf("expected active freeze removal rejection, got %v", err)
	}
	if _, err := freezes.End(ctx, active.ID, branchTestAdmin); err != nil {
		t.Fatal(err)
	}

	if _, err := repository.NewStore(service.db).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}
	scheduled, err := freezes.CreateScheduled(ctx, freeze.ScheduleParams{RepositoryID: repo.ID, Branch: "release/1.4", Reason: "window", StartsAt: time.Now().UTC().Add(time.Hour)}, branchTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewStore(service.db).SetEnforcementState(ctx, repo.ID, domain.EnforcementSetupIncomplete); err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); !IsValidationError(err) && !repository.IsValidationError(err) {
		t.Fatalf("expected scheduled freeze removal rejection, got %v", err)
	}
	if _, err := freezes.CancelScheduled(ctx, scheduled.ID, branchTestAdmin); err != nil {
		t.Fatal(err)
	}

	// Only ended/cancelled history remains, so removal proceeds and audits.
	if err := service.RemoveBranch(ctx, repo.ID, "release/1.4", branchTestAdmin); err != nil {
		t.Fatal(err)
	}
	managed, err := repository.NewStore(service.db).BranchManaged(ctx, repo.ID, "release/1.4")
	if err != nil {
		t.Fatal(err)
	}
	if managed {
		t.Fatal("expected branch to be removed")
	}
	events, err := audit.NewStore(service.db).List(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Action != audit.ActionRepositoryBranchRemoved {
		t.Fatalf("expected branch removed audit event, got %+v", events[0])
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["branch"] != "release/1.4" {
		t.Fatalf("unexpected branch removed details: %s", events[0].DetailsJSON)
	}
}
