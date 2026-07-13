package repositorysetup

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

// newReadyRepository creates a repository whose enforcement is ready with
// recorded status-post verification evidence and one historical setup check.
func newReadyRepository(t *testing.T, ctx context.Context, database *sql.DB, service *Service) domain.Repository {
	t.Helper()
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	repo, err := service.Create(ctx, repository.CreateParams{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetStatusToken(ctx, repo.ID, "first-status-token-123", admin); err != nil {
		t.Fatal(err)
	}
	store := repository.NewStore(database)
	verifiedAt := time.Now().UTC()
	if _, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, &verifiedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO setup_checks(repository_id, branch, name, status, description, checked_at)
VALUES (?, NULL, 'Status token configured', 'ok', 'historical evidence', ?)`, repo.ID, verifiedAt.Format("2006-01-02T15:04:05.000000000Z07:00")); err != nil {
		t.Fatal(err)
	}
	ready, err := store.SetEnforcementState(ctx, repo.ID, domain.EnforcementReady)
	if err != nil {
		t.Fatal(err)
	}
	return ready
}

func assertHistoricalSetupChecksRemain(t *testing.T, ctx context.Context, database *sql.DB, repositoryID int64) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM setup_checks WHERE repository_id = ?`, repositoryID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected historical setup checks to remain, got %d rows", count)
	}
}

func TestStatusTokenReplacementInvalidatesReadyState(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewServiceWithSecrets(database, newTestSecretStore(t))
	repo := newReadyRepository(t, ctx, database, service)
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	updated, err := service.SetStatusToken(ctx, repo.ID, "replacement-token-456", admin)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementSetupIncomplete {
		t.Fatalf("expected ready repository to return to setup-incomplete, got %s", updated.EnforcementState)
	}
	if updated.StatusPostVerifiedAt != nil {
		t.Fatalf("expected cleared verification evidence, got %+v", updated.StatusPostVerifiedAt)
	}
	if !updated.HasStatusToken {
		t.Fatal("expected replacement token to be stored")
	}
	assertHistoricalSetupChecksRemain(t, ctx, database, repo.ID)
}

func TestStatusTokenReplacementClearsVerificationForSetupIncomplete(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewServiceWithSecrets(database, newTestSecretStore(t))
	repo := newReadyRepository(t, ctx, database, service)
	store := repository.NewStore(database)
	if _, err := store.SetEnforcementState(ctx, repo.ID, domain.EnforcementSetupIncomplete); err != nil {
		t.Fatal(err)
	}

	updated, err := service.SetStatusToken(ctx, repo.ID, "replacement-token-456", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnforcementState != domain.EnforcementSetupIncomplete || updated.StatusPostVerifiedAt != nil {
		t.Fatalf("expected setup-incomplete with cleared verification, got %+v", updated)
	}
}

func TestStatusTokenReplacementRejectedWhileEnforcementActive(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewServiceWithSecrets(database, newTestSecretStore(t))
	repo := newReadyRepository(t, ctx, database, service)
	verified := repo.StatusPostVerifiedAt
	if _, err := repository.NewStore(database).SetEnforcementState(ctx, repo.ID, domain.EnforcementActive); err != nil {
		t.Fatal(err)
	}

	_, err := service.SetStatusToken(ctx, repo.ID, "replacement-token-456", domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"})
	if !IsValidationError(err) || err.Error() != ActiveStatusTokenLockedMessage {
		t.Fatalf("expected active token replacement rejection, got %v", err)
	}
	current, err := repository.NewStore(database).Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnforcementState != domain.EnforcementActive {
		t.Fatalf("expected active state to stay untouched, got %s", current.EnforcementState)
	}
	if verified == nil || current.StatusPostVerifiedAt == nil {
		t.Fatalf("expected verification evidence to survive the rejected replacement, got %+v", current.StatusPostVerifiedAt)
	}
}

func TestManagedBranchChangeInvalidatesReadyState(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	service := NewServiceWithSecrets(database, newTestSecretStore(t))
	admin := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}
	store := repository.NewStore(database)

	repo := newReadyRepository(t, ctx, database, service)
	if _, err := service.AddBranch(ctx, repo.ID, "develop", admin); err != nil {
		t.Fatal(err)
	}
	current, err := store.Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnforcementState != domain.EnforcementSetupIncomplete {
		t.Fatalf("expected branch add to return ready repository to setup-incomplete, got %s", current.EnforcementState)
	}
	assertHistoricalSetupChecksRemain(t, ctx, database, repo.ID)

	// Back to ready, then removal must invalidate again.
	if _, err := store.SetEnforcementState(ctx, repo.ID, domain.EnforcementReady); err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveBranch(ctx, repo.ID, "develop", admin); err != nil {
		t.Fatal(err)
	}
	current, err = store.Get(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnforcementState != domain.EnforcementSetupIncomplete {
		t.Fatalf("expected branch removal to return ready repository to setup-incomplete, got %s", current.EnforcementState)
	}
	assertHistoricalSetupChecksRemain(t, ctx, database, repo.ID)
}
