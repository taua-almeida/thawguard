package webhook

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestDeliveryStoreRecordsAndMarksProcessed(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)
	store.now = fixedDeliveryClock(time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))

	delivery, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: " delivery-123 ", Event: " pull_request ", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.ID == 0 || delivery.DeliveryID != "delivery-123" || delivery.Event != "pull_request" || !delivery.Verified {
		t.Fatalf("unexpected recorded delivery: %+v", delivery)
	}
	if delivery.RepositoryID != repo.ID || delivery.ProcessedAt != nil || delivery.ProcessingStartedAt != nil {
		t.Fatalf("expected unprocessed delivery for repository, got %+v", delivery)
	}

	store.now = fixedDeliveryClock(time.Date(2026, 6, 30, 12, 1, 0, 0, time.UTC))
	claimedDelivery, claimed, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil || !claimed {
		t.Fatalf("expected delivery claim before processing, claimed=%v err=%v", claimed, err)
	}
	processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{RepositoryID: repo.ID, Action: " opened ", ProcessingStartedAt: claimedDelivery.ProcessingStartedAt})
	if err != nil {
		t.Fatal(err)
	}
	if processed.RepositoryID != repo.ID || processed.Action != "opened" || processed.ProcessedAt == nil || processed.Error != "" {
		t.Fatalf("unexpected processed delivery: %+v", processed)
	}
	if !processed.ReceivedAt.Equal(delivery.ReceivedAt) {
		t.Fatalf("expected received_at to be preserved, got %s", processed.ReceivedAt)
	}

	byID, found, err := store.FindByRepositoryDeliveryID(ctx, repo.ID, "delivery-123")
	if err != nil {
		t.Fatal(err)
	}
	if !found || byID.ID != delivery.ID {
		t.Fatalf("expected to find delivery by delivery id, got found=%v delivery=%+v", found, byID)
	}
}

func TestDeliveryStoreRecordsProcessingError(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)

	delivery, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: "delivery-err", Event: "pull_request", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	claimedDelivery, claimed, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil || !claimed {
		t.Fatalf("expected delivery claim before processing, claimed=%v err=%v", claimed, err)
	}
	processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{Error: "repository is not configured", ProcessingStartedAt: claimedDelivery.ProcessingStartedAt})
	if err != nil {
		t.Fatal(err)
	}
	if processed.ProcessedAt == nil || processed.Error != "repository is not configured" {
		t.Fatalf("expected processing error to be recorded, got %+v", processed)
	}
}

func TestDeliveryStoreClaimsAndReleasesProcessing(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)
	delivery, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: "delivery-claim", Event: "pull_request", Verified: true})
	if err != nil {
		t.Fatal(err)
	}

	claimed, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || claimed.ProcessingStartedAt == nil || claimed.ProcessedAt != nil {
		t.Fatalf("expected first claim to mark delivery in progress, ok=%v delivery=%+v", ok, claimed)
	}
	second, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok || second.ProcessingStartedAt == nil {
		t.Fatalf("expected second claim to be rejected while in progress, ok=%v delivery=%+v", ok, second)
	}

	failed, err := store.MarkProcessingFailed(ctx, delivery.ID, "webhook processing failed", *claimed.ProcessingStartedAt)
	if err != nil {
		t.Fatal(err)
	}
	if failed.ProcessingStartedAt != nil || failed.ProcessedAt != nil || failed.Error != "webhook processing failed" {
		t.Fatalf("expected retryable failed delivery, got %+v", failed)
	}
	retry, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || retry.ProcessingStartedAt == nil || retry.Error != "" {
		t.Fatalf("expected retry claim to clear error and mark in progress, ok=%v delivery=%+v", ok, retry)
	}

	processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{RepositoryID: repo.ID, Action: "opened", ProcessingStartedAt: retry.ProcessingStartedAt})
	if err != nil {
		t.Fatal(err)
	}
	if processed.ProcessingStartedAt != nil || processed.ProcessedAt == nil || processed.Error != "" {
		t.Fatalf("expected processed delivery, got %+v", processed)
	}
	completed, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok || completed.ProcessedAt == nil {
		t.Fatalf("expected completed delivery not to be claimed, ok=%v delivery=%+v", ok, completed)
	}
}

func TestDeliveryStoreReclaimsStaleProcessingClaim(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)
	claimedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store.now = fixedDeliveryClock(claimedAt)
	delivery, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: "delivery-stale", Event: "pull_request", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	initial, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil || !ok {
		t.Fatalf("expected initial claim, ok=%v err=%v", ok, err)
	}

	store.now = fixedDeliveryClock(claimedAt.Add(deliveryProcessingClaimTimeout - time.Second))
	current, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok || current.ProcessingStartedAt == nil || !current.ProcessingStartedAt.Equal(claimedAt) {
		t.Fatalf("expected fresh claim not to be reclaimed, ok=%v delivery=%+v", ok, current)
	}

	store.now = fixedDeliveryClock(claimedAt.Add(deliveryProcessingClaimTimeout + time.Second))
	reclaimed, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || reclaimed.ProcessingStartedAt == nil || !reclaimed.ProcessingStartedAt.After(claimedAt) {
		t.Fatalf("expected stale claim to be reclaimed, ok=%v delivery=%+v", ok, reclaimed)
	}
	if _, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{RepositoryID: repo.ID, Action: "opened", ProcessingStartedAt: initial.ProcessingStartedAt}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected stale claimant not to complete newer claim, got %v", err)
	}
	processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{RepositoryID: repo.ID, Action: "opened", ProcessingStartedAt: reclaimed.ProcessingStartedAt})
	if err != nil {
		t.Fatal(err)
	}
	if processed.ProcessedAt == nil || processed.ProcessingStartedAt != nil {
		t.Fatalf("expected reclaimed claimant to complete, got %+v", processed)
	}
}

func TestDeliveryStoreRejectsInvalidOrDuplicateDeliveries(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)

	if _, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, Event: "pull_request"}); !IsValidationError(err) {
		t.Fatalf("expected missing delivery id validation error, got %v", err)
	}
	if _, err := store.Record(ctx, DeliveryRecordParams{DeliveryID: "delivery-missing-repo", Event: "pull_request"}); !IsValidationError(err) {
		t.Fatalf("expected missing repository validation error, got %v", err)
	}
	if _, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: "delivery-dup", Event: "pull_request"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: "delivery-dup", Event: "pull_request"}); !IsValidationError(err) {
		t.Fatalf("expected duplicate delivery validation error, got %v", err)
	}
	if _, err := store.MarkProcessed(ctx, 0, DeliveryProcessParams{}); !IsValidationError(err) {
		t.Fatalf("expected missing stored delivery id validation error, got %v", err)
	}
}

func TestDeliveryStoreScopesDeliveryIDsByRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	firstRepo := createWebhookDeliveryTestRepository(t, ctx, database)
	secondRepo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "second-owner", Name: "second-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewDeliveryStore(database)

	first, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: firstRepo.ID, DeliveryID: "shared-delivery", Event: "pull_request", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: secondRepo.ID, DeliveryID: "shared-delivery", Event: "pull_request", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.RepositoryID == second.RepositoryID {
		t.Fatalf("expected distinct repository-scoped deliveries, first=%+v second=%+v", first, second)
	}
}

func createWebhookDeliveryTestRepository(t *testing.T, ctx context.Context, database *sql.DB) domain.Repository {
	t.Helper()
	repo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "example-owner", Name: "example-repo", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func fixedDeliveryClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}
