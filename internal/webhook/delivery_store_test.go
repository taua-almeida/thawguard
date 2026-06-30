package webhook

import (
	"context"
	"database/sql"
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

	delivery, err := store.Record(ctx, DeliveryRecordParams{DeliveryID: " delivery-123 ", Event: " pull_request ", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.ID == 0 || delivery.DeliveryID != "delivery-123" || delivery.Event != "pull_request" || !delivery.Verified {
		t.Fatalf("unexpected recorded delivery: %+v", delivery)
	}
	if delivery.RepositoryID != 0 || delivery.ProcessedAt != nil {
		t.Fatalf("expected unprocessed delivery without repository, got %+v", delivery)
	}

	store.now = fixedDeliveryClock(time.Date(2026, 6, 30, 12, 1, 0, 0, time.UTC))
	processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{RepositoryID: repo.ID, Action: " opened "})
	if err != nil {
		t.Fatal(err)
	}
	if processed.RepositoryID != repo.ID || processed.Action != "opened" || processed.ProcessedAt == nil || processed.Error != "" {
		t.Fatalf("unexpected processed delivery: %+v", processed)
	}
	if !processed.ReceivedAt.Equal(delivery.ReceivedAt) {
		t.Fatalf("expected received_at to be preserved, got %s", processed.ReceivedAt)
	}

	byID, found, err := store.FindByDeliveryID(ctx, "delivery-123")
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
	store := NewDeliveryStore(database)

	delivery, err := store.Record(ctx, DeliveryRecordParams{DeliveryID: "delivery-err", Event: "pull_request", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{Error: "repository is not configured"})
	if err != nil {
		t.Fatal(err)
	}
	if processed.ProcessedAt == nil || processed.Error != "repository is not configured" {
		t.Fatalf("expected processing error to be recorded, got %+v", processed)
	}
}

func TestDeliveryStoreRejectsInvalidOrDuplicateDeliveries(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	store := NewDeliveryStore(database)

	if _, err := store.Record(ctx, DeliveryRecordParams{Event: "pull_request"}); !IsValidationError(err) {
		t.Fatalf("expected missing delivery id validation error, got %v", err)
	}
	if _, err := store.Record(ctx, DeliveryRecordParams{DeliveryID: "delivery-dup", Event: "pull_request"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(ctx, DeliveryRecordParams{DeliveryID: "delivery-dup", Event: "pull_request"}); !IsValidationError(err) {
		t.Fatalf("expected duplicate delivery validation error, got %v", err)
	}
	if _, err := store.MarkProcessed(ctx, 0, DeliveryProcessParams{}); !IsValidationError(err) {
		t.Fatalf("expected missing stored delivery id validation error, got %v", err)
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
