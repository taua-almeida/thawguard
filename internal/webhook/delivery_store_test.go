package webhook

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
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

func TestDeliveryStoreFindsLatestVerifiedPullRequestForExactRepository(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	otherRepo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "other", Name: "other", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewDeliveryStore(database)
	store.now = fixedDeliveryClock(time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC))
	for _, params := range []DeliveryRecordParams{
		{RepositoryID: repo.ID, DeliveryID: "unverified", Event: "pull_request"},
		{RepositoryID: repo.ID, DeliveryID: "push", Event: "push", Verified: true},
		{RepositoryID: otherRepo.ID, DeliveryID: "other-repository", Event: "pull_request", Verified: true},
		{RepositoryID: repo.ID, DeliveryID: "matching", Event: "pull_request", Verified: true},
	} {
		if _, err := store.Record(ctx, params); err != nil {
			t.Fatal(err)
		}
	}

	delivery, found, err := store.LatestVerifiedPullRequestByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || delivery.DeliveryID != "matching" || !delivery.Verified || delivery.Event != "pull_request" {
		t.Fatalf("unexpected delivery %+v found=%v", delivery, found)
	}

	missingRepo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "missing", Name: "missing", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.LatestVerifiedPullRequestByRepository(ctx, missingRepo.ID); err != nil || found {
		t.Fatalf("expected no evidence, found=%v err=%v", found, err)
	}
}

func TestDeliveryStoreListPageFiltersByProcessingState(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	otherRepo, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "other", Name: "other", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewDeliveryStore(database)
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	byState := map[string]Delivery{}
	for i, state := range []string{
		DeliveryProcessingReceived,
		DeliveryProcessingProcessing,
		DeliveryProcessingProcessed,
		DeliveryProcessingProcessedWithError,
		DeliveryProcessingRetryableFailure,
	} {
		receivedAt := base.Add(time.Duration(i) * time.Hour)
		byState[state] = seedPagedDelivery(t, ctx, store, repo.ID, "delivery-"+state, state, receivedAt, receivedAt.Add(30*time.Minute))
	}
	otherDelivery := seedPagedDelivery(t, ctx, store, otherRepo.ID, "delivery-other-repo", DeliveryProcessingProcessed, base.Add(6*time.Hour), base.Add(7*time.Hour))

	for state, want := range byState {
		deliveries, total, err := store.ListPage(ctx, state, repo.ID, DeliveryOrderReceivedDesc, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(deliveries) != 1 || deliveries[0].ID != want.ID {
			t.Fatalf("expected only %s delivery %d, got total=%d deliveries=%+v", state, want.ID, total, deliveries)
		}
	}

	deliveries, total, err := store.ListPage(ctx, "", 0, DeliveryOrderReceivedDesc, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 || len(deliveries) != 6 {
		t.Fatalf("expected all six deliveries unfiltered, got total=%d len=%d", total, len(deliveries))
	}
	deliveries, total, err = store.ListPage(ctx, "", otherRepo.ID, DeliveryOrderReceivedDesc, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(deliveries) != 1 || deliveries[0].ID != otherDelivery.ID {
		t.Fatalf("expected only other-repository delivery, got total=%d deliveries=%+v", total, deliveries)
	}
	deliveries, total, err = store.ListPage(ctx, DeliveryProcessingProcessed, repo.ID, DeliveryOrderReceivedDesc, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(deliveries) != 1 || deliveries[0].ID != byState[DeliveryProcessingProcessed].ID {
		t.Fatalf("expected repository-scoped processed delivery, got total=%d deliveries=%+v", total, deliveries)
	}
	deliveries, total, err = store.ListPage(ctx, "bogus", 0, DeliveryOrderReceivedDesc, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(deliveries) != 0 {
		t.Fatalf("expected unknown processing filter to match nothing, got total=%d deliveries=%+v", total, deliveries)
	}
}

func TestDeliveryStoreListPageOrdersDeliveries(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	first := seedPagedDelivery(t, ctx, store, repo.ID, "delivery-first", DeliveryProcessingProcessed, base, base.Add(4*time.Hour))
	second := seedPagedDelivery(t, ctx, store, repo.ID, "delivery-second", DeliveryProcessingProcessedWithError, base.Add(time.Hour), base.Add(3*time.Hour))
	third := seedPagedDelivery(t, ctx, store, repo.ID, "delivery-third", DeliveryProcessingReceived, base.Add(time.Hour), time.Time{})

	assertDeliveryOrder := func(order DeliveryOrder, want []int64) {
		t.Helper()
		deliveries, total, err := store.ListPage(ctx, "", 0, order, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if total != len(want) || len(deliveries) != len(want) {
			t.Fatalf("order %q: expected %d deliveries, got total=%d len=%d", order, len(want), total, len(deliveries))
		}
		for i, id := range want {
			if deliveries[i].ID != id {
				t.Fatalf("order %q: expected ids %v, got %+v", order, want, deliveries)
			}
		}
	}

	// second and third share received_at: id breaks the tie in sort direction.
	assertDeliveryOrder(DeliveryOrderReceivedDesc, []int64{third.ID, second.ID, first.ID})
	assertDeliveryOrder(DeliveryOrderReceivedAsc, []int64{first.ID, second.ID, third.ID})
	// Missing processed_at sorts last in both directions.
	assertDeliveryOrder(DeliveryOrderProcessedDesc, []int64{first.ID, second.ID, third.ID})
	assertDeliveryOrder(DeliveryOrderProcessedAsc, []int64{second.ID, first.ID, third.ID})
	assertDeliveryOrder(DeliveryOrder("bogus"), []int64{third.ID, second.ID, first.ID})
}

func TestDeliveryStoreListPagePaginates(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createWebhookDeliveryTestRepository(t, ctx, database)
	store := NewDeliveryStore(database)
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	ids := make([]int64, 0, 5)
	for i := range 5 {
		delivery := seedPagedDelivery(t, ctx, store, repo.ID, fmt.Sprintf("delivery-page-%d", i), DeliveryProcessingReceived, base.Add(time.Duration(i)*time.Hour), time.Time{})
		ids = append(ids, delivery.ID)
	}

	assertPage := func(offset int, want []int64) {
		t.Helper()
		deliveries, total, err := store.ListPage(ctx, "", 0, DeliveryOrderReceivedDesc, offset, 2)
		if err != nil {
			t.Fatal(err)
		}
		if total != 5 || len(deliveries) != len(want) {
			t.Fatalf("offset %d: expected %d of 5 deliveries, got total=%d len=%d", offset, len(want), total, len(deliveries))
		}
		for i, id := range want {
			if deliveries[i].ID != id {
				t.Fatalf("offset %d: expected ids %v, got %+v", offset, want, deliveries)
			}
		}
	}

	assertPage(0, []int64{ids[4], ids[3]})
	assertPage(2, []int64{ids[2], ids[1]})
	assertPage(4, []int64{ids[0]})
	assertPage(10, []int64{})
	assertPage(-3, []int64{ids[4], ids[3]})

	if _, _, err := NewDeliveryStore(nil).ListPage(ctx, "", 0, DeliveryOrderReceivedDesc, 0, 10); err == nil {
		t.Fatal("expected nil-database store to error")
	}
}

func TestDeliveryStoreListsPageForScope(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repoA := createWebhookDeliveryTestRepository(t, ctx, database)
	repoB, err := repository.NewStore(database).Create(ctx, repository.CreateParams{Owner: "other", Name: "other", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewDeliveryStore(database)
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	// Every repository B delivery is received after every repository A
	// delivery, so the newest rows an unrestricted page would serve first are
	// all foreign to a scope over repository A.
	states := []string{
		DeliveryProcessingReceived,
		DeliveryProcessingProcessing,
		DeliveryProcessingProcessed,
		DeliveryProcessingProcessedWithError,
		DeliveryProcessingRetryableFailure,
	}
	scopedByState := map[string]Delivery{}
	scopedIDs := make([]int64, 0, len(states))
	for i, state := range states {
		receivedAt := base.Add(time.Duration(i) * time.Hour)
		delivery := seedPagedDelivery(t, ctx, store, repoA.ID, "delivery-a-"+state, state, receivedAt, receivedAt.Add(30*time.Minute))
		scopedByState[state] = delivery
		scopedIDs = append(scopedIDs, delivery.ID)
	}
	for i, state := range states {
		receivedAt := base.Add(time.Duration(12+i) * time.Hour)
		seedPagedDelivery(t, ctx, store, repoB.ID, "delivery-b-"+state, state, receivedAt, receivedAt.Add(30*time.Minute))
	}

	assertPage := func(t *testing.T, scope repositoryscope.ReadScope, processing string, repositoryID int64, order DeliveryOrder, offset, limit int, wantTotal int, wantIDs []int64) {
		t.Helper()
		deliveries, total, err := store.ListPageForScope(ctx, scope, processing, repositoryID, order, offset, limit)
		if err != nil {
			t.Fatal(err)
		}
		if total != wantTotal {
			t.Fatalf("expected total %d, got %d", wantTotal, total)
		}
		if len(deliveries) != len(wantIDs) {
			t.Fatalf("expected %d deliveries, got %+v", len(wantIDs), deliveries)
		}
		for i, id := range wantIDs {
			if deliveries[i].ID != id {
				t.Fatalf("expected ids %v, got %+v", wantIDs, deliveries)
			}
		}
	}

	scopeA := repositoryscope.IDs(repoA.ID)
	// Each derived processing state intersects the scope: the same-state
	// foreign delivery never appears even without a repository filter.
	for _, state := range states {
		assertPage(t, scopeA, state, 0, DeliveryOrderReceivedDesc, 0, 10, 1, []int64{scopedByState[state].ID})
	}
	// An unknown processing value still matches nothing inside the scope.
	assertPage(t, scopeA, "bogus", 0, DeliveryOrderReceivedDesc, 0, 10, 0, nil)
	// Scope applies before ordering and pagination: a two-row first page
	// serves the two newest accessible deliveries, not empty slots consumed
	// by the newer foreign rows, and the total counts only accessible rows.
	assertPage(t, scopeA, "", 0, DeliveryOrderReceivedDesc, 0, 2, 5, []int64{scopedIDs[4], scopedIDs[3]})
	assertPage(t, scopeA, "", 0, DeliveryOrderReceivedDesc, 4, 2, 5, []int64{scopedIDs[0]})
	assertPage(t, scopeA, "", 0, DeliveryOrderReceivedAsc, 0, 2, 5, []int64{scopedIDs[0], scopedIDs[1]})
	// Filtering for an inaccessible repository yields nothing, not the
	// accessible rows.
	assertPage(t, scopeA, "", repoB.ID, DeliveryOrderReceivedDesc, 0, 10, 0, nil)
	assertPage(t, scopeA, DeliveryProcessingProcessed, repoB.ID, DeliveryOrderReceivedDesc, 0, 10, 0, nil)
	// The zero-value scope denies everything.
	assertPage(t, repositoryscope.ReadScope{}, "", 0, DeliveryOrderReceivedDesc, 0, 10, 0, nil)

	// The all scope matches the unrestricted method row for row.
	unrestricted, unrestrictedTotal, err := store.ListPage(ctx, "", 0, DeliveryOrderReceivedDesc, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if unrestrictedTotal != 10 || len(unrestricted) != 10 {
		t.Fatalf("expected unrestricted page to keep every row, got total %d and %d rows", unrestrictedTotal, len(unrestricted))
	}
	allIDs := make([]int64, 0, len(unrestricted))
	for _, delivery := range unrestricted {
		allIDs = append(allIDs, delivery.ID)
	}
	assertPage(t, repositoryscope.All(), "", 0, DeliveryOrderReceivedDesc, 0, 20, 10, allIDs)
}

// seedPagedDelivery records one delivery and drives it into the requested
// derived processing state; processedAt only applies to the processed states.
func seedPagedDelivery(t *testing.T, ctx context.Context, store *DeliveryStore, repositoryID int64, deliveryID string, state string, receivedAt, processedAt time.Time) Delivery {
	t.Helper()
	store.now = fixedDeliveryClock(receivedAt)
	delivery, err := store.Record(ctx, DeliveryRecordParams{RepositoryID: repositoryID, DeliveryID: deliveryID, Event: "pull_request", Action: "opened", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	if state == DeliveryProcessingReceived {
		return delivery
	}
	store.now = fixedDeliveryClock(receivedAt.Add(time.Minute))
	claimed, ok, err := store.ClaimForProcessing(ctx, delivery.ID)
	if err != nil || !ok {
		t.Fatalf("claim %s: ok=%v err=%v", deliveryID, ok, err)
	}
	switch state {
	case DeliveryProcessingProcessing:
		return claimed
	case DeliveryProcessingRetryableFailure:
		failed, err := store.MarkProcessingFailed(ctx, delivery.ID, "webhook processing failed", *claimed.ProcessingStartedAt)
		if err != nil {
			t.Fatal(err)
		}
		return failed
	case DeliveryProcessingProcessed, DeliveryProcessingProcessedWithError:
		message := ""
		if state == DeliveryProcessingProcessedWithError {
			message = "webhook processing failed"
		}
		store.now = fixedDeliveryClock(processedAt)
		processed, err := store.MarkProcessed(ctx, delivery.ID, DeliveryProcessParams{RepositoryID: repositoryID, Action: "opened", Error: message, ProcessingStartedAt: claimed.ProcessingStartedAt})
		if err != nil {
			t.Fatal(err)
		}
		return processed
	}
	t.Fatalf("unknown seed state %q", state)
	return Delivery{}
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
