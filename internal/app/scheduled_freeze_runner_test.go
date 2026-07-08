package app

import (
	"context"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestScheduledFreezeRunnerActivatesAndEndsDueWindows(t *testing.T) {
	ctx := context.Background()
	store := &fakeScheduledFreezeRuntimeStore{
		dueStarts: []domain.BranchFreeze{{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true}},
		dueEnds:   []domain.BranchFreeze{{ID: 2, RepositoryID: 7, Branch: "release", Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true}},
		needs:     []domain.BranchFreeze{{ID: 3, RepositoryID: 7, Branch: "hotfix", Status: domain.BranchFreezeStatusEnded, Scheduled: true, NeedsRecompute: true}},
	}
	runner := newScheduledFreezeRunner(store, nil)

	if err := runner.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(store.activated) != 1 || store.activated[0] != 1 {
		t.Fatalf("expected scheduled freeze activation, got %+v", store.activated)
	}
	if len(store.ended) != 1 || store.ended[0] != 2 {
		t.Fatalf("expected planned unfreeze execution, got %+v", store.ended)
	}
	if store.actor.Kind != domain.ActorKindSystem || store.actor.Role != "scheduler" {
		t.Fatalf("expected scheduler actor, got %+v", store.actor)
	}
	if len(store.retried) != 1 || store.retried[0] != 3 {
		t.Fatalf("expected retry recompute for pending transition, got %+v", store.retried)
	}
}

type fakeScheduledFreezeRuntimeStore struct {
	dueStarts []domain.BranchFreeze
	dueEnds   []domain.BranchFreeze
	needs     []domain.BranchFreeze
	activated []int64
	ended     []int64
	retried   []int64
	actor     domain.Actor
}

func (s *fakeScheduledFreezeRuntimeStore) ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return s.dueStarts, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	s.activated = append(s.activated, id)
	s.actor = actor
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true}, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return s.dueEnds, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	s.ended = append(s.ended, id)
	s.actor = actor
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusEnded, Scheduled: true}, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ListScheduledNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return s.needs, nil
}

func (s *fakeScheduledFreezeRuntimeStore) RetryScheduledRecompute(ctx context.Context, scheduledFreeze domain.BranchFreeze) error {
	s.retried = append(s.retried, scheduledFreeze.ID)
	return nil
}
