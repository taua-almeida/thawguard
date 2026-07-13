package app

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestFreezeLifecycleRunnerActivatesAndEndsDueWindows(t *testing.T) {
	ctx := context.Background()
	store := &fakeScheduledFreezeRuntimeStore{
		dueStarts: []domain.BranchFreeze{{ID: 1, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusScheduled, Scheduled: true}},
		dueEnds: []domain.BranchFreeze{
			{ID: 2, RepositoryID: 7, Branch: "main", Status: domain.BranchFreezeStatusActive, Active: true},
			{ID: 4, RepositoryID: 7, Branch: "release", Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true},
		},
		needs: []domain.BranchFreeze{{ID: 3, RepositoryID: 7, Branch: "hotfix", Status: domain.BranchFreezeStatusEnded, Scheduled: true, NeedsRecompute: true}},
	}
	runner := newFreezeLifecycleRunner(store, nil)

	if err := runner.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(store.activated) != 1 || store.activated[0] != 1 {
		t.Fatalf("expected scheduled freeze activation, got %+v", store.activated)
	}
	if len(store.ended) != 2 || store.ended[0] != 2 || store.ended[1] != 4 {
		t.Fatalf("expected immediate and scheduled planned unfreezes, got %+v", store.ended)
	}
	if store.actor.Kind != domain.ActorKindSystem || store.actor.Role != "scheduler" {
		t.Fatalf("expected scheduler actor, got %+v", store.actor)
	}
	if len(store.retried) != 1 || store.retried[0] != 3 {
		t.Fatalf("expected retry recompute for pending transition, got %+v", store.retried)
	}
	if got := store.order[len(store.order)-1]; got != "retry" {
		t.Fatalf("expected retry phase after due transitions, order=%+v", store.order)
	}
}

func TestFreezeLifecycleRunnerContinuesAfterOneItemFails(t *testing.T) {
	store := &fakeScheduledFreezeRuntimeStore{
		dueEnds:   []domain.BranchFreeze{{ID: 1}, {ID: 2}},
		endErrors: map[int64]error{1: errors.New("first failed")},
	}
	runner := newFreezeLifecycleRunner(store, nil)

	if err := runner.RunDue(context.Background()); err == nil {
		t.Fatal("expected joined runner error")
	}
	if len(store.ended) != 2 || store.ended[0] != 1 || store.ended[1] != 2 {
		t.Fatalf("expected later due item to be attempted, got %+v", store.ended)
	}
}

func TestFreezeLifecycleRunnerStartupPassHandlesOverdueEndAndCancellation(t *testing.T) {
	store := &fakeScheduledFreezeRuntimeStore{dueEnds: []domain.BranchFreeze{{ID: 9}}}
	runner := newFreezeLifecycleRunner(store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	runner.Start(ctx)
	if len(store.ended) != 1 || store.ended[0] != 9 {
		t.Fatalf("expected startup pass before cancellation exit, got %+v", store.ended)
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
	endErrors map[int64]error
	order     []string
}

func (s *fakeScheduledFreezeRuntimeStore) ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return s.dueStarts, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	s.activated = append(s.activated, id)
	s.order = append(s.order, "activate")
	s.actor = actor
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusActive, Active: true, Scheduled: true}, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return s.dueEnds, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	s.ended = append(s.ended, id)
	s.order = append(s.order, "end")
	s.actor = actor
	if err := s.endErrors[id]; err != nil {
		return domain.BranchFreeze{}, err
	}
	return domain.BranchFreeze{ID: id, Status: domain.BranchFreezeStatusEnded, Scheduled: true}, nil
}

func (s *fakeScheduledFreezeRuntimeStore) ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	return s.needs, nil
}

func (s *fakeScheduledFreezeRuntimeStore) RetryRecompute(ctx context.Context, pending domain.BranchFreeze) error {
	s.retried = append(s.retried, pending.ID)
	s.order = append(s.order, "retry")
	return nil
}
