package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

const freezeLifecycleRunnerLimit = 25

type freezeLifecycleRuntimeStore interface {
	ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	RetryRecompute(ctx context.Context, pending domain.BranchFreeze) error
}

type freezeLifecycleRunner struct {
	store    freezeLifecycleRuntimeStore
	logger   *slog.Logger
	interval time.Duration
}

func newFreezeLifecycleRunner(store freezeLifecycleRuntimeStore, logger *slog.Logger) *freezeLifecycleRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &freezeLifecycleRunner{store: store, logger: logger, interval: 15 * time.Second}
}

func (r *freezeLifecycleRunner) Start(ctx context.Context) {
	if r == nil || r.store == nil {
		return
	}
	r.runAndLog(ctx)
	interval := r.interval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runAndLog(ctx)
		}
	}
}

func (r *freezeLifecycleRunner) runAndLog(ctx context.Context) {
	if err := r.RunDue(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Error("freeze lifecycle runner failed", "err", err)
	}
}

func (r *freezeLifecycleRunner) RunDue(ctx context.Context) error {
	if r == nil || r.store == nil {
		return nil
	}
	actor := domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}
	dueStarts, err := r.store.ListDueScheduled(ctx, freezeLifecycleRunnerLimit)
	if err != nil {
		return err
	}
	var joined error
	for _, scheduled := range dueStarts {
		if _, err := r.store.ActivateScheduled(ctx, scheduled.ID, actor); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	dueEnds, err := r.store.ListDuePlannedUnfreezes(ctx, freezeLifecycleRunnerLimit)
	if err != nil {
		return errors.Join(joined, err)
	}
	for _, dueFreeze := range dueEnds {
		if _, err := r.store.ExecutePlannedUnfreeze(ctx, dueFreeze.ID, actor); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	needsRecompute, err := r.store.ListNeedsRecompute(ctx, freezeLifecycleRunnerLimit)
	if err != nil {
		return errors.Join(joined, err)
	}
	for _, pending := range needsRecompute {
		if err := r.store.RetryRecompute(ctx, pending); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}
