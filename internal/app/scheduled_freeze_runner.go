package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

const scheduledFreezeRunnerLimit = 25

type scheduledFreezeRuntimeStore interface {
	ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListScheduledNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	RetryScheduledRecompute(ctx context.Context, scheduledFreeze domain.BranchFreeze) error
}

type scheduledFreezeRunner struct {
	store    scheduledFreezeRuntimeStore
	logger   *slog.Logger
	interval time.Duration
}

func newScheduledFreezeRunner(store scheduledFreezeRuntimeStore, logger *slog.Logger) *scheduledFreezeRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &scheduledFreezeRunner{store: store, logger: logger, interval: 15 * time.Second}
}

func (r *scheduledFreezeRunner) Start(ctx context.Context) {
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

func (r *scheduledFreezeRunner) runAndLog(ctx context.Context) {
	if err := r.RunDue(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Error("scheduled freeze runner failed", "err", err)
	}
}

func (r *scheduledFreezeRunner) RunDue(ctx context.Context) error {
	if r == nil || r.store == nil {
		return nil
	}
	actor := domain.Actor{Kind: domain.ActorKindSystem, Role: "scheduler"}
	dueStarts, err := r.store.ListDueScheduled(ctx, scheduledFreezeRunnerLimit)
	if err != nil {
		return err
	}
	var joined error
	for _, scheduled := range dueStarts {
		if _, err := r.store.ActivateScheduled(ctx, scheduled.ID, actor); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	dueEnds, err := r.store.ListDuePlannedUnfreezes(ctx, scheduledFreezeRunnerLimit)
	if err != nil {
		return errors.Join(joined, err)
	}
	for _, scheduled := range dueEnds {
		if _, err := r.store.ExecutePlannedUnfreeze(ctx, scheduled.ID, actor); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	needsRecompute, err := r.store.ListScheduledNeedsRecompute(ctx, scheduledFreezeRunnerLimit)
	if err != nil {
		return errors.Join(joined, err)
	}
	for _, scheduled := range needsRecompute {
		if err := r.store.RetryScheduledRecompute(ctx, scheduled); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}
