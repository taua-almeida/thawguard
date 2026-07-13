package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
)

const repositoryReconciliationRunnerLimit = 25

type reconciliationJobStore interface {
	ClaimDue(ctx context.Context, limit int) ([]jobs.Job, error)
}

type reconciliationJobProcessor interface {
	processReconciliationClaim(ctx context.Context, claim jobs.Job) (string, error)
}

type repositoryReconciliationRunner struct {
	jobs      reconciliationJobStore
	processor reconciliationJobProcessor
	logger    *slog.Logger
	interval  time.Duration
}

func newRepositoryReconciliationRunner(jobStore reconciliationJobStore, processor reconciliationJobProcessor, logger *slog.Logger) *repositoryReconciliationRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &repositoryReconciliationRunner{jobs: jobStore, processor: processor, logger: logger, interval: 15 * time.Second}
}

func (r *repositoryReconciliationRunner) Start(ctx context.Context) {
	if r == nil || r.jobs == nil || r.processor == nil {
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

func (r *repositoryReconciliationRunner) runAndLog(ctx context.Context) {
	if err := r.RunDue(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Error("repository reconciliation runner pass failed")
	}
}

func (r *repositoryReconciliationRunner) RunDue(ctx context.Context) error {
	if r == nil || r.jobs == nil || r.processor == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	claims, err := r.jobs.ClaimDue(ctx, repositoryReconciliationRunnerLimit)
	if err != nil {
		return err
	}
	var joined error
	for _, claim := range claims {
		if err := ctx.Err(); err != nil {
			return errors.Join(joined, err)
		}
		category, err := r.processor.processReconciliationClaim(ctx, claim)
		if err != nil {
			if category == "" {
				category = domain.EnforcementFailureRuntime
			}
			r.logger.Warn("repository enforcement recovery scheduled for retry",
				"repository_id", claim.RepositoryID,
				"job_id", claim.ID,
				"attempt", claim.Attempts,
				"category", category,
			)
			joined = errors.Join(joined, err)
		}
	}
	return joined
}
