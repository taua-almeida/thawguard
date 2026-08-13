package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

type forgeAccessShadowPeriodicService interface {
	RunPeriodicDue(ctx context.Context) error
}

type forgeAccessShadowRunner struct {
	service  forgeAccessShadowPeriodicService
	logger   *slog.Logger
	interval time.Duration
}

func newForgeAccessShadowRunner(
	service forgeAccessShadowPeriodicService,
	logger *slog.Logger,
) *forgeAccessShadowRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &forgeAccessShadowRunner{
		service:  service,
		logger:   logger,
		interval: 15 * time.Second,
	}
}

func (r *forgeAccessShadowRunner) Start(ctx context.Context) {
	if r == nil || r.service == nil || ctx.Err() != nil {
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

func (r *forgeAccessShadowRunner) runAndLog(ctx context.Context) {
	if err := r.service.RunPeriodicDue(ctx); err != nil &&
		!errors.Is(err, context.Canceled) && ctx.Err() == nil {
		phase := "unexpected"
		switch {
		case errors.Is(err, forgeconnection.ErrAccessPeriodicReservationFailed):
			phase = "reservation"
		case errors.Is(err, forgeconnection.ErrAccessPeriodicExecutionFailed):
			phase = "execution"
		}
		// The message and phase vocabulary are fixed and cause-neutral:
		// provider, credential, actor, repository, identity, URL, and raw
		// persistence details never enter this log.
		r.logger.Error("periodic shadow refresh runner pass failed", "phase", phase)
	}
}
