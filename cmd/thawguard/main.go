package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/calitaz/thawguard/internal/app"
	"github.com/calitaz/thawguard/internal/config"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	cfg := config.FromEnv()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.New(cfg, logger).Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("thawguard stopped", "err", err)
		os.Exit(1)
	}
}
