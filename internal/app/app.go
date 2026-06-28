package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/calitaz/thawguard/internal/config"
	"github.com/calitaz/thawguard/internal/web"
)

// App wires the monolith together. The first scaffold keeps dependencies small:
// HTTP is real, while persistence, forge adapters, and workers are introduced
// behind package boundaries before being made operational.
type App struct {
	cfg    config.Config
	logger *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) *App {
	if logger == nil {
		logger = slog.Default()
	}
	return &App{cfg: cfg, logger: logger}
}

func (a *App) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              a.cfg.HTTPAddr,
		Handler:           web.NewServer(web.Config{AppName: "Thawguard"}).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		a.logger.Info("starting thawguard", "addr", a.cfg.HTTPAddr, "db", a.cfg.DatabasePath)
		errc <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errc:
		return err
	}
}
