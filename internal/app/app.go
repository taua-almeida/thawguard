package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/web"
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
	database, err := db.Open(ctx, db.DefaultConfig(a.cfg.DatabasePath))
	if err != nil {
		return err
	}
	defer database.Close()

	migrations, err := db.LoadMigrations(db.DefaultMigrationsDir)
	if err != nil {
		return err
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		return err
	}

	repositoryStore := repositorysetup.NewService(database)
	server := &http.Server{
		Addr:              a.cfg.HTTPAddr,
		Handler:           web.NewServer(web.Config{AppName: "Thawguard", RepositoryStore: repositoryStore}).Routes(),
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
