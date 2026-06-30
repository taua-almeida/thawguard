package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/secrets"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statuspublisher"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/web"
	"github.com/taua-almeida/thawguard/internal/webhook"
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
	if err := validateBootstrapLocalBind(a.cfg.HTTPAddr); err != nil {
		return err
	}

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

	secretStore, err := secretStoreFromConfig(a.cfg)
	if err != nil {
		return err
	}
	repositoryStore := repositorysetup.NewServiceWithSecrets(database, secretStore)
	setupCheckStore := setupcheck.NewStore(database)
	setupCheckRunner := localSetupHealthRunner{recorder: setupCheckStore}
	freezeStore := freeze.NewService(database)
	auditStore := audit.NewStore(database)
	statusDecisionStore := statusresult.NewService(statusresult.NewStore(database), freezeStore)
	statusPublicationStore := statuspublication.NewStore(database)
	dryRunStatusPublisher := statuspublisher.NewDryRunPublisher(statusPublicationStore, statusPublicationStore)
	pullRequestStore := pullrequest.NewStore(database)
	webhookDeliveryStore := webhook.NewDeliveryStore(database)
	pullRequestWebhookProcessor := webhook.NewPullRequestProcessor(repository.NewStore(database), pullRequestStore, statusDecisionStore, dryRunStatusPublisher)
	server := &http.Server{
		Addr: a.cfg.HTTPAddr,
		Handler: web.NewServer(web.Config{
			AppName:                              "Thawguard",
			RepositoryStore:                      repositoryStore,
			RepositorySecretEncryptionConfigured: secretStore != nil,
			SetupCheckStore:                      setupCheckStore,
			SetupCheckRunner:                     setupCheckRunner,
			FreezeStore:                          freezeStore,
			AuditStore:                           auditStore,
			StatusDecisionStore:                  statusDecisionStore,
			StatusPublicationStore:               statusPublicationStore,
			WebhookRepositoryStore:               repositoryStore,
			WebhookDeliveryStore:                 webhookDeliveryStore,
			PullRequestWebhookProcessor:          pullRequestWebhookProcessor,
		}).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
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

func secretStoreFromConfig(cfg config.Config) (secrets.Store, error) {
	if cfg.SecretKey == "" {
		return nil, nil
	}
	store, err := secrets.NewAESGCMStoreFromBase64(cfg.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid THAWGUARD_SECRET_KEY: %w", err)
	}
	return store, nil
}
