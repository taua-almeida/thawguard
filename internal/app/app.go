package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge/forgejo"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/schedule"
	"github.com/taua-almeida/thawguard/internal/scheduler"
	"github.com/taua-almeida/thawguard/internal/secrets"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	setupforgejo "github.com/taua-almeida/thawguard/internal/setupcheck/forgejo"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statuspublisher"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
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
	publicURL, err := config.CanonicalPublicURL(a.cfg.PublicURL)
	if err != nil {
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
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	repositoryStore := repository.NewStore(database)
	setupCheckStore := setupcheck.NewStore(database)
	webhookDeliveryStore := webhook.NewDeliveryStore(database)
	setupCheckRunner := setupcheck.NewReadinessService(database, repositorySetup, webhookDeliveryStore, forgejoReadinessInspectorForRepository)
	freezeStore := freeze.NewService(database)
	pullRequestStore := pullrequest.NewStore(database)
	auditStore := audit.NewStore(database)
	authService := auth.NewService(database)
	if err := validateInitialSetupBind(ctx, a.cfg.HTTPAddr, authService); err != nil {
		return err
	}
	thawExceptionStore := thawexception.NewService(database)
	statusDecisionStore := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freezeStore, thawExceptionStore, pullRequestStore)
	statusPublicationStore := statuspublication.NewStore(database)
	statusPublisher := newRuntimeStatusPublisher(statusPublicationStore, repositoryStore, repositorySetup)
	openPullRequestSyncer := newForgeOpenPullRequestSyncer(repositoryStore, repositorySetup, pullRequestStore, forgejoPullRequestClientForRepository, auditStore)
	enforcementService := newEnforcementService(database, repositorySetup, setupCheckRunner, forgejoEnforcementClientForRepository, openPullRequestSyncer, pullRequestStore, statusDecisionStore, statusPublisher)
	jobStore := jobs.NewStore(database)
	convergence := newRuntimeConvergenceService(jobStore, enforcementService)
	freezeStoreForWeb := newFreezeRecomputingStore(freezeStore, repositoryStore, openPullRequestSyncer, pullRequestStore, statusDecisionStore, statusPublisher)
	freezeStoreForWeb.convergence = convergence
	scheduleStore := schedule.NewService(database)
	freezeStoreForWeb.scheduleEnder = scheduleStore
	scheduleMaterializer := scheduler.NewMaterializer(scheduleStore, freezeStoreForWeb, scheduler.SystemClock{}, a.logger)
	thawApprovalStore := newThawApprovalService(repositoryStore, repositorySetup, pullRequestStore, thawExceptionStore, freezeStore, statusDecisionStore, statusPublisher, openPullRequestSyncer, forgejoThawApprovalClientForRepository)
	thawApprovalStore.convergence = convergence
	pullRequestWebhookProcessor := webhook.NewPullRequestProcessor(repositoryStore, pullRequestStore, statusDecisionStore, statusPublisher)
	pullRequestWebhookProcessor.SetConvergence(convergence)
	server := &http.Server{
		Addr: a.cfg.HTTPAddr,
		Handler: web.NewServer(web.Config{
			AppName:                              "Thawguard",
			PublicURL:                            publicURL,
			RepositoryStore:                      repositorySetup,
			RepositorySecretEncryptionConfigured: secretStore != nil,
			SetupCheckStore:                      setupCheckStore,
			SetupCheckRunner:                     setupCheckRunner,
			FreezeStore:                          freezeStoreForWeb,
			ScheduledFreezeStore:                 freezeStoreForWeb,
			ScheduleStore:                        scheduleStore,
			AuditStore:                           auditStore,
			ThawExceptionStore:                   thawExceptionStore,
			StatusDecisionStore:                  thawApprovalStore,
			StatusPublicationStore:               statusPublicationStore,
			WebhookRepositoryStore:               repositorySetup,
			WebhookDeliveryStore:                 webhookDeliveryStore,
			PullRequestWebhookProcessor:          pullRequestWebhookProcessor,
			AuthService:                          authService,
			PullRequestStore:                     pullRequestStore,
			EnforcementService:                   enforcementService,
			ReconciliationJobStore:               jobStore,
			DevMode:                              a.cfg.DevMode,
		}).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
	}

	errc := make(chan error, 1)
	lifecycleRunner := newFreezeLifecycleRunner(freezeStoreForWeb, a.logger)
	lifecycleRunner.materializer = scheduleMaterializer
	go lifecycleRunner.Start(ctx)
	go newRepositoryReconciliationRunner(jobStore, enforcementService, a.logger).Start(ctx)
	go func() {
		a.logger.Info("starting thawguard", "addr", a.cfg.HTTPAddr, "db", a.cfg.DatabasePath, "public_url", publicURL)
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

// newRuntimeStatusPublisher is the only status publisher construction path:
// live Forgejo/Codeberg posting, gated per repository by enforcement state.
func newRuntimeStatusPublisher(publications *statuspublication.Store, repositories *repository.Store, tokens *repositorysetup.Service) webhook.StatusPublisher {
	return statuspublisher.NewForgejoStatusPublisher(publications, publications, repositories, tokens, forgejoStatusClientForRepository)
}

func forgejoStatusClientForRepository(repo domain.Repository, token string) (statuspublisher.ForgeStatusClient, error) {
	switch strings.ToLower(strings.TrimSpace(repo.Forge)) {
	case "forgejo", "codeberg", "":
		client := forgejo.New(repo.BaseURL, token)
		client.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		return client, nil
	default:
		return nil, fmt.Errorf("repository forge %q is not supported for live status posting", repo.Forge)
	}
}

func forgejoPullRequestClientForRepository(repo domain.Repository, token string) (openPullRequestForgeClient, error) {
	switch strings.ToLower(strings.TrimSpace(repo.Forge)) {
	case "forgejo", "codeberg", "":
		client := forgejo.New(repo.BaseURL, token)
		client.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		return client, nil
	default:
		return nil, fmt.Errorf("repository forge %q is not supported for open pull request sync", repo.Forge)
	}
}

func forgejoThawApprovalClientForRepository(repo domain.Repository, token string) (thawApprovalForgeClient, error) {
	switch strings.ToLower(strings.TrimSpace(repo.Forge)) {
	case "forgejo", "codeberg", "":
		client := forgejo.New(repo.BaseURL, token)
		client.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		return client, nil
	default:
		return nil, fmt.Errorf("repository forge %q is not supported for thaw approvals", repo.Forge)
	}
}

func forgejoEnforcementClientForRepository(repo domain.Repository, token string) (enforcementForgeClient, error) {
	switch strings.ToLower(strings.TrimSpace(repo.Forge)) {
	case "forgejo", "codeberg", "":
		client := forgejo.New(repo.BaseURL, token)
		client.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		return client, nil
	default:
		return nil, fmt.Errorf("repository forge %q is not supported for enforcement verification", repo.Forge)
	}
}

func forgejoReadinessInspectorForRepository(repo domain.Repository, token string) (setupcheck.Inspector, error) {
	switch strings.ToLower(strings.TrimSpace(repo.Forge)) {
	case "forgejo", "codeberg", "":
		client := forgejo.New(repo.BaseURL, token)
		client.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		return setupforgejo.Adapter{Client: client}, nil
	default:
		return nil, fmt.Errorf("repository forge %q is not supported for readiness checks", repo.Forge)
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
