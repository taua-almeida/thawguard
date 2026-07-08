package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/config"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge/forgejo"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/pullrequest"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/secrets"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
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
	repositorySetup := repositorysetup.NewServiceWithSecrets(database, secretStore)
	repositoryStore := repository.NewStore(database)
	setupCheckStore := setupcheck.NewStore(database)
	setupCheckRunner := localSetupHealthRunner{recorder: setupCheckStore}
	freezeStore := freeze.NewService(database)
	pullRequestStore := pullrequest.NewStore(database)
	auditStore := audit.NewStore(database)
	thawExceptionStore := thawexception.NewService(database)
	statusDecisionStore := statusresult.NewServiceWithThawExceptions(statusresult.NewStore(database), freezeStore, thawExceptionStore, pullRequestStore)
	statusPublicationStore := statuspublication.NewStore(database)
	publisherMode, err := statusPublisherMode(a.cfg.StatusPublisherMode)
	if err != nil {
		return err
	}
	if err := validateStatusPublisherConfig(a.cfg, publisherMode, secretStore != nil); err != nil {
		return err
	}
	statusPublisher, err := statusPublisherFromConfig(a.cfg, publisherMode, statusPublicationStore, repositoryStore, repositorySetup)
	if err != nil {
		return err
	}
	openPullRequestSyncer, err := openPullRequestSyncerFromConfig(a.cfg, publisherMode, repositoryStore, pullRequestStore, repositorySetup, auditStore)
	if err != nil {
		return err
	}
	freezeStoreForWeb := newFreezeRecomputingStore(freezeStore, pullRequestStore, statusDecisionStore, statusPublisher, openPullRequestSyncer)
	thawApprovalStore := newThawApprovalService(repositoryStore, repositorySetup, pullRequestStore, thawExceptionStore, statusDecisionStore, statusPublisher, openPullRequestSyncer, liveStatusRepositories(a.cfg.LiveStatusRepos), forgejoThawApprovalClientForRepository)
	webhookDeliveryStore := webhook.NewDeliveryStore(database)
	pullRequestWebhookProcessor := webhook.NewPullRequestProcessor(repositoryStore, pullRequestStore, statusDecisionStore, statusPublisher)
	server := &http.Server{
		Addr: a.cfg.HTTPAddr,
		Handler: web.NewServer(web.Config{
			AppName:                              "Thawguard",
			RepositoryStore:                      repositorySetup,
			RepositorySecretEncryptionConfigured: secretStore != nil,
			SetupCheckStore:                      setupCheckStore,
			SetupCheckRunner:                     setupCheckRunner,
			FreezeStore:                          freezeStoreForWeb,
			ScheduledFreezeStore:                 freezeStoreForWeb,
			AuditStore:                           auditStore,
			StatusDecisionStore:                  thawApprovalStore,
			StatusPublicationStore:               statusPublicationStore,
			WebhookRepositoryStore:               repositorySetup,
			WebhookDeliveryStore:                 webhookDeliveryStore,
			PullRequestWebhookProcessor:          pullRequestWebhookProcessor,
		}).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
	}

	errc := make(chan error, 1)
	go newScheduledFreezeRunner(freezeStoreForWeb, a.logger).Start(ctx)
	go func() {
		a.logger.Info("starting thawguard", "addr", a.cfg.HTTPAddr, "db", a.cfg.DatabasePath, "public_url", a.cfg.PublicURL, "status_publisher", publisherMode)
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

func statusPublisherMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		mode = statuspublication.AttemptModeDryRun
	}
	switch mode {
	case statuspublication.AttemptModeDryRun, statuspublication.DeliveryModeForgejoStatus:
		return mode, nil
	default:
		return "", fmt.Errorf("THAWGUARD_STATUS_PUBLISHER must be %q or %q", statuspublication.AttemptModeDryRun, statuspublication.DeliveryModeForgejoStatus)
	}
}

func validateStatusPublisherConfig(cfg config.Config, mode string, secretStoreConfigured bool) error {
	if mode != statuspublication.DeliveryModeForgejoStatus {
		return nil
	}
	if !liveStatusPostingEnabled(cfg.LiveStatusPosting) {
		return fmt.Errorf("THAWGUARD_STATUS_PUBLISHER=%s requires THAWGUARD_LIVE_STATUS_POSTING=enabled; use dry_run for shadow mode", mode)
	}
	if !secretStoreConfigured {
		return fmt.Errorf("THAWGUARD_STATUS_PUBLISHER=%s requires THAWGUARD_SECRET_KEY so repository status tokens can be decrypted", mode)
	}
	if len(liveStatusRepositories(cfg.LiveStatusRepos)) == 0 {
		return fmt.Errorf("THAWGUARD_STATUS_PUBLISHER=%s requires THAWGUARD_LIVE_STATUS_REPOSITORIES to allow specific owner/name repositories", mode)
	}
	return nil
}

func liveStatusPostingEnabled(raw string) bool {
	return strings.EqualFold(strings.TrimSpace(raw), "enabled")
}

func liveStatusRepositories(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\t' || r == ' ' })
	repositories := make([]string, 0, len(fields))
	for _, field := range fields {
		field = normalizeLiveStatusRepository(field)
		if field != "" {
			repositories = append(repositories, field)
		}
	}
	return repositories
}

func normalizeLiveStatusRepository(fullName string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(fullName)), "/")
	if len(parts) != 2 {
		return ""
	}
	owner := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	if owner == "" || name == "" {
		return ""
	}
	return owner + "/" + name
}

func statusPublisherFromConfig(cfg config.Config, mode string, publications *statuspublication.Store, repositories *repository.Store, repositorySetup *repositorysetup.Service) (webhook.StatusPublisher, error) {
	switch mode {
	case statuspublication.AttemptModeDryRun:
		return statuspublisher.NewDryRunPublisher(publications, publications), nil
	case statuspublication.DeliveryModeForgejoStatus:
		return statuspublisher.NewForgejoStatusPublisher(publications, publications, repositories, repositorySetup, liveStatusRepositories(cfg.LiveStatusRepos), forgejoStatusClientForRepository), nil
	default:
		return nil, fmt.Errorf("unsupported status publisher mode %q", mode)
	}
}

func openPullRequestSyncerFromConfig(cfg config.Config, mode string, repositories *repository.Store, pullRequests *pullrequest.Store, repositorySetup *repositorysetup.Service, auditStore *audit.Store) (openPullRequestSyncer, error) {
	switch mode {
	case statuspublication.AttemptModeDryRun:
		return nil, nil
	case statuspublication.DeliveryModeForgejoStatus:
		return newForgeOpenPullRequestSyncer(repositories, repositorySetup, pullRequests, liveStatusRepositories(cfg.LiveStatusRepos), forgejoPullRequestClientForRepository, auditStore), nil
	default:
		return nil, fmt.Errorf("unsupported status publisher mode %q", mode)
	}
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
