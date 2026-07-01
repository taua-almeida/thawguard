package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

const defaultWebhookMaxBodyBytes int64 = 1 << 20

type Config struct {
	AppName                              string
	RepositoryStore                      RepositoryStore
	RepositorySecretEncryptionConfigured bool
	SetupCheckStore                      SetupCheckStore
	SetupCheckRunner                     SetupCheckRunner
	FreezeStore                          FreezeStore
	AuditStore                           AuditStore
	StatusDecisionStore                  StatusDecisionStore
	StatusPublicationStore               StatusPublicationStore
	WebhookRepositoryStore               WebhookRepositoryStore
	WebhookDeliveryStore                 WebhookDeliveryStore
	PullRequestWebhookProcessor          PullRequestWebhookProcessor
	WebhookMaxBodyBytes                  int64
}

type RepositoryStore interface {
	List(ctx context.Context) ([]domain.Repository, error)
	Create(ctx context.Context, params repository.CreateParams, actor domain.Actor) (domain.Repository, error)
	SetWebhookSecret(ctx context.Context, repositoryID int64, secret string, actor domain.Actor) (domain.Repository, error)
}

type SetupCheckStore interface {
	ListByRepository(ctx context.Context, repositoryID int64) ([]setupcheck.Check, error)
}

type SetupCheckRunner interface {
	Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error)
}

type FreezeStore interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
	CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error)
	End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type AuditStore interface {
	ListBySubjectType(ctx context.Context, subjectType string, limit int) ([]audit.Event, error)
}

type StatusDecisionStore interface {
	ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error)
	RunLocal(ctx context.Context, params statusresult.LocalDecisionParams) (statusresult.Result, error)
}

type StatusPublicationStore interface {
	ListRecent(ctx context.Context, limit int) ([]statuspublication.Publication, error)
	ListRecentAttempts(ctx context.Context, limit int) ([]statuspublication.Attempt, error)
}

type WebhookRepositoryStore interface {
	FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error)
	WebhookSecret(ctx context.Context, repositoryID int64) (string, bool, error)
}

type WebhookDeliveryStore interface {
	ListRecent(ctx context.Context, limit int) ([]webhook.Delivery, error)
	Record(ctx context.Context, params webhook.DeliveryRecordParams) (webhook.Delivery, error)
	ClaimForProcessing(ctx context.Context, id int64) (webhook.Delivery, bool, error)
	MarkProcessed(ctx context.Context, id int64, params webhook.DeliveryProcessParams) (webhook.Delivery, error)
	MarkProcessingFailed(ctx context.Context, id int64, message string, processingStartedAt time.Time) (webhook.Delivery, error)
}

type PullRequestWebhookProcessor interface {
	Process(ctx context.Context, body []byte) (webhook.PullRequestProcessResult, error)
}

type repositoryView struct {
	Repository  domain.Repository
	SetupChecks []setupcheck.Check
}

type repositoryOverview struct {
	RepositoryCount             int
	WebhookConfiguredCount      int
	SetupCheckRepositoryCount   int
	WebhookSecretStorageEnabled bool
}

type freezeView struct {
	Freeze     domain.BranchFreeze
	Repository domain.Repository
}

type freezeAuditView struct {
	Action       string
	SubjectID    string
	RepositoryID string
	Repository   domain.Repository
	Branch       string
	Status       string
	Reason       string
	Actor        string
	CreatedAt    string
}

type statusResultView struct {
	Result     statusresult.Result
	Repository domain.Repository
	CreatedAt  string
}

type statusPublicationView struct {
	Publication statuspublication.Publication
	Repository  domain.Repository
	CreatedAt   string
	UpdatedAt   string
}

type statusPublicationAttemptView struct {
	Attempt     statuspublication.Attempt
	Repository  domain.Repository
	AttemptedAt string
}

type webhookDeliveryView struct {
	Delivery               webhook.Delivery
	Repository             domain.Repository
	ReceivedAt             string
	ProcessingStartedAt    string
	ProcessedAt            string
	ProcessingState        string
	ProcessingStateClass   string
	VerificationState      string
	VerificationStateClass string
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	sessions *sessionStore
}

func NewServer(cfg Config) *Server {
	if cfg.AppName == "" {
		cfg.AppName = "Thawguard"
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), sessions: newSessionStore()}
	s.routes()
	return s
}

func (s *Server) Routes() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /repositories", s.handleRepositories)
	s.mux.HandleFunc("POST /repositories", s.handleCreateRepository)
	s.mux.HandleFunc("POST /repositories/webhook-secret", s.handleSetRepositoryWebhookSecret)
	s.mux.HandleFunc("POST /repositories/setup-check", s.handleRunRepositorySetupCheck)
	s.mux.HandleFunc("GET /freezes", s.handleFreezes)
	s.mux.HandleFunc("POST /freezes", s.handleCreateFreeze)
	s.mux.HandleFunc("POST /freezes/end", s.handleEndFreeze)
	s.mux.HandleFunc("POST /freezes/cancel", s.handleCancelFreeze)
	s.mux.HandleFunc("GET /decisions", s.handleDecisions)
	s.mux.HandleFunc("POST /decisions", s.handleCreateDecision)
	s.mux.HandleFunc("GET /publications", s.handlePublications)
	s.mux.HandleFunc("GET /webhooks", s.handleWebhooks)
	s.mux.HandleFunc("POST /webhooks/forgejo", s.handleForgejoWebhook)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	repositories, err := s.repositories(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	freezes, err := s.activeFreezes(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.render(w, dashboardTemplate, map[string]any{
		"AppName":           s.cfg.AppName,
		"ActivePage":        "dashboard",
		"RepositoryCount":   len(repositories),
		"ActiveFreezeCount": len(freezes),
		"Freezes":           s.freezeViews(repositories, freezes),
	})
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, results, err := s.decisionPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), "", session.CSRFToken)
}

func (s *Server) handleCreateDecision(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	pullRequestIndex, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("pull_request_index")))
	if err != nil {
		pullRequestIndex = 0
	}
	_, err = s.cfg.StatusDecisionStore.RunLocal(r.Context(), statusresult.LocalDecisionParams{
		RepositoryID:     repositoryID,
		PullRequestIndex: pullRequestIndex,
		TargetBranch:     r.PostFormValue("target_branch"),
		HeadSHA:          r.PostFormValue("head_sha"),
	})
	if err != nil {
		if !statusresult.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, results, dataErr := s.decisionPageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/decisions", http.StatusSeeOther)
}

func (s *Server) handlePublications(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusPublicationStore == nil {
		http.Error(w, "status publication store is not configured", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.sessions.getOrCreate(w, r); err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, publications, attempts, err := s.publicationPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderPublications(w, s.statusPublicationViews(repositories, publications), s.statusPublicationAttemptViews(repositories, attempts))
}

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WebhookDeliveryStore == nil {
		http.Error(w, "webhook delivery store is not configured", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.sessions.getOrCreate(w, r); err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, deliveries, err := s.webhookDeliveryPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderWebhookDeliveries(w, s.webhookDeliveryViews(repositories, deliveries))
}

func (s *Server) handleForgejoWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WebhookRepositoryStore == nil || s.cfg.WebhookDeliveryStore == nil || s.cfg.PullRequestWebhookProcessor == nil {
		http.Error(w, "webhook receiver is not configured", http.StatusServiceUnavailable)
		return
	}
	body, ok := s.readWebhookBody(w, r)
	if !ok {
		return
	}
	if len(body) == 0 || !webhookEventMayBePullRequest(r) {
		acceptedWebhook(w)
		return
	}

	event, err := webhook.ParsePullRequestEvent(body)
	if err != nil {
		acceptedWebhook(w)
		return
	}
	repo, found, err := s.cfg.WebhookRepositoryStore.FindActiveByRemote(r.Context(), repository.RemoteParams{Forge: event.Forge, BaseURL: event.BaseURL, Owner: event.Owner, Name: event.RepositoryName})
	if err != nil {
		internalServerError(w)
		return
	}
	if !found {
		acceptedWebhook(w)
		return
	}

	secret, found, err := s.cfg.WebhookRepositoryStore.WebhookSecret(r.Context(), repo.ID)
	if err != nil {
		if repositorysetup.IsConfigurationError(err) {
			acceptedWebhook(w)
			return
		}
		internalServerError(w)
		return
	}
	if !found || !webhook.VerifyHMACSHA256(secret, body, webhookSignatureHeader(r)) {
		acceptedWebhook(w)
		return
	}

	delivery, err := s.cfg.WebhookDeliveryStore.Record(r.Context(), webhook.DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: webhookDeliveryID(r, repo.ID, body), Event: "pull_request", Action: event.Action, Verified: true})
	if err != nil {
		if webhook.IsValidationError(err) {
			s.claimAndProcessVerifiedPullRequestWebhook(w, r, delivery, repo.ID, event.Action, body)
			return
		}
		internalServerError(w)
		return
	}
	s.claimAndProcessVerifiedPullRequestWebhook(w, r, delivery, repo.ID, event.Action, body)
}

func (s *Server) claimAndProcessVerifiedPullRequestWebhook(w http.ResponseWriter, r *http.Request, delivery webhook.Delivery, repositoryID int64, action string, body []byte) {
	if delivery.ID == 0 {
		acceptedWebhook(w)
		return
	}
	claimedDelivery, claimed, err := s.cfg.WebhookDeliveryStore.ClaimForProcessing(r.Context(), delivery.ID)
	if err != nil {
		internalServerError(w)
		return
	}
	if !claimed {
		acceptedWebhook(w)
		return
	}
	s.processVerifiedPullRequestWebhook(w, r, claimedDelivery, repositoryID, action, body)
}

func (s *Server) processVerifiedPullRequestWebhook(w http.ResponseWriter, r *http.Request, delivery webhook.Delivery, repositoryID int64, action string, body []byte) {
	if delivery.ProcessingStartedAt == nil {
		internalServerError(w)
		return
	}
	if !supportedPullRequestAction(action) {
		s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, "unsupported pull_request action", delivery.ProcessingStartedAt)
		return
	}

	_, processErr := s.cfg.PullRequestWebhookProcessor.Process(r.Context(), body)
	if processErr != nil {
		deliveryError := sanitizedWebhookProcessError(processErr)
		if webhook.IsValidationError(processErr) {
			if !s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, deliveryError, delivery.ProcessingStartedAt) {
				return
			}
			acceptedWebhook(w)
			return
		}
		if _, err := s.cfg.WebhookDeliveryStore.MarkProcessingFailed(r.Context(), delivery.ID, deliveryError, *delivery.ProcessingStartedAt); err != nil {
			internalServerError(w)
			return
		}
		internalServerError(w)
		return
	}
	_ = s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, "", delivery.ProcessingStartedAt)
}

func (s *Server) readWebhookBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limit := s.cfg.WebhookMaxBodyBytes
	if limit <= 0 {
		limit = defaultWebhookMaxBodyBytes
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "webhook payload too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (s *Server) markWebhookProcessed(w http.ResponseWriter, r *http.Request, deliveryID int64, repositoryID int64, action string, deliveryError string, processingStartedAt *time.Time) bool {
	if _, err := s.cfg.WebhookDeliveryStore.MarkProcessed(r.Context(), deliveryID, webhook.DeliveryProcessParams{RepositoryID: repositoryID, Action: action, Error: deliveryError, ProcessingStartedAt: processingStartedAt}); err != nil {
		internalServerError(w)
		return false
	}
	if deliveryError == "" || deliveryError == "unsupported pull_request action" {
		acceptedWebhook(w)
	}
	return true
}

func webhookEventMayBePullRequest(r *http.Request) bool {
	event := strings.ToLower(firstHeader(r, "X-Gitea-Event", "X-Forgejo-Event", "X-Gogs-Event"))
	return event == "" || event == "pull_request"
}

func webhookSignatureHeader(r *http.Request) string {
	return firstHeader(r, "X-Gitea-Signature", "X-Forgejo-Signature", "X-Hub-Signature-256")
}

func webhookDeliveryID(r *http.Request, repositoryID int64, body []byte) string {
	if deliveryID := firstHeader(r, "X-Gitea-Delivery", "X-Forgejo-Delivery", "X-Gogs-Delivery", "X-GitHub-Delivery"); deliveryID != "" {
		if validWebhookDeliveryID(deliveryID) {
			return deliveryID
		}
	}
	sum := sha256.Sum256(body)
	return "repo:" + strconv.FormatInt(repositoryID, 10) + ":sha256:" + hex.EncodeToString(sum[:])
}

func validWebhookDeliveryID(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func firstHeader(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func supportedPullRequestAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "opened", "reopened", "synchronized", "synchronize", "edited", "closed":
		return true
	default:
		return false
	}
}

func sanitizedWebhookProcessError(err error) string {
	if webhook.IsValidationError(err) {
		return "webhook validation failed"
	}
	return "webhook processing failed"
}

func acceptedWebhook(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted\n"))
}

func (s *Server) handleRepositories(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}

	repositories, err := s.repositories(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	views, err := s.repositoryViews(r.Context(), repositories)
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderRepositories(w, views, "", session.CSRFToken)
}

func (s *Server) handleCreateRepository(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}

	_, err := s.cfg.RepositoryStore.Create(r.Context(), repository.CreateParams{
		Forge:         r.PostFormValue("forge"),
		BaseURL:       r.PostFormValue("base_url"),
		Owner:         r.PostFormValue("owner"),
		Name:          r.PostFormValue("name"),
		DefaultBranch: r.PostFormValue("default_branch"),
	}, session.auditActor())
	if err != nil {
		if !repository.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, listErr := s.repositories(r.Context())
		if listErr != nil {
			internalServerError(w)
			return
		}
		views, viewErr := s.repositoryViews(r.Context(), repositories)
		if viewErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderRepositories(w, views, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleSetRepositoryWebhookSecret(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.cfg.RepositorySecretEncryptionConfigured {
		http.Error(w, "webhook secret encryption is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	_, err = s.cfg.RepositoryStore.SetWebhookSecret(r.Context(), repositoryID, r.PostFormValue("webhook_secret"), session.auditActor())
	if err != nil {
		if repositorysetup.IsConfigurationError(err) {
			http.Error(w, "webhook secret encryption is not configured", http.StatusServiceUnavailable)
			return
		}
		if !repositorysetup.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, listErr := s.repositories(r.Context())
		if listErr != nil {
			internalServerError(w)
			return
		}
		views, viewErr := s.repositoryViews(r.Context(), repositories)
		if viewErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderRepositories(w, views, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleFreezes(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, freezes, auditEvents, err := s.freezePageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, "", session.CSRFToken)
}

func (s *Server) handleCreateFreeze(w http.ResponseWriter, r *http.Request) {
	if s.cfg.FreezeStore == nil {
		http.Error(w, "freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}

	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	_, err = s.cfg.FreezeStore.CreateActive(r.Context(), freeze.CreateParams{
		RepositoryID: repositoryID,
		Branch:       r.PostFormValue("branch"),
		Reason:       r.PostFormValue("reason"),
	}, session.auditActor())
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, freezes, auditEvents, dataErr := s.freezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/freezes", http.StatusSeeOther)
}

func (s *Server) handleEndFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.endFreeze)
}

func (s *Server) handleCancelFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.cancelFreeze)
}

func (s *Server) handleCloseFreeze(w http.ResponseWriter, r *http.Request, closeFreeze func(context.Context, int64, domain.Actor) error) {
	if s.cfg.FreezeStore == nil {
		http.Error(w, "freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}

	freezeID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("freeze_id")), 10, 64)
	if err != nil {
		freezeID = 0
	}
	if err := closeFreeze(r.Context(), freezeID, session.auditActor()); err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, freezes, auditEvents, dataErr := s.freezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/freezes", http.StatusSeeOther)
}

func (s *Server) endFreeze(ctx context.Context, id int64, actor domain.Actor) error {
	_, err := s.cfg.FreezeStore.End(ctx, id, actor)
	return err
}

func (s *Server) cancelFreeze(ctx context.Context, id int64, actor domain.Actor) error {
	_, err := s.cfg.FreezeStore.Cancel(ctx, id, actor)
	return err
}

func (s *Server) handleRunRepositorySetupCheck(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SetupCheckRunner == nil {
		http.Error(w, "setup check runner is not configured", http.StatusServiceUnavailable)
		return
	}
	_, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}

	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil || repositoryID <= 0 {
		http.Error(w, "invalid repository id", http.StatusBadRequest)
		return
	}
	repo, found, err := s.repositoryByID(r.Context(), repositoryID)
	if err != nil {
		internalServerError(w)
		return
	}
	if !found {
		http.Error(w, "repository not found", http.StatusNotFound)
		return
	}

	if _, err := s.cfg.SetupCheckRunner.Run(r.Context(), repo); err != nil {
		http.Error(w, "setup check failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) requireRepositoryManagerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	session, ok := s.sessions.get(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if !session.Role.CanManageRepositories() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return sessionState{}, false
	}
	if !constantTimeTokenEqual(r.PostForm.Get(csrfFormField), session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	return session, true
}

func (s *Server) requireFreezerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	session, ok := s.sessions.get(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if !session.Role.CanFreeze() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return sessionState{}, false
	}
	if !constantTimeTokenEqual(r.PostForm.Get(csrfFormField), session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	return session, true
}

func (s *Server) repositories(ctx context.Context) ([]domain.Repository, error) {
	if s.cfg.RepositoryStore == nil {
		return nil, nil
	}
	return s.cfg.RepositoryStore.List(ctx)
}

func (s *Server) statusResults(ctx context.Context) ([]statusresult.Result, error) {
	if s.cfg.StatusDecisionStore == nil {
		return nil, nil
	}
	return s.cfg.StatusDecisionStore.ListRecent(ctx, 25)
}

func (s *Server) statusPublications(ctx context.Context) ([]statuspublication.Publication, error) {
	if s.cfg.StatusPublicationStore == nil {
		return nil, nil
	}
	return s.cfg.StatusPublicationStore.ListRecent(ctx, 25)
}

func (s *Server) statusPublicationAttempts(ctx context.Context) ([]statuspublication.Attempt, error) {
	if s.cfg.StatusPublicationStore == nil {
		return nil, nil
	}
	return s.cfg.StatusPublicationStore.ListRecentAttempts(ctx, 25)
}

func (s *Server) webhookDeliveries(ctx context.Context) ([]webhook.Delivery, error) {
	if s.cfg.WebhookDeliveryStore == nil {
		return nil, nil
	}
	return s.cfg.WebhookDeliveryStore.ListRecent(ctx, 25)
}

func (s *Server) webhookDeliveryPageData(ctx context.Context) ([]domain.Repository, []webhook.Delivery, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, err
	}
	deliveries, err := s.webhookDeliveries(ctx)
	if err != nil {
		return nil, nil, err
	}
	return repositories, deliveries, nil
}

func (s *Server) publicationPageData(ctx context.Context) ([]domain.Repository, []statuspublication.Publication, []statuspublication.Attempt, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	publications, err := s.statusPublications(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	attempts, err := s.statusPublicationAttempts(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return repositories, publications, attempts, nil
}

func (s *Server) decisionPageData(ctx context.Context) ([]domain.Repository, []statusresult.Result, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, err
	}
	results, err := s.statusResults(ctx)
	if err != nil {
		return nil, nil, err
	}
	return repositories, results, nil
}

func (s *Server) statusResultViews(repositories []domain.Repository, results []statusresult.Result) []statusResultView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusResultView, 0, len(results))
	for _, result := range results {
		views = append(views, statusResultView{Result: result, Repository: repositoriesByID[result.RepositoryID], CreatedAt: result.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func (s *Server) statusPublicationViews(repositories []domain.Repository, publications []statuspublication.Publication) []statusPublicationView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusPublicationView, 0, len(publications))
	for _, publication := range publications {
		updatedAt := publication.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = publication.CreatedAt
		}
		views = append(views, statusPublicationView{Publication: publication, Repository: repositoriesByID[publication.RepositoryID], CreatedAt: publication.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), UpdatedAt: updatedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func (s *Server) statusPublicationAttemptViews(repositories []domain.Repository, attempts []statuspublication.Attempt) []statusPublicationAttemptView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusPublicationAttemptView, 0, len(attempts))
	for _, attempt := range attempts {
		views = append(views, statusPublicationAttemptView{Attempt: attempt, Repository: repositoriesByID[attempt.RepositoryID], AttemptedAt: attempt.AttemptedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func (s *Server) webhookDeliveryViews(repositories []domain.Repository, deliveries []webhook.Delivery) []webhookDeliveryView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]webhookDeliveryView, 0, len(deliveries))
	for _, delivery := range deliveries {
		state, stateClass := webhookDeliveryProcessingState(delivery)
		verified, verifiedClass := webhookDeliveryVerificationState(delivery)
		views = append(views, webhookDeliveryView{
			Delivery:               delivery,
			Repository:             repositoriesByID[delivery.RepositoryID],
			ReceivedAt:             delivery.ReceivedAt.UTC().Format("2006-01-02 15:04 UTC"),
			ProcessingStartedAt:    optionalWebhookDeliveryTime(delivery.ProcessingStartedAt),
			ProcessedAt:            optionalWebhookDeliveryTime(delivery.ProcessedAt),
			ProcessingState:        state,
			ProcessingStateClass:   stateClass,
			VerificationState:      verified,
			VerificationStateClass: verifiedClass,
		})
	}
	return views
}

func webhookDeliveryProcessingState(delivery webhook.Delivery) (string, string) {
	if delivery.ProcessedAt != nil {
		if delivery.Error != "" {
			return "processed with error", "warning"
		}
		return "processed", "ok"
	}
	if delivery.ProcessingStartedAt != nil {
		return "processing", "pending"
	}
	if delivery.Error != "" {
		return "retryable failure", "failed"
	}
	return "received", "warning"
}

func webhookDeliveryVerificationState(delivery webhook.Delivery) (string, string) {
	if delivery.Verified {
		return "verified", "ok"
	}
	return "not verified", "warning"
}

func optionalWebhookDeliveryTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "—"
	}
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func (s *Server) activeFreezes(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s.cfg.FreezeStore == nil {
		return nil, nil
	}
	return s.cfg.FreezeStore.ListActive(ctx)
}

func (s *Server) freezePageData(ctx context.Context) ([]domain.Repository, []domain.BranchFreeze, []freezeAuditView, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	freezes, err := s.activeFreezes(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	auditEvents, err := s.freezeAuditViews(ctx, repositories)
	if err != nil {
		return nil, nil, nil, err
	}
	return repositories, freezes, auditEvents, nil
}

func (s *Server) freezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze) []freezeView {
	repositoriesByID := make(map[int64]domain.Repository, len(repositories))
	for _, repo := range repositories {
		repositoriesByID[repo.ID] = repo
	}
	views := make([]freezeView, 0, len(freezes))
	for _, freeze := range freezes {
		views = append(views, freezeView{Freeze: freeze, Repository: repositoriesByID[freeze.RepositoryID]})
	}
	return views
}

func (s *Server) freezeAuditViews(ctx context.Context, repositories []domain.Repository) ([]freezeAuditView, error) {
	if s.cfg.AuditStore == nil {
		return nil, nil
	}
	events, err := s.cfg.AuditStore.ListBySubjectType(ctx, audit.SubjectTypeBranchFreeze, 50)
	if err != nil {
		return nil, err
	}
	repositoriesByID := repositoriesByID(repositories)
	views := make([]freezeAuditView, 0, len(events))
	for _, event := range events {
		if !isFreezeAuditAction(event.Action) {
			continue
		}
		view := freezeAuditView{
			Action:    event.Action,
			SubjectID: event.SubjectID,
			CreatedAt: event.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		}
		var details map[string]string
		if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err == nil {
			view.RepositoryID = details["repository_id"]
			view.Branch = details["branch"]
			view.Status = details["status"]
			view.Reason = details["reason"]
			view.Actor = actorLabel(details["actor_kind"], details["actor_role"])
			if repositoryID, err := strconv.ParseInt(details["repository_id"], 10, 64); err == nil {
				view.Repository = repositoriesByID[repositoryID]
			}
		}
		views = append(views, view)
	}
	return views, nil
}

func isFreezeAuditAction(action string) bool {
	switch action {
	case audit.ActionBranchFreezeCreated, audit.ActionBranchFreezeEnded, audit.ActionBranchFreezeCancelled:
		return true
	default:
		return false
	}
}

func repositoriesByID(repositories []domain.Repository) map[int64]domain.Repository {
	byID := make(map[int64]domain.Repository, len(repositories))
	for _, repo := range repositories {
		byID[repo.ID] = repo
	}
	return byID
}

func actorLabel(kind string, role string) string {
	kind = strings.TrimSpace(kind)
	role = strings.TrimSpace(role)
	if kind == "" && role == "" {
		return "unknown"
	}
	if role == "" {
		return kind
	}
	if kind == "" {
		return role
	}
	return kind + " (" + role + ")"
}

func (s *Server) repositoryByID(ctx context.Context, id int64) (domain.Repository, bool, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return domain.Repository{}, false, err
	}
	for _, repo := range repositories {
		if repo.ID == id {
			return repo, true, nil
		}
	}
	return domain.Repository{}, false, nil
}

func (s *Server) repositoryViews(ctx context.Context, repositories []domain.Repository) ([]repositoryView, error) {
	views := make([]repositoryView, 0, len(repositories))
	for _, repo := range repositories {
		view := repositoryView{Repository: repo}
		if s.cfg.SetupCheckStore != nil {
			checks, err := s.cfg.SetupCheckStore.ListByRepository(ctx, repo.ID)
			if err != nil {
				return nil, err
			}
			view.SetupChecks = latestSetupChecks(checks)
		}
		views = append(views, view)
	}
	return views, nil
}

func latestSetupChecks(checks []setupcheck.Check) []setupcheck.Check {
	if len(checks) == 0 {
		return nil
	}
	checkedAt := checks[0].CheckedAt
	latest := make([]setupcheck.Check, 0, len(checks))
	for _, check := range checks {
		if !check.CheckedAt.Equal(checkedAt) {
			break
		}
		latest = append(latest, check)
	}
	return latest
}

func (s *Server) renderRepositories(w http.ResponseWriter, views []repositoryView, formError string, csrfToken string) {
	overview := repositoryOverview{RepositoryCount: len(views), WebhookSecretStorageEnabled: s.cfg.RepositorySecretEncryptionConfigured}
	for _, view := range views {
		if view.Repository.HasWebhookSecret {
			overview.WebhookConfiguredCount++
		}
		if len(view.SetupChecks) > 0 {
			overview.SetupCheckRepositoryCount++
		}
	}
	s.render(w, repositoriesTemplate, map[string]any{
		"AppName":                           s.cfg.AppName,
		"ActivePage":                        "repositories",
		"Overview":                          overview,
		"RepositoryViews":                   views,
		"FormError":                         formError,
		"CSRFToken":                         csrfToken,
		"RequiredContext":                   domain.RequiredStatusContext,
		"SetupSteps":                        setupcheck.ManualSetupSteps(),
		"WebhookSecretEncryptionConfigured": s.cfg.RepositorySecretEncryptionConfigured,
	})
}

func (s *Server) renderFreezes(w http.ResponseWriter, repositories []domain.Repository, freezes []freezeView, auditEvents []freezeAuditView, formError string, csrfToken string) {
	s.render(w, freezesTemplate, map[string]any{
		"AppName":      s.cfg.AppName,
		"ActivePage":   "freezes",
		"Repositories": repositories,
		"Freezes":      freezes,
		"AuditEvents":  auditEvents,
		"FormError":    formError,
		"CSRFToken":    csrfToken,
	})
}

func (s *Server) renderDecisions(w http.ResponseWriter, repositories []domain.Repository, results []statusResultView, formError string, csrfToken string) {
	s.render(w, decisionsTemplate, map[string]any{
		"AppName":         s.cfg.AppName,
		"ActivePage":      "thaws",
		"Repositories":    repositories,
		"Results":         results,
		"FormError":       formError,
		"CSRFToken":       csrfToken,
		"RequiredContext": domain.RequiredStatusContext,
	})
}

func (s *Server) renderPublications(w http.ResponseWriter, publications []statusPublicationView, attempts []statusPublicationAttemptView) {
	s.render(w, publicationsTemplate, map[string]any{
		"AppName":      s.cfg.AppName,
		"ActivePage":   "activity",
		"Publications": publications,
		"Attempts":     attempts,
	})
}

func (s *Server) renderWebhookDeliveries(w http.ResponseWriter, deliveries []webhookDeliveryView) {
	s.render(w, webhookDeliveriesTemplate, map[string]any{
		"AppName":    s.cfg.AppName,
		"ActivePage": "audit",
		"Deliveries": deliveries,
	})
}

func (s *Server) render(w http.ResponseWriter, source string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, err := template.New("page").Parse(source)
	if err != nil {
		internalServerError(w)
		return
	}
	_ = tpl.Execute(w, data)
}

func internalServerError(w http.ResponseWriter) {
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

const pageHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .AppName }}</title>
  <link rel="stylesheet" href="/static/thawguard.css">
</head>
<body>
  <svg class="tg-icon-sprite" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">
    <symbol id="tg-i-icy-shield" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 21.7c4.5-2.2 7-5.7 7-9.7V5.3L12 2.6 5 5.3V12c0 4 2.5 7.5 7 9.7z M12 8v8 M8.5 10l7 4 M15.5 10l-7 4"/></symbol>
    <symbol id="tg-i-freeze-branch" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M6 3v12 M9 18a3 3 0 1 1-6 0 3 3 0 0 1 6 0z M18 9a9 9 0 0 1-9 9 M18 3v6 M15.4 4.5l5.2 3 M20.6 4.5l-5.2 3"/></symbol>
    <symbol id="tg-i-thaw-drop" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 3v6 M9.4 4.5l5.2 3 M14.6 4.5l-5.2 3 M12 13c-2 3-3 4.2-3 5.8a3 3 0 0 0 6 0c0-1.6-1-2.8-3-5.8z"/></symbol>
    <symbol id="tg-i-dashboard" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M10 3H4a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1z M20 3h-6a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1z M20 11h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-6a1 1 0 0 0-1-1z M10 15H4a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1z"/></symbol>
    <symbol id="tg-i-repositories" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20 M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z M9 7h7"/></symbol>
    <symbol id="tg-i-schedule" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4.5 M16 2v4 M8 2v4 M3 10h6 M17.5 22a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11z M17.5 14v2.5l1.5 1"/></symbol>
    <symbol id="tg-i-activity" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M22 12h-4l-3 9L9 3l-3 9H2"/></symbol>
    <symbol id="tg-i-audit" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h5"/></symbol>
    <symbol id="tg-i-users" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75"/></symbol>
    <symbol id="tg-i-warning" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M21.73 18l-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z M12 9v4 M12 17h.01"/></symbol>
    <symbol id="tg-i-check" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M20 6L9 17l-5-5"/></symbol>
    <symbol id="tg-i-play" viewBox="0 0 24 24"><path fill="currentColor" stroke="none" d="M7 4.5v15l12-7.5z"/></symbol>
    <symbol id="tg-i-close" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M18 6L6 18 M6 6l12 12"/></symbol>
    <symbol id="tg-i-plus" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 5v14 M5 12h14"/></symbol>
    <symbol id="tg-i-key" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.5a4.5 4.5 0 1 1 3.18-7.68A4.5 4.5 0 0 1 12 10l8-8 M15.5 6.5l2 2 M17.5 4.5l2 2"/></symbol>
    <symbol id="tg-i-git-branch" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M6 4v10 M18 6a6 6 0 0 1-6 6H6 M8 18a2 2 0 1 1-4 0 2 2 0 0 1 4 0z M20 6a2 2 0 1 1-4 0 2 2 0 0 1 4 0z"/></symbol>
    <symbol id="tg-i-health-check" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z M5.8 12h3l1.4-3.8 2.7 7.6 1.5-3.8h3.8 M15.8 8.2l1.2 1.2 2.2-2.4"/></symbol>
    <symbol id="tg-i-branch-impact" viewBox="0 0 12 16"><path fill="currentColor" fill-rule="evenodd" d="M11 11.28V5c-.03-.78-.34-1.47-.94-2.06C9.46 2.35 8.78 2.03 8 2H7V0L4 3l3 3V4h1c.27.02.48.11.69.31.21.2.3.42.31.69v6.28A1.993 1.993 0 0 0 10 15a1.993 1.993 0 0 0 1-3.72zm-1 2.92c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zM4 3c0-1.11-.89-2-2-2a1.993 1.993 0 0 0-1 3.72v6.56A1.993 1.993 0 0 0 2 15a1.993 1.993 0 0 0 1-3.72V4.72c.59-.34 1-.98 1-1.72zm-.8 10c0 .66-.55 1.2-1.2 1.2-.65 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2zM2 4.2C1.34 4.2.8 3.65.8 3c0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2z"/></symbol>
  </svg>
  <div class="tg-app">
    <aside class="tg-sidebar" aria-label="Primary navigation">
      <a class="tg-logo" href="/" aria-label="{{ .AppName }} dashboard">
        <span class="tg-logo-mark" aria-hidden="true"><svg class="tg-brand-icon"><use href="#tg-i-icy-shield"></use></svg></span>
        <span>{{ .AppName }}</span>
      </a>
      <nav class="tg-nav">
        <a class="tg-nav-item{{ if eq .ActivePage "dashboard" }} is-active{{ end }}" href="/"><svg class="tg-icon"><use href="#tg-i-dashboard"></use></svg>Dashboard</a>
        <a class="tg-nav-item{{ if eq .ActivePage "repositories" }} is-active{{ end }}" href="/repositories"><svg class="tg-icon"><use href="#tg-i-repositories"></use></svg>Repositories</a>
        <a class="tg-nav-item{{ if eq .ActivePage "freezes" }} is-active{{ end }}" href="/freezes"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg>Freezes</a>
        <a class="tg-nav-item is-disabled" href="#"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg>Scheduled Freezes</a>
        <a class="tg-nav-item{{ if eq .ActivePage "thaws" }} is-active{{ end }}" href="/decisions"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Thaw Requests</a>
        <a class="tg-nav-item{{ if eq .ActivePage "audit" }} is-active{{ end }}" href="/webhooks"><svg class="tg-icon"><use href="#tg-i-audit"></use></svg>Audit Log</a>
        <a class="tg-nav-item is-disabled" href="#"><svg class="tg-icon"><use href="#tg-i-users"></use></svg>Users & Roles</a>
      </nav>
      <div class="tg-sidebar-note">
        <span class="tg-status-dot"></span>
        <span>Shadow mode</span>
      </div>
    </aside>
    <div class="tg-content">`

const pageFoot = `</div></div></body></html>`

const dashboardTemplate = pageHead + `
  <main class="tg-main tg-dashboard">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Dashboard</h1>
        <p class="tg-subtitle">Freeze branches. Thaw exceptions. Keep release flow auditable.</p>
      </div>
      <div class="tg-header-actions">
        <a class="tg-btn tg-btn-primary" href="/freezes"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg>Freeze Branch</a>
        <a class="tg-btn tg-btn-secondary" href="/decisions"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Thaw PR</a>
      </div>
    </header>

    <section class="tg-stats" aria-label="Dashboard summary">
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg></span>
        <span><span class="tg-stat-label">Active Freezes</span><strong class="tg-stat-value">{{ .ActiveFreezeCount }}</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg></span>
        <span><span class="tg-stat-label">Active Thaws</span><strong class="tg-stat-value">0</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-activity"></use></svg></span>
        <span><span class="tg-stat-label">Events Today</span><strong class="tg-stat-value">0</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-repositories"></use></svg></span>
        <span><span class="tg-stat-label">Repos Monitored</span><strong class="tg-stat-value">{{ .RepositoryCount }}</strong></span>
      </article>
      <article class="tg-stat tg-stat-scheduled">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span>
        <span><span class="tg-stat-label">Scheduled</span><strong class="tg-stat-value">0</strong></span>
      </article>
    </section>

    <section class="tg-columns">
      <article class="tg-panel">
        <div class="tg-panel-head"><h2>Active Freezes</h2><span class="tg-badge">{{ .ActiveFreezeCount }} active</span></div>
        {{ if .Freezes }}
          {{ range .Freezes }}
          <div class="tg-freeze-row">
            <div class="tg-freeze-main"><span class="tg-lock" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg></span><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch">{{ .Freeze.Branch }}</code></div>
            <div class="tg-freeze-meta"><span>{{ .Freeze.Reason }}</span><span class="tg-dot">·</span><span>bootstrap admin</span><span class="tg-dot">·</span><span class="tg-muted">recorded locally</span></div>
          </div>
          {{ end }}
        {{ else }}
          <div class="tg-empty-row">
            <strong>No active freezes yet</strong>
            <span>Create a local freeze to see branch cards here.</span>
          </div>
        {{ end }}
      </article>

      <article class="tg-panel">
        <div class="tg-panel-head"><h2>Recent Events</h2><a class="tg-btn tg-btn-secondary tg-btn-sm" href="/webhooks">View All</a></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-freeze"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg></span><span>Branch freeze workflow is ready for local records</span><span class="tg-muted">local</span></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-ok"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span><span>Dry-run publisher records what would publish later</span><span class="tg-muted">dry-run</span></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-fail"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span><span>Signed webhook receiver stores sanitized delivery metadata only</span><span class="tg-muted">safe</span></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-ok"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span><span>Required status context is <code>` + domain.RequiredStatusContext + `</code></span><span class="tg-muted">future</span></div>
      </article>
    </section>

    <section class="tg-panel tg-scheduled-panel">
      <div class="tg-panel-head tg-scheduled-head">
        <h2>Scheduled Windows</h2>
        <span class="tg-badge tg-badge-scheduled">2 upcoming</span>
        <a class="tg-btn tg-btn-secondary tg-btn-sm" href="#">View Schedules</a>
      </div>
      <div class="tg-schedule-row">
        <div class="tg-schedule-main"><span class="tg-scheduled-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span><code>acme/shop-api</code><span class="tg-arrow">→</span><code class="tg-branch tg-branch-scheduled">main</code></div>
        <div class="tg-schedule-meta"><span><span class="tg-caps">Starts</span> Fri 18:00</span><span><span class="tg-caps">Ends</span> Mon 09:00</span><span class="tg-dot">·</span><span>Weekend release freeze</span></div>
        <div class="tg-schedule-actions"><a class="tg-btn tg-btn-primary tg-btn-sm" href="#"><svg class="tg-icon"><use href="#tg-i-play"></use></svg>Start Now</a><a class="tg-btn tg-btn-secondary tg-btn-sm" href="#">Cancel</a><a class="tg-btn tg-btn-secondary tg-btn-sm" href="#schedule-weekend-details">View</a></div>
      </div>
      <div class="tg-schedule-row">
        <div class="tg-schedule-main"><span class="tg-scheduled-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg></span><code>acme/frontend</code><span class="tg-arrow">→</span><code class="tg-branch tg-branch-scheduled">release/2026-07</code></div>
        <div class="tg-schedule-meta"><span><span class="tg-caps">Window</span> Tomorrow 10:00-11:00</span><span class="tg-dot">·</span><span>Emergency thaw review mock</span></div>
        <div class="tg-schedule-actions"><a class="tg-btn tg-btn-secondary tg-btn-sm" href="#schedule-thaw-details">View</a></div>
      </div>
    </section>

    <section id="schedule-weekend-details" class="tg-modal" aria-labelledby="schedule-weekend-title">
      <a class="tg-modal-backdrop" href="#" aria-label="Close schedule details"></a>
      <div class="tg-modal-card" role="dialog" aria-modal="true">
        <div class="tg-modal-head"><h2 id="schedule-weekend-title">Weekend release freeze</h2><a href="#" class="tg-modal-close" aria-label="Close">×</a></div>
        <dl class="tg-detail-grid"><dt>Repository</dt><dd><code>acme/shop-api</code></dd><dt>Branch</dt><dd><code class="tg-branch tg-branch-scheduled">main</code></dd><dt>Starts</dt><dd>Friday 18:00</dd><dt>Ends</dt><dd>Monday 09:00</dd><dt>Mode</dt><dd>Mocked scheduled freeze preview</dd></dl>
        <p>This dashboard modal is a preview target only. The dedicated Scheduled Freezes page will own editing and full lifecycle actions later.</p>
      </div>
    </section>

    <section id="schedule-thaw-details" class="tg-modal" aria-labelledby="schedule-thaw-title">
      <a class="tg-modal-backdrop" href="#" aria-label="Close schedule details"></a>
      <div class="tg-modal-card" role="dialog" aria-modal="true">
        <div class="tg-modal-head"><h2 id="schedule-thaw-title">Emergency thaw review</h2><a href="#" class="tg-modal-close" aria-label="Close">×</a></div>
        <dl class="tg-detail-grid"><dt>Repository</dt><dd><code>acme/frontend</code></dd><dt>Branch</dt><dd><code class="tg-branch tg-branch-scheduled">release/2026-07</code></dd><dt>Window</dt><dd>Tomorrow 10:00-11:00</dd><dt>Mode</dt><dd>Mocked thaw review preview</dd></dl>
        <p>Thaw exceptions are not live yet. This modal shows where dashboard-level schedule details will appear.</p>
      </div>
    </section>

    <section class="tg-warning-callout">
      <span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
      <span>Shadow mode alpha: Thawguard records decisions and dry-run publication attempts. It does not post live Forgejo/Codeberg statuses yet.</span>
      <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories">View Setup</a>
    </section>
  </main>` + pageFoot

const webhookDeliveriesTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Signed webhook delivery history</p>
      <h1>Webhook deliveries</h1>
      <p class="warning">This page shows sanitized local delivery metadata only. Thawguard does not store raw webhook payloads, signatures, or webhook secrets here.</p>
      <p class="warning">Bootstrap sessions are for local development only. Do not expose webhook delivery visibility on a network until real local auth is configured.</p>
      <p>Use this page to confirm signed webhook receipt, verification, local recomputation processing, and retryable processing failures before live Forgejo/Codeberg status posting is wired.</p>
    </section>

    <section class="panel">
      <h2>Recent webhook deliveries</h2>
      {{ if .Deliveries }}
      <table>
        <thead><tr><th>Received</th><th>Repository</th><th>Delivery ID</th><th>Event</th><th>Action</th><th>Verified</th><th>Processing</th><th>Claimed</th><th>Processed</th><th>Error</th></tr></thead>
        <tbody>
        {{ range .Deliveries }}
          <tr>
            <td data-label="Received">{{ .ReceivedAt }}</td>
            <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else if .Delivery.RepositoryID }}Repository #{{ .Delivery.RepositoryID }}{{ else }}Unknown repository{{ end }}</td>
            <td data-label="Delivery ID"><code>{{ .Delivery.DeliveryID }}</code></td>
            <td data-label="Event"><code>{{ .Delivery.Event }}</code></td>
            <td data-label="Action">{{ if .Delivery.Action }}<code>{{ .Delivery.Action }}</code>{{ else }}—{{ end }}</td>
            <td data-label="Verified"><span class="status status-{{ .VerificationStateClass }}">{{ .VerificationState }}</span></td>
            <td data-label="Processing"><span class="status status-{{ .ProcessingStateClass }}">{{ .ProcessingState }}</span></td>
            <td data-label="Claimed">{{ .ProcessingStartedAt }}</td>
            <td data-label="Processed">{{ .ProcessedAt }}</td>
            <td data-label="Error">{{ if .Delivery.Error }}{{ .Delivery.Error }}{{ else }}—{{ end }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No webhook deliveries recorded yet.</p>
      {{ end }}
    </section>
  </main>` + pageFoot

const publicationsTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Local publication intents</p>
      <h1>Status publication intents</h1>
      <p class="warning">These are idempotent local records of the latest status Thawguard would publish later. No status has been posted to Forgejo/Codeberg from this page or from the current local publisher.</p>
      <p class="warning">Bootstrap sessions are for local development only. Do not expose publication-intent visibility on a network until real local auth is configured.</p>
      <p>Use this page to inspect the status context, state, head SHA, dry-run attempt history, and description generated by the local recomputation pipeline before live status posting is wired.</p>
    </section>

    <section class="panel">
      <h2>Latest local publication intents</h2>
      {{ if .Publications }}
      <table>
        <thead><tr><th>Last updated</th><th>Repository</th><th>PR</th><th>Target branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Mode</th><th>Description</th></tr></thead>
        <tbody>
        {{ range .Publications }}
          <tr>
            <td data-label="Last updated">{{ .UpdatedAt }}</td>
            <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Publication.RepositoryID }}{{ end }}</td>
            <td data-label="PR">#{{ .Publication.PullRequestIndex }}</td>
            <td data-label="Target branch">{{ .Publication.TargetBranch }}</td>
            <td data-label="Head SHA"><code>{{ .Publication.HeadSHA }}</code></td>
            <td data-label="Context"><code>{{ .Publication.Context }}</code></td>
            <td data-label="State"><span class="status status-{{ .Publication.State }}">{{ .Publication.State }}</span></td>
            <td data-label="Mode"><code>{{ .Publication.DeliveryMode }}</code></td>
            <td data-label="Description">{{ .Publication.Description }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No local publication intents yet.</p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Recent dry-run publication attempts</h2>
      <p class="muted">Dry-run attempts are local planning records created by the publisher seam. They do not call Forgejo/Codeberg.</p>
      {{ if .Attempts }}
      <table>
        <thead><tr><th>Attempted</th><th>Repository</th><th>PR</th><th>Target branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Mode</th><th>Result</th><th>Description</th><th>Error</th></tr></thead>
        <tbody>
        {{ range .Attempts }}
          <tr>
            <td data-label="Attempted">{{ .AttemptedAt }}</td>
            <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Attempt.RepositoryID }}{{ end }}</td>
            <td data-label="PR">#{{ .Attempt.PullRequestIndex }}</td>
            <td data-label="Target branch">{{ .Attempt.TargetBranch }}</td>
            <td data-label="Head SHA"><code>{{ .Attempt.HeadSHA }}</code></td>
            <td data-label="Context"><code>{{ .Attempt.Context }}</code></td>
            <td data-label="State"><span class="status status-{{ .Attempt.State }}">{{ .Attempt.State }}</span></td>
            <td data-label="Mode"><code>{{ .Attempt.Mode }}</code></td>
            <td data-label="Result"><code>{{ .Attempt.Result }}</code></td>
            <td data-label="Description">{{ .Attempt.Description }}</td>
            <td data-label="Error">{{ if .Attempt.Error }}{{ .Attempt.Error }}{{ else }}—{{ end }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No dry-run publication attempts yet.</p>
      {{ end }}
    </section>
  </main>` + pageFoot

const repositoriesTemplate = pageHead + `
  <main class="tg-main tg-setup-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Repositories</h1>
        <p class="tg-subtitle">Connect Forgejo/Codeberg repositories and verify freeze setup.</p>
      </div>
      <div class="tg-header-actions">
        <a class="tg-btn tg-btn-primary" href="#connect-repository"><svg class="tg-icon"><use href="#tg-i-plus"></use></svg>Add Repository</a>
      </div>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    <section class="tg-stats tg-setup-stats" aria-label="Repository setup summary">
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-repositories"></use></svg></span>
        <span><span class="tg-stat-label">Repos</span><strong class="tg-stat-value">{{ .Overview.RepositoryCount }}</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span>
        <span><span class="tg-stat-label">Webhooks</span><strong class="tg-stat-value">{{ .Overview.WebhookConfiguredCount }}</strong></span>
      </article>
      <article class="tg-stat tg-stat-info">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span>
        <span><span class="tg-stat-label">Checks</span><strong class="tg-stat-value">Local</strong></span>
      </article>
      <article class="tg-stat tg-stat-scheduled">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-icy-shield"></use></svg></span>
        <span><span class="tg-stat-label">Mode</span><strong class="tg-stat-value">Shadow</strong></span>
      </article>
    </section>

    <section id="connect-repository" class="tg-modal tg-connect-modal" aria-labelledby="connect-repository-title">
      <a class="tg-modal-backdrop" href="#" aria-label="Close connect repository"></a>
      <div class="tg-modal-card" role="dialog" aria-modal="true">
        <div class="tg-modal-head">
          <h2 id="connect-repository-title">Connect a repository</h2>
          <a href="#" class="tg-modal-close" aria-label="Close"><svg class="tg-icon"><use href="#tg-i-close"></use></svg></a>
        </div>
        <p class="tg-setup-copy">Add the Forgejo or Codeberg repository Thawguard should watch. The required status context stays fixed as <code>{{ .RequiredContext }}</code>.</p>
        <form method="post" action="/repositories" class="tg-setup-form tg-connect-form">
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <label>Forge
            <select name="forge">
              <option value="forgejo">Forgejo</option>
              <option value="codeberg">Codeberg</option>
            </select>
          </label>
          <label>Base URL <input name="base_url" value="https://codeberg.org"></label>
          <label>Owner <input name="owner" placeholder="acme" required></label>
          <label>Repository <input name="name" placeholder="shop-api" required></label>
          <label>Default branch <input name="default_branch" value="main"></label>
          <div class="tg-form-submit"><button type="submit" class="tg-btn tg-btn-primary">Connect</button></div>
        </form>
        <p class="tg-local-note"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg><span>Local bootstrap session active. Keep this UI on loopback until real auth is configured.</span></p>
      </div>
    </section>

    <div class="tg-section-heading tg-section-heading-compact">
      <div>
        <h2>Configured repositories</h2>
        <p>Configure signed webhooks, record local setup checks, and confirm each repository is ready for freeze workflows.</p>
      </div>
    </div>

    {{ if .RepositoryViews }}
    <section class="tg-repo-grid" aria-label="Configured repositories">
      {{ range .RepositoryViews }}
      <article class="tg-repo-card">
        <div class="tg-repo-card-head">
          <div>
            <p class="tg-repo-kicker">{{ .Repository.Forge }}</p>
            <h3>{{ .Repository.FullName }}</h3>
          </div>
          {{ if .Repository.HasWebhookSecret }}<span class="tg-badge status-ok">webhook configured</span>{{ else }}<span class="tg-badge status-warning">webhook missing</span>{{ end }}
        </div>
        <dl class="tg-repo-meta">
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-git-branch"></use></svg></span><dt>Default branch</dt><dd><code>{{ .Repository.DefaultBranch }}</code></dd></div>
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span><dt>Required context</dt><dd><code>` + domain.RequiredStatusContext + `</code></dd></div>
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span><dt>Setup checks</dt><dd>{{ if .SetupChecks }}<span class="tg-badge tg-badge-info">local batch recorded</span>{{ else }}<span class="tg-badge status-warning">not run</span>{{ end }}</dd></div>
        </dl>
        <div class="tg-repo-checks">
          {{ if .SetupChecks }}
            {{ range .SetupChecks }}
            <div class="tg-repo-check"><span class="status status-{{ .Result.Status }}">{{ .Result.Status }}</span><div><strong>{{ .Result.Name }}</strong><small>{{ .Result.Description }}{{ if .Result.Remediation }} {{ .Result.Remediation }}{{ end }}</small></div></div>
            {{ end }}
          {{ else }}
            <p class="tg-muted">Run a local setup check to record placeholder readiness results. Live forge verification is not wired yet.</p>
          {{ end }}
        </div>
        <div class="tg-repo-actions">
          {{ if $.WebhookSecretEncryptionConfigured }}
          <form method="post" action="/repositories/webhook-secret" class="tg-secret-form">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <input type="password" name="webhook_secret" minlength="16" maxlength="512" autocomplete="new-password" placeholder="Webhook secret" aria-label="Webhook secret for {{ .Repository.FullName }}" required>
            <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>{{ if .Repository.HasWebhookSecret }}Rotate secret{{ else }}Set secret{{ end }}</button>
          </form>
          {{ else }}
          <p class="tg-muted">Set <code>THAWGUARD_SECRET_KEY</code> to save webhook secrets.</p>
          {{ end }}
          <form method="post" action="/repositories/setup-check">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-health-check"></use></svg>Run setup check</button>
          </form>
        </div>
      </article>
      {{ end }}
    </section>
    {{ else }}
    <section class="tg-panel tg-empty-row">
      <strong>No repositories configured yet</strong>
      <span>Add your first Forgejo or Codeberg repository to start setup.</span>
    </section>
    {{ end }}

    <section class="tg-panel tg-setup-checklist">
      <div class="tg-panel-head"><h2>Manual setup checklist</h2><span class="tg-badge tg-badge-info">local guidance</span></div>
      <div class="tg-checklist-grid">
        <article><span>1</span><div><strong>Required status context</strong><p>Configure branch protection to require <code>{{ .RequiredContext }}</code> once live status posting is configured.</p></div></article>
        <article><span>2</span><div><strong>Signed webhook receiver</strong><p>Point pull request webhooks at <code>/webhooks/forgejo</code> with the repository webhook secret.</p></div></article>
        <article><span>3</span><div><strong>Local setup checks</strong><p>Current checks are local placeholders for setup visibility, not live Forgejo/Codeberg verification.</p></div></article>
      </div>
    </section>
  </main>` + pageFoot

const freezesTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-freezes-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Branch Freezes</h1>
        <p class="tg-subtitle">Freeze a branch to block merges, then review and lift active freezes.</p>
      </div>
      <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg>Cooperative enforcement — auditable, not a hard security gate</span>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    <section class="tg-freeze-workbench" aria-label="Create branch freeze and preview impact">
      <section class="tg-panel tg-freeze-form-panel">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div>
            <h2>Create a freeze</h2>
            <p class="tg-panel-subtitle">Open PRs on the branch receive a failing <code>` + domain.RequiredStatusContext + `</code> status check.</p>
          </div>
        </div>
        {{ if .Repositories }}
        <form method="post" action="/freezes" class="tg-setup-form tg-freeze-form" data-freeze-form>
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <label>Repository
            <select name="repository_id" required data-freeze-repository>
            {{ range .Repositories }}<option value="{{ .ID }}">{{ .FullName }}</option>{{ end }}
            </select>
          </label>
          <label>Branch <input name="branch" placeholder="main" value="main" required data-freeze-branch></label>
          <label class="tg-field-wide">Reason <input name="reason" placeholder="Release cut 2026-07 — QA verification in progress" required></label>
          <div class="tg-freeze-form-footer tg-field-wide">
            <span class="tg-muted"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>Every freeze is written to the audit log.</span>
            <div class="tg-freeze-form-actions">
              <button type="reset" class="tg-btn tg-btn-secondary tg-btn-sm">Reset</button>
              <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg>Freeze Branch</button>
            </div>
          </div>
        </form>
        {{ else }}
        <div class="tg-empty-row">
          <strong>No repositories configured yet</strong>
          <span>Add a repository before creating a freeze.</span>
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories"><svg class="tg-icon"><use href="#tg-i-plus"></use></svg>Add repository</a>
        </div>
        {{ end }}
      </section>

      <aside class="tg-panel tg-impact-card">
        <div class="tg-panel-head tg-impact-head">
          <div class="tg-impact-title-row">
            <h2><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-branch-impact"></use></svg>Preview impact</h2>
          <span class="tg-badge status-warning">3 open PRs</span>
          </div>
          <p class="tg-panel-subtitle">Live preview of PRs blocked by this freeze. Updates on repo/branch change; real lookup is wired later.</p>
        </div>
        <div class="tg-impact-context"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-git-branch"></use></svg><code data-preview-repository>Selected repository</code><span class="tg-arrow">→</span><code class="tg-branch" data-preview-branch>main</code></div>
        <div class="tg-pr-preview-list">
          <div class="tg-pr-preview-row"><a href="#">#248</a><div><strong>Fix checkout tax rounding</strong><small>Ivo · a3f7c2d</small></div></div>
          <div class="tg-pr-preview-row"><a href="#">#245</a><div><strong>Add coupon validation endpoint</strong><small>Priya · 7be9f1d</small></div></div>
          <div class="tg-pr-preview-row"><a href="#">#241</a><div><strong>Update shipping rate calculator</strong><small>Lena · c02de84</small></div></div>
        </div>
        <p class="tg-impact-warning"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg>These PRs will get a failing <code>` + domain.RequiredStatusContext + `</code> check until the freeze is lifted.</p>
      </aside>
    </section>

    <section class="tg-panel tg-active-freezes-panel">
      <div class="tg-panel-head"><h2>Active Freezes</h2><span class="tg-badge">{{ len .Freezes }} active</span></div>
      {{ if .Freezes }}
      <div class="tg-table-wrap">
        <table class="tg-data-table tg-freezes-table">
          <thead><tr><th>Repository / branch</th><th>Reason</th><th>Created by</th><th>Expiry</th><th>PRs</th><th>Status</th><th></th></tr></thead>
          <tbody>
          {{ range .Freezes }}
            <tr>
              <td><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-freeze-branch"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch">{{ .Freeze.Branch }}</code></span></td>
              <td>{{ .Freeze.Reason }}</td>
              <td>bootstrap admin</td>
              <td><span class="tg-muted">Manual</span></td>
              <td><span class="tg-muted">preview</span></td>
              <td><span class="status status-frozen">{{ .Freeze.Status }}</span></td>
              <td class="tg-table-actions">
                <form method="post" action="/freezes/end">
                  <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Lift</button>
                </form>
                <form method="post" action="/freezes/cancel">
                  <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-close"></use></svg>Cancel</button>
                </form>
              </td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row">
          <strong>No active freezes yet</strong>
          <span>Freeze a repository branch to see it listed here.</span>
        </div>
      {{ end }}
    </section>
  </main>
  <script>
    (() => {
      const form = document.querySelector('[data-freeze-form]');
      if (!form) return;
      const repo = form.querySelector('[data-freeze-repository]');
      const branch = form.querySelector('[data-freeze-branch]');
      const repoOut = document.querySelector('[data-preview-repository]');
      const branchOut = document.querySelector('[data-preview-branch]');
      const update = () => {
        if (repoOut && repo) repoOut.textContent = repo.options[repo.selectedIndex]?.textContent?.trim() || 'Selected repository';
        if (branchOut && branch) branchOut.textContent = branch.value.trim() || 'branch';
      };
      repo.addEventListener('change', update);
      branch.addEventListener('input', update);
      update();
    })();
  </script>
` + pageFoot

const decisionsTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-thaws-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Thaw Requests</h1>
        <p class="tg-subtitle">Review exceptions for PRs that need to land during an active branch freeze. Every decision should be auditable — this is cooperative workflow for trusted teams, not a hard security gate.</p>
      </div>
      <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-icy-shield"></use></svg>Auditable exceptions — not a hard security gate</span>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    <section class="tg-thaw-workbench" aria-label="Request a thaw exception and preview eligibility">
      <section class="tg-panel tg-thaw-form-panel">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div class="tg-thaw-panel-title">
            <span class="tg-thaw-panel-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg></span>
            <div>
              <h2>Request a thaw exception</h2>
              <p class="tg-panel-subtitle">Nominate a PR candidate for a thaw exception. This alpha records a local <code>{{ .RequiredContext }}</code> status result; request details and approval persistence are wired later.</p>
            </div>
          </div>
        </div>
        {{ if .Repositories }}
        <form method="post" action="/decisions" class="tg-setup-form tg-thaw-form" data-thaw-form>
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <label>Repository
            <select name="repository_id" required data-thaw-repository>
            {{ range .Repositories }}<option value="{{ .ID }}">{{ .FullName }}</option>{{ end }}
            </select>
          </label>
          <label>Pull request <input name="pull_request_index" inputmode="numeric" placeholder="251" required data-thaw-pr></label>
          <label>Target branch <input name="target_branch" placeholder="main" value="main" required data-thaw-branch></label>
          <label>Head SHA <input name="head_sha" placeholder="abc123" required></label>
          <label class="tg-field-wide">Reason for exception <input name="reason" placeholder="Reason capture lands with request persistence" aria-describedby="thaw-alpha-note" disabled></label>
          <label>Exception expires
            <select name="expires_after" disabled>
              <option>24 hours after approval</option>
            </select>
          </label>
          <label>Notify channel (optional) <input name="notify_channel" placeholder="#releases" disabled></label>
          <div class="tg-form-footer tg-thaw-form-footer tg-field-wide">
            <span id="thaw-alpha-note" class="tg-muted"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>Only repository, PR number, target branch, and head SHA are saved as a local status result today.</span>
            <div class="tg-form-actions">
              <button type="reset" class="tg-btn tg-btn-secondary tg-btn-sm">Reset</button>
              <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Evaluate request</button>
            </div>
          </div>
        </form>
        {{ else }}
        <div class="tg-empty-row">
          <strong>No repositories configured yet</strong>
          <span>Add a repository before requesting a thaw exception.</span>
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories"><svg class="tg-icon"><use href="#tg-i-plus"></use></svg>Add repository</a>
        </div>
        {{ end }}
      </section>

      <aside class="tg-panel tg-eligibility-card">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div class="tg-impact-title-row">
            <h2><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-health-check"></use></svg>Eligibility preview</h2>
            <span class="tg-badge tg-badge-info">local only</span>
          </div>
          <p class="tg-panel-subtitle">How the local status evaluation will be recorded for the target branch.</p>
        </div>
        <div class="tg-thaw-freeze-card">
          <div class="tg-thaw-freeze-main"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-freeze-branch"></use></svg><code data-thaw-preview-repository>Selected repository</code><span class="tg-arrow">→</span><code class="tg-branch" data-thaw-preview-branch>main</code><span class="status status-pending">Preview</span></div>
          <p>After submission, the latest result below shows whether the local policy check would pass or fail for this PR candidate.</p>
        </div>
        <ul class="tg-eligibility-list">
          <li><span class="tg-event-ok"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-check"></use></svg></span><span>Repository, PR number, target branch, and head SHA are captured for local evaluation.</span></li>
          <li><span class="tg-event-ok"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-check"></use></svg></span><span><code>{{ .RequiredContext }}</code> would be recomputed for the supplied head SHA.</span></li>
          <li><span class="tg-event-ok"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-check"></use></svg></span><span>Future approvals should be scoped to one PR and one head SHA.</span></li>
          <li><span class="tg-event-fail"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg></span><span>Reviewer approval is not persisted yet; this page records local status results only.</span></li>
        </ul>
        <div class="tg-review-actions">
          <span class="tg-caps">Reviewer decision</span>
          <div>
            <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm" disabled>Deny later</button>
            <button type="button" class="tg-btn tg-btn-primary tg-btn-sm" disabled><svg class="tg-icon"><use href="#tg-i-check"></use></svg>Approve later</button>
          </div>
        </div>
      </aside>
    </section>

    <section class="tg-panel tg-open-thaws-panel">
      <div class="tg-panel-head"><h2>Thaw request evaluations</h2><span class="tg-badge tg-badge-info">{{ len .Results }} local results</span></div>
      {{ if .Results }}
      <div class="tg-table-wrap">
        <table class="tg-data-table tg-thaws-table">
          <thead><tr><th>Request candidate</th><th>Source</th><th>Policy result</th><th>Status context</th><th>Expiry</th><th>Status</th><th>Workflow</th></tr></thead>
          <tbody>
          {{ range .Results }}
            <tr>
              <td><div class="tg-thaw-request-main"><a href="#">#{{ .Result.PullRequestIndex }}</a><span><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-git-branch"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Result.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch">{{ .Result.TargetBranch }}</code></span><small><code>{{ .Result.HeadSHA }}</code> · {{ .CreatedAt }}</small></div></td>
              <td><span>bootstrap admin</span><small class="tg-muted">local preview</small></td>
              <td>{{ .Result.Description }}</td>
              <td><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-freeze-branch"></use></svg><code>{{ .Result.Context }}</code></span><small class="tg-muted">{{ if eq .Result.State "failure" }}freeze · failing{{ else }}freeze · passing{{ end }}</small></td>
              <td><span class="tg-muted">Not persisted</span></td>
              <td><span class="status status-{{ .Result.State }}">{{ if eq .Result.State "success" }}Eligible{{ else if eq .Result.State "failure" }}Blocked{{ else }}{{ .Result.State }}{{ end }}</span></td>
              <td class="tg-table-actions"><button type="button" class="tg-btn tg-btn-secondary tg-btn-sm" disabled>Not wired</button></td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row">
          <strong>No local thaw evaluations yet</strong>
          <span>Evaluate a PR above to record the local status result that the approval workflow will build on later.</span>
        </div>
      {{ end }}
    </section>
  </main>
  <script>
    (() => {
      const form = document.querySelector('[data-thaw-form]');
      if (!form) return;
      const repo = form.querySelector('[data-thaw-repository]');
      const branch = form.querySelector('[data-thaw-branch]');
      const repoOut = document.querySelector('[data-thaw-preview-repository]');
      const branchOut = document.querySelector('[data-thaw-preview-branch]');
      const update = () => {
        if (repoOut && repo) repoOut.textContent = repo.options[repo.selectedIndex]?.textContent?.trim() || 'Selected repository';
        if (branchOut && branch) branchOut.textContent = branch.value.trim() || 'branch';
      };
      repo.addEventListener('change', update);
      branch.addEventListener('input', update);
      form.addEventListener('reset', () => window.setTimeout(update, 0));
      update();
    })();
  </script>
` + pageFoot
